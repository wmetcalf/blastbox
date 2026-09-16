#!/bin/sh
# Bring the daemon up, WAIT FOR IT TO BE ANSWERING, then hand off to the blastbox
# worker entrypoint given as our argv.
#
# THE WAIT IS THE POINT. clamd forks, parses roughly a gigabyte of signatures, and only
# then binds its socket — and until that finishes there is nothing to connect to. A
# worker that starts scanning immediately gets a connection error on the first sample,
# which this engine correctly seals as `engine_error`; correct, but it would make every
# cold job fail for the first half-minute of a slot's life. Waiting here is what makes
# a slot READY mean "can answer", which is also the state the warm tier checkpoints.
set -e

if [ ! -f /var/lib/clamav/main.cvd ] && [ ! -f /var/lib/clamav/main.cld ]; then
    # A DAEMON WITH NO DATABASE ANSWERS `OK` TO EVERYTHING. It comes up, it is healthy,
    # it reports every sample clean — the exact false negative this engine exists to
    # refuse, wearing the appearance of a working deployment. The image bakes a database
    # at build time so this should never fire; if it does, fetch before serving.
    echo "[clamav] no signature database in the image — fetching before serving" >&2
    freshclam --config-file=/etc/clamav/freshclam.conf --stdout
fi

# THE SOCKET DIR MUST BE WRITABLE, AND UNDER A READ-ONLY ROOTFS IT IS NOT.
# Observed live: the blastbox dispatcher runs workers with a read-only rootfs, clamd
# answered `Socket file /run/clamav/clamd.ctl could not be bound: Read-only file
# system`, and the job failed. Mounting a tmpfs was the first fix and it was wrong —
# that needs CAP_SYS_ADMIN, which a hardened worker correctly does not have, so it
# merely traded one failure for another.
#
# So the socket MOVES to whatever is writable instead of demanding a fixed path. The
# output directory is deliberately not a candidate: a control socket is not evidence
# and has no business inside a sealed result.
CONF=/etc/clamav/clamd.conf
for d in /run/clamav /tmp/clamav "${TMPDIR:-/tmp}/clamav"; do
    if mkdir -p "$d" 2>/dev/null && touch "$d/.w" 2>/dev/null; then
        rm -f "$d/.w"; SOCKDIR="$d"; break
    fi
done
if [ -z "${SOCKDIR:-}" ]; then
    echo "[clamav] no writable directory for the control socket — clamd cannot bind" >&2
    exit 1
fi
chown clamav:clamav "$SOCKDIR" 2>/dev/null || true
if [ "$SOCKDIR" != "/run/clamav" ]; then
    # clamd takes exactly one config file, so rewrite a copy rather than trying to
    # override LocalSocket on the command line (it has no such flag).
    CONF="$SOCKDIR/clamd.conf"
    sed "s#^LocalSocket .*#LocalSocket $SOCKDIR/clamd.ctl#" /etc/clamav/clamd.conf > "$CONF"
    # The engine resolves the socket from this env var; without it the client would
    # still look in /run/clamav and report a healthy daemon as unreachable.
    export BLASTBOX_CLAMD_SOCKET="$SOCKDIR/clamd.ctl"
    echo "[clamav] socket relocated to $SOCKDIR (read-only rootfs)" >&2
fi

clamd --config-file="$CONF" &
CLAMD=$!

# WAIT FOR AN ANSWER, NOT FOR AN INODE. This loop used to test `[ ! -S <socket> ]`,
# which is true the moment clamd binds and listen()s — before it has finished parsing
# the database. A connect() during that window lands in the listen backlog instead of
# erroring, so socket existence cannot distinguish "bound" from "answering", and the
# whole point of the wait (and of the warm tier checkpointing a READY slot, which
# freezes whatever state this loop signalled) is the difference between the two.
# python3 is already in the image for blastbox, so this costs no new package.
clamd_answers() {
    python3 -c '
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.settimeout(5)
try:
    s.connect(sys.argv[1])
    s.sendall(b"nPING\n")
    sys.exit(0 if s.recv(64).strip() == b"PONG" else 1)
except OSError:
    sys.exit(1)
finally:
    s.close()
' "$1"
}

i=0
until clamd_answers "$SOCKDIR/clamd.ctl"; do
    i=$((i + 1))
    if [ "$i" -gt 300 ]; then
        echo "[clamav] clamd did not answer PING on $SOCKDIR/clamd.ctl within 300s" >&2
        exit 1
    fi
    # A dead clamd never answers, so without this the loop waits the full timeout to
    # report a failure that already happened.
    kill -0 "$CLAMD" 2>/dev/null || { echo "[clamav] clamd exited during startup" >&2; exit 1; }
    sleep 1
done
echo "[clamav] daemon ready and answering PING (socket $SOCKDIR/clamd.ctl)" >&2

exec "$@"
