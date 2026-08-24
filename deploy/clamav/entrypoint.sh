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

clamd --config-file=/etc/clamav/clamd.conf &
CLAMD=$!

i=0
while [ ! -S /run/clamav/clamd.ctl ]; do
    i=$((i + 1))
    if [ "$i" -gt 300 ]; then
        echo "[clamav] clamd did not open its socket within 300s" >&2
        exit 1
    fi
    # A dead clamd never opens the socket, so without this the loop waits the full
    # timeout to report a failure that already happened.
    kill -0 "$CLAMD" 2>/dev/null || { echo "[clamav] clamd exited during startup" >&2; exit 1; }
    sleep 1
done
echo "[clamav] daemon ready ($(clamdscan --config-file=/etc/clamav/clamd.conf --version 2>/dev/null))" >&2

exec "$@"
