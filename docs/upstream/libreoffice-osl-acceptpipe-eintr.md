# LibreOffice: retry accept() on EINTR in osl_acceptPipe (sal/osl/unx/pipe.cxx)

> Draft for filing at LibreOffice (Bugzilla / gerrit). A small robustness fix.

## Summary

`osl_psz_acceptPipe` (`sal/osl/unx/pipe.cxx`) calls `accept(socket, nullptr, nullptr)` exactly
once and treats any error — including `EINTR` — as a hard failure; there is no retry loop. (The
only wakeup-handling path, connect-to-self, is gated behind
`#ifdef CLOSESOCKET_DOESNT_WAKE_UP_ACCEPT`, which is FreeBSD-only.)

On Linux, a **spurious `EINTR`** on that `accept()` makes the pipe acceptor bail and stop
accepting, even though a connection is queued. This happens with any signal delivered without
`SA_RESTART`, and notably under **checkpoint/restore runtimes** (gVisor `runsc` C/R interrupts
the blocked `accept()` with `EINTR` on resume): a warm `soffice --accept=pipe` that is
checkpointed idle and restored per request never accepts the next UNO connection — the
conversion hangs.

## Suggested patch

Retry on `EINTR` around the blocking `accept()` — the standard EINTR-robustness convention for
blocking sockets:

```cpp
int s;
do {
    s = accept(pPipe->m_Socket, nullptr, nullptr);
} while (s < 0 && errno == EINTR);
```

(applied where `osl_psz_acceptPipe` currently does the single `accept`).

## Validation / context

Found while building a warm-snapshot document-conversion tier that checkpoints an idle
`unoserver` and restores it per document under gVisor `runsc` C/R. The restore interrupts the
acceptor's blocked `accept()` with `EINTR` (reproduced even with `SA_RESTART` set on all
signals and with all signals masked — see the companion gVisor report). Because
`osl_acceptPipe` does not retry, the acceptor returns an error and the warm `soffice` never
services the connection. An `LD_PRELOAD` shim that simply retries `accept`/`accept4` on
`EINTR` fixes it without any LibreOffice change — so the one-line retry above would resolve it
at the source, and is a reasonable hardening regardless of C/R (a single non-retrying blocking
`accept()` is fragile against any EINTR).
