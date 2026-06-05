# gVisor C/R: blocked syscalls surface EINTR after restore (even with SA_RESTART / masked signals)

> Draft for filing at github.com/google/gvisor. Found while building a warm-snapshot tier
> that checkpoints an idle `unoserver`/`soffice` and restores it per request.

## Summary

After `runsc restore`, a thread that was blocked in a syscall (e.g. `accept()`) at checkpoint
time has its syscall return **EINTR** on resume — **even when** the interruption would normally
be transparently restarted (handler installed with `SA_RESTART`) or never delivered at all
(the signal is blocked via `sigprocmask(SIG_BLOCK, <all>)`). Programs that re-call the syscall
on EINTR recover transparently; programs that issue a single non-retrying call do not, and a
connection that queued during the restore window is never accepted → the process hangs serving
that listener.

This appears to violate host-Linux semantics: a syscall interrupted purely by the C/R
machinery (not a user-delivered signal) should be restarted on resume (`ERESTART*`), not
surface a spurious `EINTR` — and certainly should not fire for a thread with the relevant
signal masked.

## Environment

- `runsc release-20260511.0`; reproduced on the **systrap (default), kvm, and ptrace** platforms.
- x86_64 Linux host, kernel 6.8.
- Driven directly (containerd/CRI checkpoint is unimplemented): `runsc run -detach` →
  `runsc checkpoint -image-path <dir>` → `runsc restore -image-path <dir> -detach`.
- `-network=none`, bind-mounted control dir; AF_UNIX listener on a bind-mounted (or tmpfs) path.

## Minimal reproduction (native C)

A single-threaded server that installs a no-op handler for all catchable signals **with
`SA_RESTART`** (or, alternatively, masks all signals via `sigprocmask`), binds an AF_UNIX
listener, and calls `accept(fd, NULL, NULL)` with **no retry**:

```c
#define _GNU_SOURCE
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
static void h(int s){}
int main(void){
    struct sigaction sa; memset(&sa,0,sizeof sa); sa.sa_handler=h; sa.sa_flags=SA_RESTART;
    for(int i=1;i<=64;i++){ if(i==SIGKILL||i==SIGSTOP||i==SIGSEGV||i==SIGBUS||i==SIGFPE||i==SIGILL||i==SIGABRT) continue; sigaction(i,&sa,0); }
    /* alternatively: sigset_t set; sigfillset(&set); sigprocmask(SIG_BLOCK,&set,0); */
    unlink("/ctrl/s.sock");
    int s=socket(AF_UNIX,SOCK_STREAM,0);
    struct sockaddr_un a; memset(&a,0,sizeof a); a.sun_family=AF_UNIX; strcpy(a.sun_path,"/ctrl/s.sock");
    bind(s,(struct sockaddr*)&a,sizeof a); listen(s,5);
    FILE*r=fopen("/ctrl/ready","w"); fputs("r",r); fclose(r);
    int c=accept(s,NULL,NULL);                 /* single accept, like osl_acceptPipe */
    FILE*o=fopen("/out/result","w");
    if(c<0) fprintf(o,"accept errno=%d\n",errno);   /* observed: errno=4 (EINTR) after restore */
    else fputs("accepted\n",o);
    fclose(o); return 0;
}
```

Steps: `runsc run` it; wait for `/ctrl/ready`; `runsc checkpoint`; `runsc delete`;
`runsc restore` into a fresh bundle; from a second process `connect()` to `/ctrl/s.sock`.

**Observed:** `/out/result` shows `accept errno=4` (EINTR) — the blocked `accept()` was
interrupted on restore despite `SA_RESTART` (and despite the all-signals mask in the variant).
A version that loops `while ((c=accept(...))<0 && errno==EINTR);` instead **recovers** and
accepts the connection. The gVisor debug log during restore shows lines like
`task_signals.go: Not restarting syscall N after error to be restarted if SA_RESTART is set`.

## Real-world impact

LibreOffice's `osl_acceptPipe` (`sal/osl/unx/pipe.cxx`) does exactly one
`accept(socket, nullptr, nullptr)` with no EINTR retry (the self-pipe wakeup is
`#ifdef`'d FreeBSD-only). A warm `soffice --accept=pipe` (e.g. `unoserver`) checkpointed idle
and restored per request therefore never accepts the post-restore UNO connection — the
conversion hangs (process alive, listening socket present, raw `connect()` returns 0, but
`accept()` never returns). Wrapping `accept`/`accept4` with an EINTR-retry `LD_PRELOAD` shim
fixes it completely, confirming the cause. A full JVM, Python servers (PEP 475), and every
retrying C variant are unaffected — only the single-non-retrying-accept pattern breaks.

## Expected

A syscall interrupted solely by the checkpoint/restore machinery should be **transparently
restarted on resume** (host-Linux `ERESTART*` semantics) — at minimum it should honor
`SA_RESTART` and must not surface `EINTR` to a thread with the signal masked. Otherwise C/R
silently breaks any blocked-syscall server that doesn't defensively retry `EINTR`.
