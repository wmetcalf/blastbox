/* accept-retry LD_PRELOAD shim for the gVisor (runsc) C/R warm-soffice tier.
 *
 * gVisor's checkpoint/restore interrupts blocked syscalls with EINTR (regardless
 * of SA_RESTART / signal mask). Most code re-calls accept() and recovers, but
 * LibreOffice's osl_acceptPipe (sal/osl/unx/pipe.cxx) does a single non-retrying
 * accept(), so its UNO-pipe acceptor bails on the restore EINTR and the warm
 * conversion hangs. This shim transparently retries accept()/accept4() on EINTR,
 * restoring the behavior osl omits. Required ONLY for the soffice warm container;
 * inert everywhere else (the retry only fires on a restore-time EINTR).
 *
 * Build: gcc -shared -fPIC -O2 -o /opt/clippyshot/accept-retry.so accept_retry.c -ldl
 * Use:   LD_PRELOAD=/opt/clippyshot/accept-retry.so  (set in the warm soffice env)
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <sys/socket.h>

static int (*real_accept)(int, struct sockaddr *, socklen_t *) = 0;
static int (*real_accept4)(int, struct sockaddr *, socklen_t *, int) = 0;

int accept(int fd, struct sockaddr *a, socklen_t *l) {
    if (!real_accept) real_accept = dlsym(RTLD_NEXT, "accept");
    for (;;) { int r = real_accept(fd, a, l); if (r < 0 && errno == EINTR) continue; return r; }
}

int accept4(int fd, struct sockaddr *a, socklen_t *l, int flags) {
    if (!real_accept4) real_accept4 = dlsym(RTLD_NEXT, "accept4");
    for (;;) { int r = real_accept4(fd, a, l, flags); if (r < 0 && errno == EINTR) continue; return r; }
}
