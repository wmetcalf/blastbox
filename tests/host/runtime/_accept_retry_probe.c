/* Probe for the accept-retry LD_PRELOAD shim (deploy/gvisor/accept_retry.c).
 *
 * Reproduces the LibreOffice osl_acceptPipe failure mode WITHOUT runsc or soffice: a child
 * interrupts the parent's blocking accept() with SIGUSR1 (handler installed WITHOUT SA_RESTART,
 * exactly how gVisor's restore delivers EINTR), then connects. With the shim preloaded, accept()
 * retries past the EINTR and returns the connection -> exit 0 ("retried"). Without it, accept()
 * returns -1/EINTR before the connection arrives -> exit 1 ("bailed", the osl single-accept bug).
 * Driven by tests/host/runtime/test_accept_retry_shim.py, run both ways. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void on_sig(int s) { (void)s; } /* no-op: just interrupts accept() */

int main(int argc, char **argv) {
    if (argc < 2) return 4;
    const char *path = argv[1];
    unlink(path);

    int lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (lfd < 0) return 5;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    if (bind(lfd, (struct sockaddr *)&addr, sizeof addr) < 0) return 6;
    if (listen(lfd, 1) < 0) return 7;

    /* sa_flags = 0 -> NO SA_RESTART -> accept() returns EINTR when this handler runs. */
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sig;
    if (sigaction(SIGUSR1, &sa, NULL) < 0) return 8;

    pid_t parent = getpid();
    pid_t kid = fork();
    if (kid < 0) return 9;
    if (kid == 0) {
        close(STDOUT_FILENO); /* release the inherited stdout pipe so the parent's exit EOFs it */
        close(STDERR_FILENO);
        usleep(150000);          /* the parent is now blocked in accept() */
        kill(parent, SIGUSR1);   /* -> EINTR in the parent's accept() */
        usleep(150000);          /* then deliver the connection */
        int c = socket(AF_UNIX, SOCK_STREAM, 0);
        if (c >= 0) connect(c, (struct sockaddr *)&addr, sizeof addr);
        usleep(200000);
        _exit(0);
    }

    int afd = accept(lfd, NULL, NULL);
    if (afd >= 0) { printf("retried\n"); return 0; }
    if (errno == EINTR) { printf("bailed\n"); return 1; }
    printf("error errno=%d\n", errno);
    return 2;
}
