#include "verify.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include "rex_err.h"

static int run_capture(const char *bin, char *out, size_t outn, int *status) {
    int p[2];
    if (pipe(p)) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(p[0]); close(p[1]); return -1; }
    if (pid == 0) {
        dup2(p[1], 1); dup2(p[1], 2); close(p[0]); close(p[1]);
        execl(bin, bin, (char *)NULL);
        _exit(127);
    }
    close(p[1]);
    size_t n = 0;
    for (;;) {
        if (n + 1 >= outn) { char sink[256]; if (read(p[0], sink, sizeof(sink)) <= 0) break; continue; }
        ssize_t r = read(p[0], out + n, outn - 1 - n);
        if (r <= 0) break;
        n += (size_t)r;
    }
    out[n] = 0;
    close(p[0]);
    int st = 0; waitpid(pid, &st, 0);
    *status = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    return 0;
}

int rex_verify_bins(const char *a, const char *b, char *err, size_t errlen) {
    char oa[1 << 16], ob[1 << 16];
    int sa, sb;
    if (run_capture(a, oa, sizeof(oa), &sa) || run_capture(b, ob, sizeof(ob), &sb))
        return rex_errf(err, errlen, REX_E501_VERIFY, "could not run binaries");
    if (sa != sb)
        return rex_errf(err, errlen, REX_E501_VERIFY, "exit %d vs %d", sa, sb);
    if (strcmp(oa, ob))
        return rex_errf(err, errlen, REX_E501_VERIFY, "stdout/stderr differ");
    return 0;
}
