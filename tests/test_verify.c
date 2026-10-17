/* rex_verify_bins: pairs of small programs that differ in one way each must
 * be told apart (exit, stdout past a NUL or past 64 KB, stderr, argv, stdin,
 * the signal that killed it, a rebuilt program that never finishes); a
 * program agrees with itself; a nondeterministic original is compared on the
 * no-argument input only. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/verify.h"
#include "../src/rex_err.h"

void rex_refuse(const char *msg) { fprintf(stderr, "rex: %s\n", msg); }

static int g_fail;
static void build(const char *name, const char *src) {
    char c[512], cmd[1024];
    snprintf(c, sizeof c, "/tmp/rexvt_%s.c", name);
    FILE *f = fopen(c, "w");
    if (!f) { perror(c); exit(1); }
    fputs(src, f); fclose(f);
    snprintf(cmd, sizeof cmd, "cc -O1 -w -o /tmp/rexvt_%s %s", name, c);
    if (system(cmd)) { fprintf(stderr, "cannot build %s\n", name); exit(1); }
}
static void expect(const char *a, const char *b, int want, const char *needle) {
    char pa[256], pb[256], err[512] = "";
    snprintf(pa, sizeof pa, "/tmp/rexvt_%s", a); snprintf(pb, sizeof pb, "/tmp/rexvt_%s", b);
    int rc = rex_verify_bins(pa, pb, err, sizeof err, REX_E601_VERIFY);
    if (rc != want || (needle && !strstr(err, needle))) {
        printf("FAIL %s vs %s: rc %d (want %d) err: %s\n", a, b, rc, want, err);
        g_fail++;
    }
}

int main(void) {
    build("base", "#include <stdio.h>\nint main(void){ fputs(\"hi\\n\", stdout); return 3; }\n");
    build("exit", "#include <stdio.h>\nint main(void){ fputs(\"hi\\n\", stdout); return 4; }\n");
    build("nul1", "#include <stdio.h>\nint main(void){ fwrite(\"a\\0b\", 1, 3, stdout); return 0; }\n");
    build("nul2", "#include <stdio.h>\nint main(void){ fwrite(\"a\\0c\", 1, 3, stdout); return 0; }\n");
    build("big1", "#include <stdio.h>\nint main(void){ for (int i = 0; i < 100000; i++) putchar('x'); putchar('1'); return 0; }\n");
    build("big2", "#include <stdio.h>\nint main(void){ for (int i = 0; i < 100000; i++) putchar('x'); putchar('2'); return 0; }\n");
    build("err1", "#include <stdio.h>\nint main(void){ fputs(\"hi\\n\", stdout); fputs(\"e1\", stderr); return 3; }\n");
    build("err2", "#include <stdio.h>\nint main(void){ fputs(\"hi\\n\", stdout); fputs(\"e2\", stderr); return 3; }\n");
    /* the same with no arguments: only the argv inputs tell them apart */
    build("argv1", "int main(int c, char **v){ return c > 1 ? 5 : 0; }\n");
    build("argv2", "int main(int c, char **v){ return 0; }\n");
    build("argv0", "#include <string.h>\nint main(int c, char **v){ return (int)strlen(v[0]); }\n");
    /* the same on empty stdin */
    build("in1", "#include <stdio.h>\nint main(void){ int s = 0, x; while (scanf(\"%d\", &x) == 1) s += x; return s & 255; }\n");
    build("in2", "#include <stdio.h>\nint main(void){ int s = 0, x; while (scanf(\"%d\", &x) == 1) s += 2 * x; return s & 255; }\n");
    build("segv", "#include <signal.h>\nint main(void){ raise(SIGSEGV); return 0; }\n");
    build("abrt", "#include <signal.h>\nint main(void){ raise(SIGABRT); return 0; }\n");
    build("spin", "volatile int z;\nint main(void){ while (!z) ; return 0; }\n");
    /* differs from run to run when given arguments: those inputs are skipped */
    build("rnd1", "#include <unistd.h>\nint main(int c, char **v){ return c > 1 ? getpid() & 127 : 9; }\n");
    build("rnd2", "int main(int c, char **v){ return 9; }\n");

    expect("base", "base", 0, NULL);
    expect("base", "exit", REX_E601_VERIFY, "exit 3 vs exit 4");
    expect("nul1", "nul2", REX_E601_VERIFY, "stdout differs at byte 2");
    expect("nul1", "nul1", 0, NULL);
    expect("big1", "big2", REX_E601_VERIFY, "stdout differs at byte 100000");
    expect("err1", "err2", REX_E601_VERIFY, "stderr differs at byte 1");
    expect("argv1", "argv2", REX_E601_VERIFY, "exit 5 vs exit 0 (args: 7");
    expect("argv0", "argv0", 0, NULL);
    expect("in1", "in2", REX_E601_VERIFY, "stdin: 2 bytes");
    expect("segv", "abrt", REX_E601_VERIFY, "killed by signal 11 vs killed by signal 6");
    expect("segv", "segv", 0, NULL);
    expect("base", "spin", REX_E601_VERIFY, "the rebuilt program did not finish in 20 s");
    expect("rnd1", "rnd2", 0, NULL);
    printf("verify: %s\n", g_fail ? "FAIL" : "ok");
    return g_fail != 0;
}
