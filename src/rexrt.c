#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>

/* Old libc REX runtime, kept for reference. Nothing links it: the runtime
 * that runs is the string embedded in src/elf.c, and the two drift. */

void rex_print_int(long x) {
    printf("%ld\n", x);
    fflush(stdout);
}

void rex_print_str(const char *s) {
    fputs(s, stdout);
    fputc('\n', stdout);
    fflush(stdout);
}

void rex_exec(const char *s) {
    int rc = system(s);
    (void)rc;
}

void rex_fail(const char *s) {
    fprintf(stderr, "rex: %s\n", s);
    exit(1);
}

long rex_read_int(void) {
    long x = 0;
    if (scanf("%ld", &x) != 1) return 0;
    return x;
}
