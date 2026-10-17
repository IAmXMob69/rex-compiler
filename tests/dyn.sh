#!/bin/sh
# Dynamically linked (glibc) programs, PIE and not.
set -e
T=$(mktemp -d)
cat > "$T/hello.c" <<'C'
#include <stdio.h>
int add(int a, int b) { return a + b; }
int main(void) { puts("hello"); printf("sum=%d\n", add(2, 3)); return add(4, 5); }
C
cat > "$T/sum.c" <<'C'
int f(int n) { int s = 0; for (int i = 0; i < n; i++) s += i; return s; }
int main(void) { return f(10); }
C
for pie in "-no-pie -fno-pic" "-pie -fPIE"; do
    gcc -O0 $pie -o "$T/hello" "$T/hello.c"
    gcc -O1 $pie -o "$T/sum" "$T/sum.c"
    # library calls print by name through the PLT, with their arguments
    ./rex tosource "$T/hello" -o "$T/hello.rex" 2>/dev/null
    grep -q 'puts(gmem' "$T/hello.rex" && grep -q 'printf(gmem' "$T/hello.rex"
    ! grep -q 'fn()' "$T/hello.rex"
    # the C runtime's start code and helpers are not part of the source
    ! grep -q '__libc_start_main' "$T/hello.rex"
    # match cannot rebuild a library call: one plain line and E602, exit 90
    set +e; ./rex match "$T/hello" -o "$T/hm.rex" 2> "$T/hm.err"; rc=$?; set -e
    test $rc -eq 90
    grep -q "shared library" "$T/hm.err" && grep -q "E602: puts()" "$T/hm.err"
    # a program that never calls the library rebuilds and matches
    ./rex match "$T/sum" -o "$T/sum.rex" >/dev/null 2>&1
done
# a shared library is not a program
gcc -shared -fPIC -o "$T/lib.so" "$T/sum.c"
! ./rex look "$T/lib.so" 2> "$T/so.err"
grep -q "E102" "$T/so.err"
rm -rf "$T"
echo "dyn: ok"
