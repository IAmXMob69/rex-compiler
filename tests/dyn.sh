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
# clang -O1 main is "mov $10,%edi; jmp fib" with fib below it: the jmp is a tail
# call, not fib's body merged into main (which lost the argument and gave 0)
printf '%s\n' 'int fib(int n){if(n<2)return n;return fib(n-1)+fib(n-2);}' \
    'int main(void){return fib(10);}' > "$T/rec.c"
clang -O1 -no-pie -fno-pic -o "$T/rec" "$T/rec.c"
./rex match "$T/rec" -o "$T/rec.rex" >/dev/null 2>&1
grep -q 'f[0-9]*(10)' "$T/rec.rex"
# gcc -O2 fib needs a continue of an outer loop, which REX cannot spell. It must
# refuse with E402 and write nothing, never print a copy-nested body that loops.
gcc -O2 -no-pie -fno-pic -o "$T/rec2" "$T/rec.c"
! ./rex tosource "$T/rec2" -o "$T/rec2.rex" 2> "$T/rec2.err"
grep -q "E402: fib" "$T/rec2.err"
test ! -f "$T/rec2.rex"
# -O0 struct code keeps a struct in an address-taken frame: its cells are
# memory (*(fr + n)), stored to, never declared with let
printf '%s\n' 'typedef struct{int a,b;long c;}S; long sum(S*s){return s->a+s->b+s->c;}' \
    'int main(){S s={1,2,3};return (int)sum(&s);}' > "$T/st.c"
for cc in gcc clang; do
    $cc -O0 -no-pie -fno-pic -o "$T/st_$cc" "$T/st.c"
    ./rex match "$T/st_$cc" -o "$T/st_$cc.rex" >/dev/null 2>&1
done
# recovered source that does not build is refused with one plain line and
# E603 (exit 91); the compiler's own messages never reach the user
printf '%s\n' 'static int sq(int x){return x*x;}' 'int (*volatile fp)(int) = sq;' \
    'int main(void){return fp(3);}' > "$T/fp.c"
gcc -O1 -no-pie -fno-pic -o "$T/fp" "$T/fp.c"
set +e; ./rex match "$T/fp" -o "$T/fp.rex" > "$T/fp.out" 2> "$T/fp.err"; rc=$?; set -e
test $rc -eq 91
grep -q "doesn't build" "$T/fp.err" && grep -q "E603: .* line [0-9]*: " "$T/fp.err"
test $(wc -l < "$T/fp.err") -eq 2
! grep -q "aborting" "$T/fp.err" "$T/fp.out"
# a shared library is not a program
gcc -shared -fPIC -o "$T/lib.so" "$T/sum.c"
! ./rex look "$T/lib.so" 2> "$T/so.err"
grep -q "E102" "$T/so.err"
rm -rf "$T"
echo "dyn: ok"
