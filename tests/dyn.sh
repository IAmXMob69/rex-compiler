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
# gcc -O2 fib needs a continue of an outer loop, which REX cannot spell, and
# saves registers with push/pop: the dispatch fallback takes it once the stack
# model shows every block sees the frame where the machine has it
gcc -O2 -no-pie -fno-pic -o "$T/rec2" "$T/rec.c"
./rex match "$T/rec2" -o "$T/rec2.rex" >/dev/null 2>&1
grep -q "st == " "$T/rec2.rex"
# an irreducible loop with calls (callee-saved pushes) at every level
printf '%s\n' '__attribute__((noinline)) int g(int x){ return x*3+1; }' \
    '__attribute__((noinline)) int irr(int n, int m){' \
    '    int s = 0, i = 0;' \
    '    if (n & 1) goto mid;' \
    'top:' \
    '    s += g(i);' \
    '    i++;' \
    'mid:' \
    '    s ^= g(s + m);' \
    '    if (i < n) goto top;' \
    '    if (s & 4) { i = 0; if (m-- > 0) goto mid; }' \
    '    return s;' \
    '}' \
    '' \
    'int main(void){ unsigned s=0; for(int n=0;n<12;n++) for(int m=-2;m<5;m++) s = s*31 + irr(n,m); return (int)(s % 251); }' > "$T/irr.c"
for cc in gcc clang; do for o in O1 O2 Os; do
    $cc -$o -no-pie -fno-pic -o "$T/irr" "$T/irr.c"
    ./rex match "$T/irr" -o "$T/irr.rex" >/dev/null 2>&1
done; done
# the same, edited by hand (tests/stack): a frame block with sub/add rsp and an
# rsp address matches; a cross-block pop outside the epilogue, an rsp read of a
# pushed slot and a mid-function rsp shift are refused with E402, no file
gcc -no-pie -o "$T/st_frame" tests/stack/frame.s
./rex match "$T/st_frame" -o "$T/st_frame.rex" >/dev/null 2>&1
for t in xpop slot shift; do
    gcc -no-pie -o "$T/st_$t" tests/stack/$t.s
    set +e; ./rex tosource "$T/st_$t" -o "$T/st_$t.rex" 2> "$T/st_$t.err"; rc=$?; set -e
    test $rc -eq 146 && grep -q "E402: irr" "$T/st_$t.err" && test ! -e "$T/st_$t.rex"
done
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
# a dynamic _start passes main to the C library in rdi: main is found from
# there, so a stripped program still has one, and a main that cannot be built
# is reported instead of dropped (which left a source without main)
printf '%s\n' '__attribute__((noinline)) int tri(int n){int s=0;for(int i=1;i<=n;i++)s+=i*i;return s;}' \
    'int main(void){int t=0;for(int k=0;k<9;k++)t+=tri(k);return t&0x7f;}' > "$T/sp.c"
gcc -O1 -no-pie -fno-pic -s -o "$T/sp_gcc" "$T/sp.c"
clang -O1 -no-pie -fno-pic -s -o "$T/sp_clang" "$T/sp.c"
gcc -O1 -pie -fpie -s -o "$T/sp_pie" "$T/sp.c"
for b in sp_gcc sp_clang sp_pie; do ./rex match "$T/$b" -o "$T/$b.rex" >/dev/null 2>&1; grep -q "^fn main" "$T/$b.rex"; done
# (unsigned % constant is a one-operand mul, not decoded yet: if it is one day,
# pick another instruction REX does not know)
printf '%s\n' 'int main(int c, char **v){unsigned long s=(unsigned long)c*977;return (int)(s % 251);}' > "$T/um.c"
gcc -O1 -no-pie -fno-pic -o "$T/um" "$T/um.c"
set +e; ./rex tosource "$T/um" -o "$T/um.rex" 2> "$T/um.err"; rc=$?; set -e
test $rc -ne 0 && grep -q "E200" "$T/um.err" && test ! -s "$T/um.rex" -o ! -e "$T/um.rex"
# match runs each program for at most 20 s: an original that never finishes
# is reported in one line instead of hanging match
printf '%s\n' 'volatile int z;' 'int main(void){ while (!z) ; return 0; }' > "$T/spin.c"
gcc -O1 -no-pie -fno-pic -o "$T/spin" "$T/spin.c"
set +e; ./rex match "$T/spin" -o "$T/spin.rex" 2> "$T/spin.err"; rc=$?; set -e
test $rc -ne 0 && grep -q "did not finish in 20 s" "$T/spin.err"
# a 32-bit compare with a negative immediate (cmp $-1,%esi) is a compare of
# the masked register with 0xffffffff, not with -1 (which never held)
printf '%s\n' '__attribute__((noinline)) int t(int a, int e){ a--; if (e == -1) { a += 4; a ^= 0x55; return a*5+3; } return 0; }' \
    '__attribute__((noinline)) int get(int v){ return v; }' 'int main(void){ return t(get(-7), get(-1)) & 0xff; }' > "$T/neg.c"
for cc in gcc clang; do
    $cc -O1 -no-pie -fno-pic -o "$T/neg_$cc" "$T/neg.c"
    ./rex match "$T/neg_$cc" -o "$T/neg_$cc.rex" >/dev/null 2>&1
done
# an indirect jmp REX cannot resolve (a computed goto) is refused with E401
# and no file; it used to become a trap, and tosource wrote wrong code
printf '%s\n' '__attribute__((noinline)) int cg(int x){ static void *L[] = { &&a, &&b, &&c, &&d }; int r = 0;' \
    '  goto *L[x & 3]; a: r += 1; b: r += 2; c: r += 3; d: return r; }' 'int main(void){ return cg(1) + cg(2) * 10; }' > "$T/cg.c"
for cc in gcc clang; do for o in O0 O2; do
    $cc -$o -no-pie -fno-pic -o "$T/cg" "$T/cg.c"
    set +e; ./rex tosource "$T/cg" -o "$T/cg.rex" 2> "$T/cg.err"; rc=$?; set -e
    test $rc -ne 0 && grep -q "E401: fn_[0-9a-f]*: indirect jump" "$T/cg.err" && test ! -e "$T/cg.rex"
done; done
# PIE switch tables hold offsets from the table: read for gcc and clang at
# -O0..-O2, with the dispatch lifted as a compare of the offset
printf '%s\n' '__attribute__((noinline)) int sw(int x){ switch (x) { case 0: return 11; case 1: return 23; case 2: return 37; case 3: return 41;' \
    '  case 4: return 59; case 5: return 61; case 6: return 79; case 7: return 83; default: return -1; } }' \
    'int main(void){ int s = 0; for (int i = -2; i < 10; i++) s = s * 7 + sw(i); return s & 0xff; }' > "$T/sw.c"
for cc in gcc clang; do for o in O0 O1 O2; do
    $cc -$o -pie -fpie -o "$T/sw" "$T/sw.c"
    ./rex match "$T/sw" -o "$T/sw.rex" >/dev/null 2>&1
done; done
# gcc -O0 non-PIE checks the bound on a stack slot
gcc -O0 -no-pie -fno-pic -o "$T/sw" "$T/sw.c"
./rex match "$T/sw" -o "$T/sw.rex" >/dev/null 2>&1
# a loop over a string with a char switch has the shape of REX's len helper;
# in a gcc/clang program one that main reaches is the program's own code
cat > "$T/sw2.c" <<'C'
__attribute__((noinline)) int body(int x, int acc){
    for (int i = 0; i < 3; i++) {
        switch (x + i) {
        case 0: acc += 3; break;
        case 1: acc ^= 0x55; /* fallthrough */
        case 2: acc = acc * 5 + 1; break;
        case 3: { int j = 0; while (j < x) { acc += j * j; j++; } break; }
        case 4: acc -= 7; break;
        case 5: acc = (acc << 2) | 1; break;
        case 6: acc = acc / 3 + 2; break;
        case 7: continue;
        case 8: acc += 100; break;
        default: acc -= 1;
        }
        acc += i;
    }
    return acc;
}
__attribute__((noinline)) int off(int x){
    switch (x) { case 10: return 1; case 11: return 4; case 12: return 9; case 13: return 16;
                 case 14: return 25; case 15: return 36; case 16: return 49; default: return 0; }
}
__attribute__((noinline)) int chr(const char *s){
    int n = 0;
    for (; *s; s++) switch (*s) { case 'a': n += 1; break; case 'b': n += 20; break; case 'c': n *= 3; break;
        case 'd': n -= 4; break; case 'e': n ^= 9; break; case 'f': n += 77; break; default: n++; }
    return n;
}
int main(void){
    unsigned s = 0;
    for (int x = -2; x < 11; x++) s = s * 33 + (unsigned)body(x, x * 7);
    for (int x = 5; x < 20; x++) s = s * 31 + (unsigned)off(x);
    s += (unsigned)chr("abcdefabcxyzfed");
    return (int)(s % 253);
}
C
for cc in gcc clang; do for o in O0 O2; do
    $cc -$o -pie -fpie -o "$T/sw2" "$T/sw2.c"
    ./rex match "$T/sw2" -o "$T/sw2.rex" >/dev/null 2>&1
done; done
# a table whose bounds check another path skips is refused (tests/jt/skip.s);
# the same code without the skip matches
gcc -pie -o "$T/skip" tests/jt/skip.s
set +e; ./rex tosource "$T/skip" -o "$T/skip.rex" 2> "$T/skip.err"; rc=$?; set -e
test $rc -ne 0 && grep -q "E401: .*past the bounds check" "$T/skip.err" && test ! -e "$T/skip.rex"
sed 's/jz\t\.Lload/jz\t.Ldef/' tests/jt/skip.s > "$T/noskip.s"
gcc -pie -o "$T/noskip" "$T/noskip.s"
./rex match "$T/noskip" -o "$T/noskip.rex" >/dev/null 2>&1
# leaf functions keep locals below rsp (the red zone): slots, not *(0 - 8)
printf '%s\n' '__attribute__((noinline)) long f(long a){ volatile long m = a; return m * 3 + m; }' \
    'int main(void){ long s = 0; for (int i = 0; i < 10; i++) s += f(i); return (int)(s & 255); }' > "$T/rz.c"
for cc in gcc clang; do
    $cc -O1 -no-pie -fno-pic -o "$T/rz" "$T/rz.c"
    ./rex match "$T/rz" -o "$T/rz.rex" >/dev/null 2>&1
done
# without a frame pointer rbp is an ordinary register (tests/dec/rbp.c)
gcc -O1 -no-pie -fno-pic -o "$T/rbp" tests/dec/rbp.c
./rex match "$T/rbp" -o "$T/rbp.rex" >/dev/null 2>&1
# clang -O0 stores rdx after a div wrote it: a saved value, not a third argument
printf '%s\n' 'typedef unsigned long u64;' '__attribute__((noinline)) u64 md(u64 x){ return x % 251 + x / 977 + x / 10; }' \
    'int main(void){ u64 s = 0; for (u64 x = 1; x < 3000000000000UL; x = x * 3 + 1) s += md(x); return (int)(s & 255); }' > "$T/md.c"
clang -O0 -no-pie -fno-pic -o "$T/md" "$T/md.c"
./rex match "$T/md" -o "$T/md.rex" >/dev/null 2>&1
# a shared library is not a program
gcc -shared -fPIC -o "$T/lib.so" "$T/sum.c"
! ./rex look "$T/lib.so" 2> "$T/so.err"
grep -q "E102" "$T/so.err"
rm -rf "$T"
echo "dyn: ok"
