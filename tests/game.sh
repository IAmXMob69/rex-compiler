#!/bin/sh
# Game-like C samples (bench/game): jump tables, foreign-code recovery, refusals.
# Skips quietly when no C compiler is installed.
set -e
command -v gcc >/dev/null 2>&1 || { echo "game: gcc not found, skipped"; exit 0; }
T=/tmp/rex-game-test
rm -rf "$T"; mkdir -p "$T"
G="-static -nostdlib -fno-pie -ffreestanding -fno-stack-protector -Ibench/game"
build() { "$1" "-$2" $G -o "$T/$3_$1_$2" "bench/game/$3.c"; }
# gcc jump table (cmp; ja; jmp *T(,r,8)): rebuild must match and decompile shows a switch
build gcc O1 dispatch
./rex compare "$T/dispatch_gcc_O1" -o "$T/d.re" >/dev/null
./rex decompile "$T/dispatch_gcc_O1" -o "$T/d.rex"
grep -q 'switch (' "$T/d.rex"
# a table jump without a bounds check is refused with E401
printf '%s\n' '.globl _start' '_start: mov $1,%eax' ' jmp *tbl(,%rax,8)' 'a: mov $60,%eax' ' syscall' \
    '.section .rodata' 'tbl: .quad a, a' > "$T/nobound.s"
gcc -static -nostdlib -no-pie -o "$T/nobound" "$T/nobound.s"
! ./rex decompile "$T/nobound" -o "$T/nb.rex" 2> "$T/nb.err"
grep -q 'E401' "$T/nb.err"
# end-pointer idiom: base register + displacement one past the data (map+N(%rdx)
# with rdx negative). The data block must cover that end address (gmem), or the
# recovered reads hit raw absolute addresses and the program crashes.
printf '%s\n' '.intel_syntax noprefix' '.globl _start' '.section .rodata' \
    'tbl: .byte 3,1,4,1,5' '.text' '_start:' ' call main' ' mov edi, eax' \
    ' mov eax, 60' ' syscall' 'main:' ' xor eax, eax' ' mov rdx, -5' \
    '.L0: movzx ecx, byte ptr [tbl+5+rdx]' ' add eax, ecx' ' inc rdx' ' jne .L0' ' ret' > "$T/endptr.s"
gcc -static -nostdlib -no-pie -o "$T/endptr" "$T/endptr.s"
./rex match "$T/endptr" -o "$T/endptr.rex" >/dev/null
grep -q 'gmem + 5' "$T/endptr.rex"
# foreign register code recovered to REX that behaves the same
build gcc O1 rng
./rex match "$T/rng_gcc_O1" -o "$T/r.rex" >/dev/null
grep -q 'let g_' "$T/r.rex"
if command -v clang >/dev/null 2>&1; then
    build clang O1 rng
    ./rex match "$T/rng_clang_O1" -o "$T/rc.rex" >/dev/null
    # clang -O2 ends the loop with "add $-2,%eax; jne": the flag compare must be
    # against -imm (reg != 2), not the raw immediate, or the loop never ends.
    build clang O2 rng
    ./rex match "$T/rng_clang_O2" -o "$T/rc2.rex" >/dev/null
    build clang O1 collide
    ./rex match "$T/collide_clang_O1" -o "$T/c.rex" >/dev/null
    # clang -O2 pulls in an SSE memcpy/memset the linker never calls; that dead
    # library function is dropped instead of failing the whole program.
    build clang O2 collide
    ./rex match "$T/collide_clang_O2" -o "$T/c2.rex" >/dev/null
    # clang -O2 entities: defensive pin/spill temporaries that are never read are
    # dropped, so the recovered main stays under REX's 64 local-name cap.
    build clang O2 entities
    ./rex match "$T/entities_clang_O2" -o "$T/en2.rex" >/dev/null
    test "$(awk '/^fn main\(/{f=1} f&&/^    let (v|w|x)[0-9]+ = 0;/{c++} f&&/^}/{print c; exit}' "$T/en2.rex")" -le 64
    # clang -O0: memory operands on imul/add/cmp and movslq from memory
    for s in tilemap statemachine entities; do
        build clang O0 $s
        ./rex compare "$T/${s}_clang_O0" -o "$T/c0.re" >/dev/null
    done
    # clang -O1 keeps the accumulator in rbp (a callee-saved register) across the
    # calls; rbp is only the frame pointer when established with mov %rsp,%rbp, so
    # here it must stay an ordinary variable or the running total is lost.
    clang -O1 $G -o "$T/chains_clang_O1" tests/chains.c
    ./rex match "$T/chains_clang_O1" -o "$T/chc1.rex" >/dev/null
fi
# global array (data sections in gmem) and memory read-modify-write at -O0
for o in O0 O1; do
    build gcc $o tilemap
    ./rex match "$T/tilemap_gcc_$o" -o "$T/t.rex" >/dev/null
done
grep -q 'gmem = alloc(' "$T/t.rex"
# stack array (frame block fr) and cmp; je; jg chains
for o in O0 O1; do
    build gcc $o statemachine
    ./rex match "$T/statemachine_gcc_$o" -o "$T/s.rex" >/dev/null
done
grep -q 'let fr = gfr;' "$T/s.rex"
# frame block is handed back on return
grep -q 'free(fr);' "$T/s.rex"
if command -v clang >/dev/null 2>&1; then
    # clang -O1 zeroes a stack buffer with xorps + movaps; the SSE move subset
    # recovers that to REX that behaves the same.
    build clang O1 statemachine
    ./rex match "$T/statemachine_clang_O1" -o "$T/sm1.rex" >/dev/null
fi
# unsigned div/mod: rebuild and recovered source behave the same
for o in O0 O1; do
    "gcc" "-$o" $G -o "$T/udiv_$o" tests/udiv.c
    ./rex compare "$T/udiv_$o" -o "$T/u.re" >/dev/null
    ./rex match "$T/udiv_$o" -o "$T/u.rex" >/dev/null
done
grep -q 'udiv(' "$T/u.rex"
# div with an unknown high half (rdx) is refused with E302
printf '%s\n' '.globl _start' '_start: mov $7,%ecx' ' mov $100,%eax' ' div %ecx' ' mov %eax,%edi' ' mov $60,%eax' ' syscall' > "$T/divrdx.s"
gcc -static -nostdlib -no-pie -o "$T/divrdx" "$T/divrdx.s"
! ./rex decompile "$T/divrdx" -o "$T/dr.rex" 2> "$T/dr.err"
grep -q 'E302' "$T/dr.err"
# && / || chains fold into one condition; tail-exit loops print as do-while
for o in O0 O1; do
    "gcc" "-$o" $G -o "$T/chains_$o" tests/chains.c
    ./rex match "$T/chains_$o" -o "$T/ch_$o.rex" >/dev/null
done
grep -q ' && \| || ' "$T/ch_O0.rex"
grep -q '} while (' "$T/ch_O1.rex"
# gcc -O2 keeps the loop counter in edx across calls to leaf functions that
# never write edx; the i++ (add edx,1) must survive the call or the loop
# counter is lost and the loop never ends.
"gcc" "-O2" $G -o "$T/chains_O2" tests/chains.c
./rex match "$T/chains_O2" -o "$T/ch_O2.rex" >/dev/null
# De Morgan: a negated || chain reads as a short-circuit && condition, no !( ... || ... )
! grep -qE '!\(.*\|\|' "$T/ch_O0.rex"
# E-code regressions: each refusal prints a plain line and its code
asm() { printf '%s\n' '.globl _start' '_start:' "$@" ' mov %eax,%edi' ' mov $60,%eax' ' syscall' > "$T/e.s"; gcc -static -nostdlib -no-pie -o "$T/e" "$T/e.s"; }
asm ' mov $7,%ecx' ' mov $100,%eax' ' xor %edx,%edx' ' div %cl'
! ./rex rebuild "$T/e" -o "$T/e.re" 2> "$T/e.err"
grep -q 'divide step' "$T/e.err" && grep -q 'E302' "$T/e.err"
asm ' mov $1,%eax' ' shl $3,%ax'
! ./rex rebuild "$T/e" -o "$T/e.re" 2> "$T/e.err"
grep -q "couldn't build the new program file" "$T/e.err" && grep -q 'E500' "$T/e.err"
asm ' mov $39,%eax' ' syscall'
! ./rex compare "$T/e" -o "$T/e.re" 2> "$T/e.err"
grep -q 'acted differently' "$T/e.err" && grep -q 'E501' "$T/e.err"
# unknown command: plain reply pointing at help
! ./rex frobnicate 2> "$T/u.err"
grep -q "I don't know the command 'frobnicate'. Type \`rex help\`" "$T/u.err"
# packed-integer SSE: gcc -O2 vectorizes the entity position update with
# paddd + pshufd; the recovered lanes must match the real CPU.
build gcc O2 entities
./rex match "$T/entities_gcc_O2" -o "$T/eg2.rex" >/dev/null
# packed-integer SSE differential test: every packed op (paddd/psubd, pand/por/
# pxor, pcmpeq[bwd]/pcmpgt[bwd], punpck[lh]{bw,wd,dq,qdq}, pshufd immediates,
# psrlq/psllq) is computed on the real CPU and by a plain-C per-lane reference
# over edge and random vectors; main returns nonzero on any byte mismatch, so
# this match stays green only if the recovered lanes equal the real CPU.
gcc -O0 $G -o "$T/ssecheck" tests/ssecheck.c
./rex match "$T/ssecheck" -o "$T/ssecheck.rex" >/dev/null
# statemachine gcc -O2: the region structurer cannot nest gcc's dispatch, so
# the decompiler falls back to an exact dispatch loop (a state variable st and
# one arm per block). It must round-trip, and it must use that loop.
build gcc O2 statemachine
./rex match "$T/statemachine_gcc_O2" -o "$T/sm2.rex" >/dev/null
grep -q "let st = 0;" "$T/sm2.rex"
# recursive fib at gcc -O2 is too tangled for the structurer and its stack
# pointer moves (prologue push/pop): the dispatch loop takes it once the stack
# model shows every block sees the frame where the machine has it.
printf '%s\n' '#include "rt.h"' 'int fib(int n){if(n<2)return n;return fib(n-1)+fib(n-2);}' \
    'int main(void){return fib(10);}' > "$T/recur.c"
gcc -O2 $G -o "$T/recur_gcc_O2" "$T/recur.c"
./rex match "$T/recur_gcc_O2" -o "$T/rc2.rex" >/dev/null
grep -q "let st = 0;" "$T/rc2.rex"
rm -rf "$T"
echo "game: ok"
