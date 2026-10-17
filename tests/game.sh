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
# foreign register code recovered to REX that behaves the same
build gcc O1 rng
./rex match "$T/rng_gcc_O1" -o "$T/r.rex" >/dev/null
grep -q 'let g_' "$T/r.rex"
if command -v clang >/dev/null 2>&1; then
    build clang O1 rng
    ./rex match "$T/rng_clang_O1" -o "$T/rc.rex" >/dev/null
    build clang O1 collide
    ./rex match "$T/collide_clang_O1" -o "$T/c.rex" >/dev/null
    # clang -O0: memory operands on imul/add/cmp and movslq from memory
    for s in tilemap statemachine entities; do
        build clang O0 $s
        ./rex compare "$T/${s}_clang_O0" -o "$T/c0.re" >/dev/null
    done
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
# vector code stays an explicit refusal
build gcc O2 entities
! ./rex decompile "$T/entities_gcc_O2" -o "$T/e.rex" 2> "$T/e.err"
grep -q 'E200' "$T/e.err"
rm -rf "$T"
echo "game: ok"
