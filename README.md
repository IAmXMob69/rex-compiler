# REX

REX is a small compiler. It turns a `.rex` file into a Linux program.

It writes the program itself. It does not call gcc. It does not call an assembler. The finished file is an ELF that talks to the kernel directly.

That is the point. chibicc, 8cc, and the Toomey tutorial stop at assembly and hand the rest to gcc. c4 interprets. TCC is a real C compiler and it is bigger. REX is not a C compiler. It is a finished compiler for a small language, in two files.

It is for Arch Linux. It also has a few XFCE files so Mousepad can color the code and you can open a `.rex` file from the menu.

`examples/rexcomp.rex` is a smaller compiler written in REX. The C compiler builds it. That program compiles its own source, and the assembly matches. The compiler produced by that compile still prints 42 for `examples/stage.rex`. That is a fixed point of the subset compiler. It is not a self-host of `src/rex.c`.

## What you can write

```
fn main() {
    let x = 40;
    let y = 2;
    print(x + y);
}
```

That prints 42.

You can use `+ - * / %`, and also `&&`, `||`, and `!`. `&&` and `||` stop early. Functions can take up to 6 numbers.

You can make a fixed list of integers. The length is a constant. Slots start at 0. A bad index stops the program. `len(a)` is the length.

```
fn main() {
    let a[3];
    a[0] = 40;
    a[1] = 2;
    a[2] = a[0] + a[1];
    print(a[2]);
    print(len(a));
}
```

`for` and `while` loop. `break` leaves the loop. `continue` skips to the next step. `switch` picks one constant case and does not fall through. `'A'` is a number. `#define NAME 10` is an integer constant.

```
fn main() {
    let s = 0;
    for let i = 1; i <= 10; i = i + 1 {
        s = s + i;
    }
    print(s);
}
```

A string can be stored and printed. `s[i]` is the byte at that slot. `len(s)` is the length.

You can take the address of a number or a struct. `p + 1` moves one number. `p - a` is how many slots apart they are. `p->x` reads a field through a struct pointer. A file-level `let g = 40;` is a global you can assign later.

```
struct Point { x; y; }

fn main() {
    let x = 40;
    let p = &x;
    *p = 2;
    let a = alloc(3);
    a[0] = x;
    print(len(a));
    free(a);
    let pt = Point;
    pt.x = 40;
    pt.y = 2;
    print(pt.x + pt.y);
}
```

```
fn main() {
    let msg = "REX";
    print(msg);
}
```

```
fn add(a, b) {
    return a + b;
}
```

`main` cannot take arguments. `print` writes a number or some text. `read()` reads a number. `exec("command")` runs a shell command and waits. Do not run a file you did not write.

A name does not work until its `let` line. Parameters work from the start of the function. `print(x); let x = 5;` is an error. You can only have 64 names in one function. The same name cannot be used twice in one function. A name in a `for` belongs to the whole function.

Numbers have to fit in a normal 64-bit signed integer. Divide by zero stops the program and says so. Zero prints as 0. A negative number prints with a minus.

## Install

You need a C compiler once, to build REX. After that, REX does not need one.

```
sudo pacman -S --needed base-devel
make
make test
sudo make install
```

That puts `rex` in `/usr/local/bin`.

If you want it in `/usr` instead:

```
make PREFIX=/usr
sudo make PREFIX=/usr install
```

## Use

```
rex run examples/loop.rex
rex build examples/arithmetic.rex -o arith
./arith
rex asm examples/functions.rex
```

`rex run` builds the program, runs it, and deletes it. `rex build` keeps the program. `rex asm` only prints the assembly.

`rex inspect` and `rex disasm` read an existing ELF. `rex recompile` lifts it through the machine IR and writes a new ELF. `rex decompile` writes a `.rex` file that often rebuilds for simple programs.

## Files

- `src/rex.c` is the compiler
- `src/elf.c` is the assembler and the ELF writer
- `src/ir.c` / `src/ir.h` is the machine IR (architecture-independent)
- `src/elfread.c` is the ELF64 loader (reads; never runs the input)
- `src/x86_decode.c` is the x86-64 decoder
- `src/cfg.c` builds the control-flow graph
- `src/x86_lift.c` lifts x86-64 into the machine IR
- `src/codegen.c` encodes the IR back to x86-64
- `src/recompiler.c` writes a new ELF from the IR
- `src/decompiler.c` recovers REX source from the IR
- `src/rexrt.c` is the old helper. The ELF path does not use it
- `examples/` has test programs
- `tests/` has unit tests for the IR, ELF reader and decoder
- `share/` has the XFCE launcher and the Mousepad color file

## Inspect, disassemble, recompile, decompile

```
rex inspect program
rex disasm program
rex disasm --cfg program
rex disasm --function main program
rex ir program
rex recompile program -o rebuilt
rex decompile program -o recovered.rex
```

The path is always:

```
ELF → loader → x86 decoder → CFG → machine IR → native ELF
                                         ↘ REX source
```

`rex recompile` keeps the original data segments at their old addresses and
puts new code in a fresh segment. With `--poison` the old code bytes are
filled with `int3`, so a matching run proves the new code is what executed.

`rex decompile` targets REX-built binaries. Names are invented. Runtime
helpers become `print` / `putc` / `alloc` / `free`. Loops, arrays, pointers,
globals, switches and function pointers are only partly recovered — see
Limits. Simple arithmetic, branches, calls and returns round-trip today.

## Limits

No nested structs. A struct stays in the function that created it, unless you pass its address. `alloc` memory stays until `free`. It only makes x86-64 Linux programs. A function that calls itself forever will crash. REX will tell you the program was killed. This is not a C compiler.

The recompiler and decompiler start from ELF64 x86-64 Linux executables
(ET_EXEC). Relocatable objects, PIE, shared libraries, Windows PE, ARM and
game binaries are out of scope for now. The decoder covers the instructions
REX itself emits (mov, push/pop, lea, arithmetic, logic, shifts, cmp/test,
jumps, calls, returns, setcc, cqo, syscall, movzx/movsx). Unsupported
opcodes stop the lift with a clear error. Indirect jumps are refused.
Function-pointer calls keep working after recompile because the original
code stays mapped; the decompiler turns them into opaque calls.
