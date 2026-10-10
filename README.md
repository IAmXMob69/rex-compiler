# REX

REX is a small compiler and binary toolchain for x86-64 Linux. It turns a `.rex` file into an ELF, and it turns that ELF back into machine IR, a new ELF, or `.rex` source.

It writes the program itself. It does not call gcc. It does not call an assembler. The finished file is an ELF that talks to the kernel directly.

That is the point. chibicc, 8cc, and the Toomey tutorial stop at assembly and hand the rest to gcc. c4 interprets. TCC is a real C compiler and it is bigger. REX is not a C compiler. It is a finished compiler for a small language, plus a loader, decoder, lifter, recompiler and decompiler for the binaries it makes.

It is for Arch Linux. It also has a few XFCE files so Mousepad can color the code and you can open a `.rex` file from the menu.

`examples/rexcomp.rex` is a smaller compiler written in REX. The C compiler builds it. That program compiles its own source, and the assembly matches. The compiler produced by that compile still prints 42 for `examples/stage.rex`. That is a fixed point of the subset compiler. It is not a self-host of `src/rex.c`.

## Commands

Everyday names (shortcuts):

| Command | Means |
|---------|--------|
| `rex run file.rex` | compile and run |
| `rex build file.rex` | make a binary (`-o` optional, default `a.out`) |
| `rex look elf` | peek at ELF headers (`inspect`) |
| `rex show elf` | disassemble (`disasm`) |
| `rex rebuild elf` | recompile from IR (`recompile`, `-o` optional, default `a.out`) |
| `rex tosource elf` / `rex undo elf` | recover `.rex` (`decompile`, `-o` optional, default `out.rex`) |
| `rex help` | plain help (also `-h`, `--help`) |

All older command names still work. An unknown command prints `rex: unknown command 'X' (try rex help)` and exits 2.

## Features

- Compiler: `.rex` → AST → AT&T text → built-in assembler → ELF64. No gcc, no `as`, no libc in the output.
- Checks: use before `let`, duplicate names, call arity, simple types (`rex check`). Errors carry a caret; several are reported per run.
- ELF64 loader: reads headers and segments. Never runs the input.
- x86-64 decoder and disassembler, with a control-flow graph per function.
- Machine IR: architecture-independent, printed by `rex ir`.
- x86 lift: x86-64 → machine IR.
- Recompile: machine IR → fresh x86-64 code in a new segment → new ELF.
- Decompile: machine IR → `.rex` source that rebuilds for simple programs.

## Pipeline

```
.rex → lexer → parser → AST → codegen → AT&T text → assembler → ELF64
                                                                 │
ELF64 → loader → x86 decoder → CFG → x86 lift → machine IR ──┬─→ codegen → native ELF   (rex recompile)
                                                             └─→ REX source            (rex decompile)
```

Front end: `src/rex.c`, `src/elf.c`. Back half: `elfread.c` → `x86_decode.c` → `cfg.c` → `x86_lift.c` → `ir.c` → `codegen.c` + `recompiler.c`, or `decompiler.c`.

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

That puts `rex` in `/usr/local/bin`. `make test` runs the unit tests (IR, ELF reader, decoder, differential CPU), every example, the `rexcomp` fixed point, and the recompile/decompile round trips.

If you want it in `/usr` instead:

```
make PREFIX=/usr
sudo make PREFIX=/usr install
```

## Use

### Compile

```
rex run examples/loop.rex                  # build, run, delete
rex build examples/arithmetic.rex -o arith # keep the binary
rex check examples/retbad.rex              # parse and type-check only
rex asm examples/functions.rex             # AT&T text to stdout
rex elf prog.s -o prog                     # assemble REX-emitted text
rex version
```

### Read a binary

```
rex inspect arith                  # ELF64 headers and segments
rex disasm arith                   # all executable segments
rex disasm --cfg arith             # functions and basic blocks
rex disasm --function main arith   # one function: start, main, fn_ADDR, ADDR
rex ir arith                       # lift to machine IR and print it
rex ir --function main arith
```

### Rebuild a binary

```
rex recompile arith -o arith.re            # new code, old data
rex recompile --poison arith -o arith.re   # old code filled with int3
rex recompile --debug arith -o arith.re    # per-function address map
rex decompile arith -o arith.rex           # recovered source
rex decompile --verbose arith -o arith.rex
```

Verified on `examples/arithmetic.rex`: the original, the `--poison` recompile, and `rex run arith.rex` all print the same six lines.

```
$ rex inspect arith
ELF64 x86-64 executable
Entry: 0x4005e6
Size: 1852 bytes
Executable segments: 1
...
$ rex ir --function main arith
func fn_400078 @0x400078
b0:  ; 0x400078
    push rbp:8
    mov rbp:8, rsp:8
    sub rsp:8, rsp:8, 16
    mov rax:8, 40
    store [rbp - 8]:8, rax:8
...
$ rex decompile arith -o arith.rex && head -9 arith.rex
// recovered by rex decompile
// REX-built ELF64 only; names are invented

fn main() {
    let t1 = 0;
    let t2 = 0;
    t1 = 40;
    t2 = 2;
    print((t1 + t2));
```

`rex recompile` keeps the original data segments at their old addresses and puts new code in a fresh segment. With `--poison` the old code bytes are filled with `int3`, so a matching run proves the new code is what executed.

`rex decompile` targets REX-built binaries. Names are invented. Runtime helpers are recognized by shape and become `print`, `putc`, `alloc`, `free`, `exec`, `read`, `len`, or `strcmp` (printed as `a == b`). Simple arithmetic, branches, calls and returns round-trip today.

## Limits

Language: No nested structs. A struct stays in the function that created it, unless you pass its address. `alloc` memory stays until `free`. It only makes x86-64 Linux programs. A function that calls itself forever will crash. REX will tell you the program was killed. This is not a C compiler.

Input binaries: ELF64, little-endian, x86-64, Linux/SysV ABI, `ET_EXEC` only. The loader refuses 32-bit ELF, big-endian, relocatable objects, shared objects and PIE, core dumps, and extended header/section counts. Windows PE, ARM and game binaries are out of scope.

Decoder and lift: the instructions REX itself emits (mov, push/pop, lea, arithmetic, logic, shifts, cmp/test, jumps, calls, returns, setcc, cqo, syscall, movzx/movsx). Direct calls start functions; a rip-relative `lea`/`mov` also does, but only when its target starts with `push rbp` (0x55) or `endbr64`. The lift stops with a clear error on unsupported opcodes, `ah`/`bh`/`ch`/`dh`, unsigned `div`, `cltd`/`cwtd`, unusual `idiv` forms, unsupported conditions and branch shapes. Indirect jumps are refused.

Recompile: no pc-relative `lea`, no 8/16-bit shifts. Function-pointer calls keep working because the original code stays mapped.

Decompile: names are invented. A call through a register prints the pointer expression with two arguments. Loops, arrays, pointers, globals and switches are only partly recovered; nested structs, switch and most pointer arithmetic stay opaque. Arbitrary binaries may be refused or give a stub that does not round-trip.

## Files

- `src/rex.c` is the compiler and the CLI
- `src/elf.c` is the assembler, the ELF writer and the embedded runtime
- `src/elfread.c` is the ELF64 loader (reads; never runs the input)
- `src/inspect.c` is `rex inspect` and `rex disasm`
- `src/x86_decode.c` is the x86-64 decoder
- `src/cfg.c` builds the control-flow graph
- `src/x86_lift.c` lifts x86-64 into the machine IR
- `src/ir.c` / `src/ir.h` is the machine IR (architecture-independent)
- `src/codegen.c` encodes the IR back to x86-64
- `src/recompiler.c` writes a new ELF from the IR
- `src/decompiler.c` recovers REX source from the IR
- `examples/` has test programs and expected output
- `tests/` has unit tests for the IR, ELF reader and decoder, and differential CPU tests (`test_cpu_diff.c`)
- `share/` has the XFCE launcher and the Mousepad color file
- `docs/compiler.md` is the architecture audit

See [docs/compiler.md](docs/compiler.md) for the front end, both pipelines, the machine IR, lift rules, runtime, global state and known issues.

`make unit` also runs differential CPU tests (`tests/test_cpu_diff.c`) checking alu/logic/shift/compare/test ops against host inline asm for results and flags across widths and edge values.
