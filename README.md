<p align="center"><img src="docs/logo/rex-logo-256.png" width="128" alt="REX logo"></p>

# REX

REX is a compiler for a small language, plus tools that open a Linux or Windows program, lift its machine code, and rebuild it or turn it back into source.

The compiler writes the finished program itself: no gcc, no assembler, no C library in the output. The result is an x86-64 Linux ELF that talks to the kernel directly.

## Install

You need a C compiler and `make` once, to build REX.

```
sudo pacman -S --needed base-devel   # Arch Linux; elsewhere install gcc and make
make
make test
sudo make install                    # rex goes to /usr/local/bin
```

`make PREFIX=/usr` and `sudo make PREFIX=/usr install` put it in `/usr` instead. Install also adds a menu launcher and a Mousepad color file for `.rex`.

## Quick start

Everyday commands:

```
rex look prog                 # headers: type, entry point, segments, imports, exports
rex show prog                 # the machine instructions
rex rebuild prog -o new       # write new code for the program from the lifted IR
rex tosource prog -o out.rex  # turn the program back into .rex (also: rex undo)
rex compare prog              # rebuild, run both, check they act the same
rex match prog                # tosource, build that source, run both, check they act the same
rex explain E503              # what an error code means
rex help                      # the command list
rex help match                # more about one command
```

`-o` is optional. `compare --ir` and `match --ir` also check that the lifted machine code matches. Add `--color=always`, `--color=never` or `--color=auto` (the default) to any command; auto colors errors only on a terminal, and `NO_COLOR` turns it off.

Writing and running `.rex`:

```
rex run hello.rex             # build and run; nothing is kept
rex build hello.rex -o hello  # keep the program (default a.out)
rex check hello.rex           # find mistakes, build nothing
```

More tools: `show --cfg` (functions and blocks), `show --function F` (one function), `ir` (print the machine IR), `asm` (print the assembly), `elf` (assemble REX assembly), `rebuild --poison` (fill the old code with `int3`, so only the new code can run), `rebuild --debug` (where each function moved), `version`. The older names `inspect`, `disasm`, `recompile` and `decompile` still work.

## The language

```
fn main() {
    let x = 40;
    let y = 2;
    print(x + y);
}
```

That prints 42.

- Integers are 64-bit signed. `+ - * / %`, comparisons, `&& || !` (`&&` and `||` stop early). Dividing by zero stops the program and says so.
- `if`/`else`, `while`, `for let i = 0; i < n; i = i + 1 { }`, `break`, `continue`, and `switch` (no fall-through).
- Functions take up to 6 numbers. `main` takes none.
- Fixed arrays (`let a[3];`, bounds-checked, `len(a)`), strings (`s[i]` is a byte, `len(s)`), `'A'` character numbers, and `#define NAME 10`.
- Pointers (`&x`, `*p`, `p + 1`, `p - q`), structs (`struct Point { x; y; }`, `p->x`), and globals (`let g = 40;` at file level).
- Optional types: `let n: int`, `let s: str`, `let p: ptr`. `rex check` catches use before `let`, duplicate names, wrong argument counts, and type mistakes, with a caret under each one.
- Built-ins: `print`, `read()`, `alloc(n)`/`free(p)`, and `exec("command")` (runs a shell command; only run files you trust).
- At most 64 names per function. A name works from its `let` line on.

`examples/` has a program for each feature, with its expected output. `examples/rexcomp.rex` is a smaller compiler written in REX that compiles its own source to the same assembly (`make test` checks it).

## What works today

**Loading.** ELF64 x86-64 programs: static or dynamically linked, fixed-address or PIE. PE32+ x86-64 Windows programs with no imports, relocations, TLS or .NET. REX reads files and never runs them while loading. Shared libraries, 32-bit, big-endian, object files and core dumps are refused with a plain reason.

**Instructions.** Everything REX's own compiler emits, plus what common gcc and clang `-O0` to `-O3` code uses:

- mov, lea, push/pop, add/sub/and/or/xor, inc/dec, neg/not, shifts, cmp/test, setcc, cmovcc, movzx/movsx, xchg, leave, endbr, nop forms, hlt/ud2, syscall
- multiply: imul with two or three operands, and one-operand mul/imul at 8, 16, 32 and 64 bits
- divide: 32- and 64-bit div and idiv, after cqo/cltd or a zeroed rdx
- switch jump tables, both absolute and PIE-relative
- SSE: 16-byte loads, stores and register moves; movd/movq; zeroing with xorps/pxor; register-to-register paddd, psubd, pand, por, pxor, pcmpeq/pcmpgt (b/w/d), punpck (low and high), pshufd, psrlq/psllq

**Rebuild (`rebuild`, `compare`).** The program's code is lifted to REX's machine IR, encoded again as fresh x86-64, and written to a new file. The original data stays at its old addresses. A simple PE32+ program rebuilds to a new PE with a `.rextext` section.

**Source recovery (`tosource`, `match`).**

- A REX-built program comes back as readable `.rex`. Runtime helpers become `print`, `alloc`, `free`, `read`, `exec`, `len` and string compare.
- gcc and clang code comes back as `.rex` with invented names: `vN` for registers, `g_ADDR` for globals, and exact 8/16/32-bit widths.
- Structure is recovered: `while`, `do`/`while`, `if`/`else`, `break`/`continue`, `&&`/`||` chains, and `switch`. A function that can't be nested prints as an exact state loop over `st`.
- Arrays and address-taken data live in one heap block (`gmem`), and an address-taken or very large stack frame in another (`fr`).
- Unsigned divides and high multiplies become emitted helpers (`udiv`, `urem`, `umulh`, `smulh`). SSE lanes are written as plain integer math.
- Calls through function pointers become `callp(p, ...)`. In dynamic programs, library calls print by name (`puts(...)`) and the C startup code is left out.

**Checking.** `compare` and `match` run the original and the rebuilt program on several inputs: no arguments, plus argument and stdin sets the original answers the same way twice. They compare exit status, stdout and stderr byte for byte. Each run gets 20 seconds at most. The `--verify` flag on `rebuild` and `tosource` does the same.

## Errors

Every refusal prints one plain sentence, then a code and the detail, for example `E503: prog is dynamically linked; ...`. The exit status is the code number when it fits in an exit status, and a bad command line exits with 2. `rex explain <code>` repeats the sentence. The full list with fixes is in [docs/errors.md](docs/errors.md).

- E1xx: opening the file (format, PE features)
- E2xx: decoding instructions
- E3xx: lifting to the IR
- E4xx: control flow (computed jumps, tangled paths)
- E5xx: rebuilding and checking a rebuild
- E6xx: recovering source and checking it

## Limits

- **Libraries.** `rebuild` and `compare` refuse a dynamically linked program (E503): the new file has no loader to bring in the C library. `match` can't rebuild a C library call (E602), and `tosource` still shows it by name.
- **SSE rebuild.** SSE code is recovered as source, but `rebuild` refuses it (E500).
- **Missing instructions.** 8/16-bit div is E302. String instructions, bt*, cmpxchg, other SSE math (such as pmuludq) and packed math with a memory operand are E200. ah/bh/ch/dh are E300.
- **Function pointers.** A call through a pointer to a C library function, or to a function with 6 arguments, is refused by `match` (E605).
- **Computed jumps.** A computed goto, an unreadable switch table, or a table whose bounds check can be skipped is E401. Paths too tangled to write in `.rex` are E402.
- **Memory.** One `.rex` memory block holds 4 KB (4088 bytes). Recovered source whose data block or frame block needs more is refused (E606).
- **No program arguments.** `.rex` programs have no argv, so recovered source sees no program arguments, and a program whose output depends on them does not match (E601).
- **Long runs.** A program that runs longer than 20 seconds can't be checked (E604).
- **Shapes.** Recovered gcc/clang source is exact but not pretty: names are invented, and nested structs and named array types are not recovered.
- **Rebuild gaps.** 8/16-bit shifts and pc-relative `lea` are not rebuilt yet (E500).
- **Formats.** x86-64 only: no ARM, no Mach-O. PE imports, relocations, TLS, .NET and packed files are refused.
- **The language.** x86-64 Linux output only, no nested structs, and memory from `alloc` stays until `free`. Recursion that never ends crashes, and REX reports the program was killed.

## Benchmark

`make bench-decompile` runs `tosource` and `match` on 115 programs: 43 REX examples, plus 36 small C programs and 36 game-style programs from `bench/game`, each built by gcc and clang at `-O0`, `-O1` and `-O2`.

- `tosource` succeeds on 115 of 115.
- `match` passes on 94 of 115: 29 REX examples, 31 C programs, and 34 game programs.
- `match --ir` passes on 26 of 115.

The misses are REX examples with globals, heap pointers or strings (E601/E603), string code that calls the C library (E602), and one game program whose data needs more than 4 KB (E606).

## Roadmap

No schedule.

1. Rebuild C library calls and dynamically linked programs (E602, E503).
2. Rebuild SSE code, and data or frames bigger than 4 KB.
3. More x86-64: 8/16-bit div, string instructions, bt*, cmpxchg, packed math from memory.
4. Better recovered source: loop guards proven equal to the loop condition, struct fields, named arrays, `.eh_frame` function starts.
5. PE imports and relocations.
6. Later: ARM64, RISC-V, Mach-O.

## How it works

```
.rex → lexer → parser → AST → codegen → assembly text → built-in assembler → ELF64

program → loader → x86 decoder → control-flow graph → lift → machine IR ─┬→ codegen → new program  (rebuild)
                                                                          └→ .rex source            (tosource)
```

- `src/rex.c`: compiler and command line. `src/elf.c`: assembler, ELF writer and runtime.
- `src/loader.c`, `src/elfread.c`: file formats.
- `src/x86_decode.c`, `src/cfg.c`, `src/x86_lift.c`, `src/ir.c`: decode, control flow, lift, IR.
- `src/codegen.c`, `src/recompiler.c`: rebuild. `src/decompiler.c`: source recovery. `src/verify.c`: running both programs and comparing them.
- `src/inspect.c`: `look` and `show`.

[docs/compiler.md](docs/compiler.md) covers the internals.

## Contributing and license

See [CONTRIBUTING.md](CONTRIBUTING.md). Before a change: `make` (0 warnings) and `make test`. For decompiler changes, also run `make bench-decompile` before and after. MIT licensed; see [LICENSE](LICENSE).
