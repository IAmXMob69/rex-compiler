# REX compiler architecture

Audit of the tree in this repository. Version string: 0.14.0. This is the Phase 0 record. It is not a claim that REX matches GCC, Clang, Rust, Go, or MSVC.

## Pipeline

```
.rex source
    lexer          src/rex.c lex_next
    parser         src/rex.c parse_*
    AST            Node
    one function   scan locals, then gen_expr / gen_stmt
    AT&T text      emitted into a buffer
    ELF writer     src/elf.c rex_write_elf
    Linux x86-64 executable
```

There is no separate semantic-analysis pass, no typed AST, and no IR. Types are a tag on each local: integer, fixed array, string, pointer, struct, or function pointer. The code generator checks some of those tags while it emits.

`src/rexrt.c` is the readable runtime. The bytes that actually run are the string embedded in `src/elf.c`. Those two can drift.

## What is elegant and should stay

- Two translation units. The language compiler and the assembler/ELF writer are separate.
- Direct ELF64. No gcc, no assembler, no libc in the generated program.
- SysV AMD64 calls. `print`, `read`, `exec`, `alloc`, `free`, and `load` are syscalls inside the embedded runtime.
- Bounds checks on fixed arrays, heap blocks, and string bytes.
- Division by zero is a diagnostic, not a raw signal, on the tested path.
- A name cannot be used before its `let`. That check already exists.

## Feature matrix

| Area | Present | Missing |
| --- | --- | --- |
| Integers | signed 64-bit only | i8/i16/i32, unsigned, bool as its own type |
| Control | if/else, while, do, for, break, continue, switch | pattern matching, result types |
| Functions | up to 6 args, function pointers | varargs, methods, nested functions |
| Data | fixed arrays, structs, pointers, globals, heap | slices, maps, modules |
| Constants | `#define NAME integer`, character literals, enum | typed constants, const |
| Strings | literals, index, len, equality | safe string type, formatting |
| Backend | x86-64 Linux ELF, one RWX load | objects, relocations, ARM64, PE, Mach-O |
| Tools | `run`, `build`, `asm`, `elf`, Mousepad spec | fmt, lint, lsp, package manager |
| Tests | example output compare, two negative tests | unit tests, fuzz, diagnostic snapshots |

## Global state

Lexer and parser are local. Everything else is process-global: output file, label counter, current function, break/continue labels, macros, function table, struct table, string table, error count, diagnostic source. Two compilations in one process would interfere. That blocks a library API and a language server until this is a context struct.

## x86-64 Linux assumptions

- ELF64, `EM_X86_64`, one `PT_LOAD` with read/write/execute.
- Syscalls 0, 1, 2, 9, 11, 57, 59, 60, 61.
- Registers and stack layout are SysV AMD64.
- `exec` is `fork` plus `/bin/sh -c`. That is a security footgun. A safer process API has to replace it before any real program takes outside input.

## Known bugs and limits

- Self-host is not done. `examples/rexcomp.rex` can compile `examples/stage.rex` to a program that prints 42. Compiling `rexcomp.rex` with that compiler does not produce a correct second compiler. The bootstrap remains the C sources.
- Diagnostics name a line, and now a column and a caret when the source is still in memory. They do not recover. The first hard error still exits.
- Nodes store a line and not a column. Caret placement uses the token column only when the caller passes it.
- Integer overflow is checked for decimal literals. It is not checked for `+`, `*`, or shifts in generated code.
- The assembler in `src/elf.c` accepts a fixed set of instruction strings. A new shape fails the compile. That is safer than a silent bad encoding, and it is why the backend cannot grow by accident.
- Structs have at most 8 fields. A function has at most 64 locals. There are at most 16 struct types and 64 macros.
- `rexrt.c` and the embedded runtime are not generated from one source.

## Portability blockers

A second architecture needs a target interface that does not exist. The instruction names, syscall numbers, and ELF header are inline. RISC-V or AArch64 cannot be added by a flag.

## Optimization

There is none beyond what the C compiler does to `rex` itself. Constant folding, dead code, and register allocation are future IR work. Do not bolt them onto the current emitter.

## Priority after this audit

1. Reliability and diagnostics. Started: errors print the file, line, column, source line, and a caret.
2. One context object instead of file-scope globals.
3. A real type checker in front of codegen.
4. Keep the C bootstrap until a REX compiler can compile that compiler and the outputs match.

Do not call the result 1.0 until the Phase 20 list in the development plan is actually true.
