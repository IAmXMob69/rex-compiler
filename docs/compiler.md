# REX architecture

Audit of this tree. Version: 0.17.0 (`REX_VERSION` in `src/rex.c`). Every claim below is checked against the source. It is not a claim that REX matches GCC, Clang, Rust, Go, or MSVC.

## Two pipelines

```
compile     .rex → lex_next → parse_* → Node AST → gen_program → AT&T text
                 → rex_write_elf (src/elf.c) → ELF64, one RWX PT_LOAD at 0x400000

binary      ELF64 → rex_elf_open → x86 decoder → cfg_build → x86_lift → IrModule
                 ├→ cg_emit_module → rex_recompile → new ELF        (rex recompile)
                 ├→ rex_decompile → .rex source                     (rex decompile)
                 └→ ir_print_func                                   (rex ir)
```

`rex inspect` and `rex disasm` (`src/inspect.c`) stop after the loader and the CFG.

## Front end (`src/rex.c`)

- Lexer: `lex_next` over a `Lexer` with line and column. Tokens are `TokKind`.
- Parser: recursive descent, one function per precedence level: `parse_primary` → `parse_postfix` → `parse_unary` → `parse_factor` → `parse_term` → `parse_shift` → `parse_cmp` → `parse_eq` → `parse_bitand` → `parse_bitxor` → `parse_bitor` → `parse_and` → `parse_expr`. Statements: `parse_stmt`, `parse_block`. Top level: `parse_program`, `parse_struct`, `parse_global`, `parse_enum`.
- Error recovery: `sync_stmt` skips to the next statement, so one run reports several errors. `error_at` / `show_line` print file, line, column, the source line and a caret.
- AST: one `Node` type tagged by `NodeKind`. No typed AST, no separate semantic pass.
- Scope: `scan_locals` assigns stack slots per function. `require_declared` enforces use after `let`. `local_add_slots` rejects duplicates.
- Types: `ty_of` / `check_node` / `need_num` check a tag per expression (number, string, array, pointer, struct, function pointer) while the code generator runs. `rex check` stops before codegen.
- Codegen: `gen_fn2`, `gen_stmt`, `gen_expr`, `gen_cmp`. Output is AT&T text to a temp `.s` file, then `compile_to` hands it to `rex_write_elf`.
- Calls: SysV AMD64, at most 6 arguments (`fn_arity`, `collect_fns`).

## Assembler and ELF writer (`src/elf.c`)

`rex_write_elf` runs `asm_line` over the compiler's text, then over the embedded `runtime` string. `asm_line` accepts a fixed set of instruction shapes; anything else fails the compile. Labels are resolved as rel32. Undefined `rex_g_*` labels become an 8-byte zero global; undefined `rexfn_*` labels become a lone `ret`.

Output: one ELF64 header, one `PT_LOAD` with flags RWX (7) at 0x400000, entry at `rex_start`. No sections, no symbols.

## Runtime

The code that runs is the `runtime` string in `src/elf.c`: `rex_start`, `rex_print_int`, `rex_print_str`, `rex_putc`, `rex_read_int`, `rex_exec`, `rex_alloc`, `rex_free`, `rex_load`, `rex_fail`, `rex_strlen`, `rex_strcmp` and helpers. All of it is raw syscalls: read 0, write 1, open 2, mmap 9, munmap 11, fork 57, execve 59, exit 60, wait4 61.

`src/rexrt.c` is a libc version of a few of the same helpers. Nothing links it. `make install` still copies it to `share/rex/rexrt.c`. `rt_path` (which reads `REX_RUNTIME`) is never called, so the `REX_RUNTIME=` prefix in `make test` has no effect. The two runtimes are not generated from one source and do drift: `rexrt.c` has no `alloc`, `free`, `load`, `putc` or string helpers.

## ELF loader (`src/elfread.c`)

`rex_elf_open` / `rex_elf_parse` treat the input as untrusted. Every offset is bounds-checked (`in_file`); nothing is executed. Accepts ELF64, little-endian, x86-64, OS ABI 0 or 3, `ET_EXEC`. Refuses 32-bit, big-endian, relocatable, shared/PIE, core, extended program header and section counts. `rex_elf_code_at` maps a virtual address to bytes.

## Decoder and CFG (`src/x86_decode.c`, `src/cfg.c`)

The decoder turns bytes into `X86Insn` with destination-first operands. It covers what REX emits: mov, movzx/movsx, lea, push/pop, add/sub/and/or/xor, shl/shr/sar, inc/dec, neg/not, imul, idiv/div, cqo, cmp/test, jmp/jcc, call, ret, setcc, syscall, nop.

`cfg_build` does recursive descent from the entry point. No linear sweep. Direct calls start new functions; jumps stay inside the function. Indirect jumps are refused. `cfg_is_exit` marks blocks that end in an exit syscall. `main_addr` is the first direct call from the entry.

## Machine IR (`src/ir.h`, `src/ir.c`)

Architecture-independent. Registers are plain numbers; the front end gives them meaning.

- `IrModule` → `IrFunc` (name, address) → `IrBlock` (id, address, `succ[2]`) → `IrInsn`.
- `IrInsn`: `op`, `cc`, operands `dst`, `a`, `b`, and `origin` (source address).
- `IrOperand` kinds: `REG`, `IMM`, `MEM` (base, index, scale, disp; base `IR_PC` is rip-relative), `BLOCK`, `ADDR`. Widths 1, 2, 4, 8 bytes.
- Ops: `MOV LOAD STORE ADDR`, `ADD SUB MUL DIVS REMS`, `AND OR XOR SHL SHR SAR`, `NEG NOT ZEXT SEXT`, `CMP TEST SETCC`, `JMP BR CALL RET`, `PUSH POP SYSCALL TRAP`, `NOP`.
- Conditions: `EQ NE LT LE GT GE ULT ULE UGT UGE NEG POS`.
- Flags are one implicit value per function: only `CMP`/`TEST` write it; `BR`/`SETCC` read it.
- `ir_link` checks that every block ends in a terminator and fills successors. `ir_print_func` is what `rex ir` prints.

## x86 lift (`src/x86_lift.c`)

IR register n is x86 register n (rax=0 … r15=15). `lift_insn` rules:

- `mov` becomes `LOAD`, `STORE` or `MOV` by operand kind. `lea` becomes `ADDR`.
- A 32-bit write is followed by an explicit `ZEXT` (`zext32`); 8/16-bit writes keep the upper bits.
- ALU ops are three-address (`dst = dst op src`). `inc`/`dec` become `ADD`/`SUB` 1.
- `cqo` becomes `MOV rdx, rax; SAR rdx, 63`. `idiv` becomes `REMS` then `DIVS`, only if rdx was last set by `cqo` (rax untouched) or `xor edx, edx` in the same block.
- When a branch reads flags from an ALU result instead of cmp/test, `need_flags` inserts the matching `TEST`.
- `jcc` must end its block and becomes `BR taken, fallthrough`. `call` keeps its return address in `b`. An exit syscall is followed by `TRAP`.
- Refused with an error: `ah`/`bh`/`ch`/`dh`, unsigned `div`, `cltd`/`cwtd`, other `idiv` forms, 16-bit push/pop, unmapped conditions, odd branch shapes, jumps outside the function, any unlisted instruction.

## Recompiler (`src/codegen.c`, `src/recompiler.c`)

`cg_emit_module` encodes each IR op back to x86-64 bytes (REX prefix, ModRM, SIB by hand) and lays out functions. Block jumps are local fixups; calls to an `ADDR` are rel32 relocations by original address; register calls become `call *reg`. `TRAP` emits nothing. It refuses pc-relative `ADDR`, 8/16-bit shifts, non-register divisors, and other forms it cannot encode exactly (`cgfail`).

`rex_recompile` copies every original `PT_LOAD` unchanged at its old address and flags, adds one R+X segment at the next page above them plus 0x100000, points the entry at the new `start`, and rebinds calls to lifted functions to the new code. Calls to anything else go to the original address. The image must stay below 2 GiB (rel32). `--poison` overwrites every decoded original instruction with `int3`. `--debug` prints counts and the old → new address map.

## Decompiler (`src/decompiler.c`)

`rex_decompile` lifts, then `classify`:

- `start` is skipped. The function at `main_addr` is `main`. Others are `f<N>`.
- A function with a syscall is a runtime helper, guessed by shape: div plus 10 → `print`, mmap → `alloc`, munmap → `free`, a byte store → `putc`, else `print`.
- Parameters come from early stores of argument registers to `[rbp-…]`: `a`, `b`, `c`, …. Other stack slots become `t<N>`.

`step` evaluates IR symbolically into expressions; `walk2` rebuilds `if`/`else` (via `find_join`) and `while` (via `is_loop_header`). Prologue and epilogue are dropped. Calls to unrecognized helpers such as `rex_fail` are dropped. A call through a register prints the pointer expression called with two arguments. Output starts with two `//` header lines. `--verbose` prints each function's kind, argument count and builtin.

## Feature matrix

| Area | Present | Missing |
| --- | --- | --- |
| Integers | signed 64-bit only | i8/i16/i32, unsigned, bool type |
| Control | if/else, while, do, for, break, continue, switch | pattern matching, result types |
| Functions | up to 6 args, function pointers | varargs, methods, nested functions |
| Data | fixed arrays, structs, pointers, globals, heap | nested structs, slices, maps, modules |
| Constants | `#define NAME integer`, char literals, enum | typed constants, const |
| Strings | literals, index, len, equality | safe string type, formatting |
| Output | x86-64 Linux ELF, one RWX load | objects, relocations, ARM64, PE, Mach-O |
| Binary input | ELF64 x86-64 `ET_EXEC` | PIE, shared objects, other arches |
| Back half | inspect, disasm, CFG, IR, recompile, decompile | optimization, full decompile of loops/arrays/switch |
| Tools | `run build check asm elf inspect disasm ir recompile decompile version`, Mousepad spec | fmt, lint, lsp, package manager |
| Tests | example outputs, negative diagnostics, `rexcomp` fixed point, unit tests (IR, ELF reader, decoder), recompile and decompile round trips | fuzz, diagnostic snapshots |

## Global state

Lexer and parser state is local. The rest of `src/rex.c` is file-scope: `g_out`, `g_lbl`, `g_fn`, `g_break`/`g_cont`, `g_macros`, `g_fns`/`g_arity`, `g_sd`, `g_globs`, `g_strs`, `g_err`, `g_src`/`g_path`, `g_panic`. `src/elf.c` keeps labels, relocations and the code buffer in globals too. Two compilations in one process interfere, which blocks a library API or a language server until this becomes a context struct. The back half (`elfread`, `cfg`, `x86_lift`, `codegen`, `recompiler`, `decompiler`) passes state explicitly.

## Limits

- Fixed tables: 64 locals per function, 8 fields per struct, 16 struct types, 64 macros, 32 globals.
- Integer overflow is checked for decimal literals only, not for `+`, `*` or shifts at run time.
- One RWX segment. No W^X.
- `exec` is `fork` plus `/bin/sh -c`. That is a security footgun; do not feed it outside input.
- Recompile and decompile are designed for REX's own output. Other binaries usually stop at the lift or the encoder with an error.
- Decompile partly recovers loops, arrays, pointers and globals. Switch, nested structs and most pointer arithmetic stay opaque. Names are invented.
- No optimization anywhere. No second architecture: instruction names, syscall numbers and ELF headers are inline.

## Known issues

- `make` warns: `src/rex.c:1907: suggest parentheses around '&&' within '||' [-Wparentheses]`. The condition is long and hard-coded around names such as `names`, `lens`, `offs`, `firsts`. Behaviour is as written; the intent should be bracketed explicitly.
- `rt_path` and `REX_RUNTIME` are dead (hidden by `-Wno-unused-function`). `src/rexrt.c` is installed but unused.
- Nodes store a line, not a column. The caret uses a token column only when the caller passes one (`col_of`).
- Self-host is not done. `examples/rexcomp.rex` reaches a fixed point for its own subset only. It is not a self-host of `src/rex.c`.
