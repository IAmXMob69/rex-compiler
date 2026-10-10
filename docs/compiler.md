# REX architecture

Audit of this tree. Version: 0.17.0 (`REX_VERSION` in `src/rex.c`). Every claim below is checked against the source. Direction: a general-purpose reverse-engineering / recovery tool (load → CFG → machine IR → recompile / decompile), with the REX language compile path kept working. It is not a claim of parity with Ghidra, Binary Ninja, GCC, Clang, Rust, Go or MSVC.

### REX vs Ghidra / Binary Ninja

Stronger here: round-trip `compare`/`match` (optional `--ir`), plain-English refusals with stable `E` codes, a short everyday CLI, simple PE32+ look/show/rebuild, and a compile path that matches the recovery tools.

Weaker here: format/ISA breadth, no GUI or scripting, thin types/hints only, and deliberate refusals for packed/import-heavy/PIE binaries.

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

## CLI (`main` in `src/rex.c`)

Everyday names are the primary surface (`print_help`). `alias_cmd` maps:

| Everyday | Internal |
|---|---|
| `look` | `inspect` |
| `show` | `disasm` |
| `rebuild` | `recompile` |
| `tosource` / `undo` | `decompile` |
| `compare` | recompile + run-both check (`--ir` also diffs normalized main IR) |
| `match` | decompile + compile + run-both check (`--ir` also diffs IR) |
| `explain` | look up an `E` code |
| `help` / `-h` / `--help` | `print_help` |

`-o` is optional and may appear anywhere: `build` / `recompile` / `compare` default to `a.out`, `decompile` / `match` to `out.rex`. An unknown command prints `rex: unknown command 'X' (try rex help)` and exits 2. Failures print a plain-English line, then `E<nnn>: …` details (`rex_errf`).

## Tests

`make unit` builds four C tests: `tests/test_ir.c`, `tests/test_elf.c`, `tests/test_x86.c`, and `tests/test_cpu_diff.c`. The differential test compares a C model of the IR ops (`eval_add`, `eval_sub`, `eval_logic`, `eval_mul`, `eval_shl`/`shr`/`sar`) against the host CPU through inline asm, for results and flags, at widths 1, 2, 4 and 8 with edge and pseudo-random values. Without x86-64 inline asm it prints `cpu diff: SKIP`. `make test` then runs every example, the `rexcomp` fixed point (its `in.rex` lives in `/tmp/rex-test`, removed at the end), and the recompile/decompile round trips.

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

This is the only runtime. The old libc `src/rexrt.c`, the dead `rt_path` lookup and `REX_RUNTIME` are gone: a C runtime cannot replace the embedded one without a C compiler and libc, which REX output does not use, so there is nothing for it to drift from.

## Loader (`src/loader.h`, `src/loader.c`)

`rex_bin_open` / `rex_bin_parse` walk a registry of `RexLoader` entries (`name`, `probe`, `parse`). First matching probe wins.

| Name | Probe | Behavior |
| --- | --- | --- |
| `elf64` | `\x7fELF` | Full parse via `rex_elf_parse`. Same acceptance and refusals as before. |
| `pe` | `MZ` at 0 and `PE\0\0` at `e_lfanew` | PE32+ x86-64 static images: section table → synthetic `PT_LOAD`, entry = ImageBase+EntryRVA, `.text` via `code_at`. Refuses i386/ARM (`E104`), PE32 (`E105`), imports (`E106`), relocs (`E107`), TLS (`E108`), .NET (`E109`), packed/no-X (`E110`). Simple static PE rebuilds to a new PE32+ with a `.rextext` section; failure to emit cleanly is `E502`. |

Anything else returns `REX_BIN_ERR_UNRECOGNIZED` (exit 2) with `unrecognized binary format: <up to 8 bytes as hex>`. Callers (`inspect`, `disasm`, `ir`, `recompile`, `decompile`) go through the registry and propagate those exit codes.


## Failure codes

Each failure prints a plain-English first line, then `E<nnn>: …` details. `rex explain E101` reprints the plain line. The process exit status is the code.

| Code | Area | Meaning |
| --- | --- | --- |
| E100 | loader | unrecognized binary format (first bytes in hex) |
| E101 | loader | PE feature not supported (legacy / catch-all) |
| E102 | loader | ELF refused (class, endian, type, machine, …) |
| E103 | loader | open/read failure |
| E104 | loader | PE not x86-64 |
| E105 | loader | PE not PE32+ |
| E106 | loader | PE imports present |
| E107 | loader | PE relocations present |
| E108 | loader | PE TLS |
| E109 | loader | PE .NET / CLR |
| E110 | loader | PE packed / no executable section |
| E200 | decode | unsupported or invalid opcode at address |
| E300 | lift | cannot model instruction exactly |
| E302 | lift | idiv / div shape |
| E400 | CFG | recovery failed |
| E401 | CFG | indirect jump (reserved; today the block just ends) |
| E402 | CFG / decompile | irreducible control flow in main |
| E403 | CFG | address outside executable code |
| E500 | recompile | encode / layout failure |
| E501 | recompile | `--verify` / `--ir` mismatch |
| E502 | recompile | PE rebuild failed / not clean |
| E600 | decompile | recovery failure |
| E601 | decompile | `--verify` mismatch |

No silent partial output: a failure returns the code and prints the message. `--verify` on `recompile` / `decompile` runs both sides with no args and compares exit status plus combined stdout/stderr. `compare --ir` / `match --ir` also lift both sides and compare a normalized dump of `main` (identity `mov`, call return addresses, and rip displacements are stripped).

## ELF loader (`src/elfread.c`)

`rex_elf_open` / `rex_elf_parse` treat the input as untrusted. Every offset is bounds-checked (`in_file`); nothing is executed. Accepts ELF64, little-endian, x86-64, OS ABI 0 or 3, `ET_EXEC`. Refuses 32-bit, big-endian, relocatable, shared/PIE, core, extended program header and section counts. `rex_elf_code_at` maps a virtual address to bytes.

## Decoder and CFG (`src/x86_decode.c`, `src/cfg.c`)

The decoder turns bytes into `X86Insn` with destination-first operands. It covers what REX emits: mov, movzx/movsx, lea, push/pop, add/sub/and/or/xor, shl/shr/sar, inc/dec, neg/not, imul, idiv/div, cqo, cmp/test, jmp/jcc, call, ret, setcc, syscall, nop.

`cfg_build` does recursive descent from the entry point, then seeds more addresses from ELF `SYMTAB`/`DYNSYM` function symbols (paired with `.strtab`/`.dynstr`). No linear sweep. Direct calls start new functions; jumps stay inside the function. A rip-relative `lea` or `mov` also starts a function when the target begins with `push rbp` (0x55) or `endbr64`. Indirect jumps end the current block with no successors (they do not abort the whole CFG). `hlt`/`ud2` are terminators. Symbol names rename functions; `main` sets `main_addr` when present, else it stays the first direct call from the entry.

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
- `nop` / `endbr64` / `endbr32` emit nothing. `leave` becomes `mov rsp, rbp; pop rbp`.
- Refused with an error: `ah`/`bh`/`ch`/`dh`, unsigned `div`, `cltd`/`cwtd`, other `idiv` forms, 16-bit push/pop, unmapped conditions, odd branch shapes, jumps outside the function, any unlisted instruction.

## Recompiler (`src/codegen.c`, `src/recompiler.c`)

`cg_emit_module` encodes each IR op back to x86-64 bytes (REX prefix, ModRM, SIB by hand) and lays out functions. Block jumps are local fixups; calls to an `ADDR` are rel32 relocations by original address; register calls become `call *reg`. `TRAP` emits nothing. It refuses pc-relative `ADDR`, 8/16-bit shifts, non-register divisors, and other forms it cannot encode exactly (`cgfail`).

`rex_recompile` copies every original `PT_LOAD` unchanged at its old address and flags, adds one R+X segment at the next page above them plus 0x100000, points the entry at the new `start`, and rebinds calls to lifted functions to the new code. Calls to anything else go to the original address. The image must stay below 2 GiB (rel32). `--poison` overwrites every decoded original instruction with `int3`. `--debug` prints counts and the old → new address map.

## Decompiler (`src/decompiler.c`)

`rex_decompile` lifts, then `classify`:

- `start` is skipped. The function at `main_addr` is `main`. Others are `f<N>`.
- A function with a syscall is a runtime helper, guessed by shape in this order: fork/execve (57/59) → `exec`, read syscall plus a digit compare → `read`, div plus 10 → `print`, mmap → `alloc`, munmap → `free`, a byte store → `putc`, else `print`.
- A syscall-free leaf with no calls or multiplies is `strcmp` (two or more byte loads, three or more blocks) or `len` (byte load, compare with 0, add 1, at most one argument). A `strcmp` call is printed as `a == b`.
- Argument-register stores are not hidden as prologue (`is_prolog`), so parameter spills stay visible.
- Parameters come from early stores of argument registers to `[rbp-…]`: `a`, `b`, `c`, …. Other stack slots become `t<N>`.

`step` evaluates IR symbolically into expressions; `walk2` rebuilds `if`/`else` (via `find_join`) and `while` (via `is_loop_header`). Prologue and epilogue are dropped. Calls to unrecognized helpers such as `rex_fail` are dropped. A call through a register prints the pointer expression called with two arguments. Output starts with two `//` header lines. `--verbose` prints each function's kind, argument count and builtin.

## x86-64 decoder / lift roadmap

Present today (decoder + lift unless noted): the REX emission set, plus `nop` variants (`90`, `0f 1f /0`, `66`/`2e`/`3e`-prefixed nops), `endbr64`/`endbr32`, `leave`, `hlt`/`ud2`, `cmovcc` (IR_CMOV), `movzx`/`movsx` (0f b6/b7/be/bf), `test` r/m with register or immediate, `setcc`, `cqo`, shifts by imm and by `%cl`.

Next instruction groups, in rough leverage order for gcc/clang `-O0`/`-O1` output:

1. Remaining `movzx`/`movsx` / `movsxd` forms; `cdqe`.
2. More `imul` forms (one-operand full rdx:rax).
4. String ops (`movs`, `stos`, `rep` prefixes) — likely refused with a clear error for a long time.
5. `bt` / `bts` / `btr` / `btc`, `xchg`, `cmpxchg`, `xadd`.
6. General rip-relative memory in more ops; PIC/PLT call shapes.
7. Jump tables (switch) — CFG work as much as decode work.
8. SSE/AVX moves used as GPR spills (`movdqa`/`movaps` to stack).

## Roadmap (tool)

1. Real PE section and import parsing; then PE → the same IR subset.
2. Reducible-graph structuring (dominators → if/else/while) when no REX pattern matches; `.eh_frame` seeds. Keep the REX path as the high-quality case.
3. PIE, shared objects, relocations.
4. Mach-O, ARM64, RISC-V — each behind the same loader registry.

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
| Binary input | ELF64 x86-64 `ET_EXEC`; PE recognition stub | PE load, PIE, shared objects, Mach-O, other arches |
| Back half | inspect, disasm, CFG, IR, recompile, decompile | optimization, full decompile of loops/arrays/switch |
| Tools | `run build check asm elf inspect disasm ir recompile decompile version help`, aliases `look show rebuild tosource undo`, Mousepad spec | fmt, lint, lsp, package manager |
| Tests | example outputs, negative diagnostics, `rexcomp` fixed point, unit tests (IR, ELF reader, decoder), differential CPU tests, recompile and decompile round trips | fuzz, diagnostic snapshots |

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

- Nodes store a line, not a column. The caret uses a token column only when the caller passes one (`col_of`).
- Self-host is not done. `examples/rexcomp.rex` reaches a fixed point for its own subset only. It is not a self-host of `src/rex.c`.
