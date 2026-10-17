# REX architecture

Internals of this tree, checked against the source. Version: 0.17.0 (`REX_VERSION` in `src/rex.c`). REX is a recovery tool (load → CFG → machine IR → rebuild / source), with the REX language compile path kept working.

## Two pipelines

```
compile     .rex → lex_next → parse_* → Node AST → gen_program → AT&T text
                 → rex_write_elf (src/elf.c) → ELF64, one RWX PT_LOAD at 0x400000

binary      ELF64 / PE32+ → rex_bin_open → x86 decoder → cfg_build → x86_lift → IrModule
                 ├→ cg_emit_module → rex_recompile → new program  (rex rebuild)
                 ├→ rex_decompile → .rex source                   (rex tosource)
                 └→ ir_print_func                                 (rex ir)
```

`rex look` and `rex show` (`src/inspect.c`) stop after the loader and the CFG.

## CLI (`main` in `src/rex.c`)

Everyday names come first in `print_help`. `alias_cmd` maps them to the internal names:

- `look` → `inspect`, `show` → `disasm`, `rebuild` → `recompile`, `tosource` and `undo` → `decompile`
- `compare`: rebuild, then run both (`--ir` also diffs the normalized IR of `main`)
- `match`: source, build it, then run both (`--ir` also diffs the IR)
- `explain`: the plain sentence for an `E` code
- `help`, `-h`, `--help`: `print_help`; `rex help <command>` prints one command's options

`-o` is optional and may appear anywhere: `build` / `rebuild` / `compare` default to `a.out`, `tosource` / `match` to `out.rex`. An unknown command says so, points to `rex help`, and exits 2. Failures print a plain-English line, then `E<nnn>: …` details (`rex_errf`).

## Tests

`make unit` builds eight C tests: IR (`test_ir`), ELF reader (`test_elf`), loader registry (`test_loader`), error codes (`test_err`), PE (`test_pe`), decoder (`test_x86`), CPU differential (`test_cpu_diff`) and the run-both checker (`test_verify`). The differential test compares a C model of the IR ops against the host CPU through inline asm, for results and flags, at widths 1, 2, 4 and 8 with edge and pseudo-random values; without x86-64 inline asm it prints `cpu diff: SKIP`.

`make test` then runs `test_cli`, every example against its `.out`, the negative diagnostics, the `rexcomp` stages and fixed point (its `in.rex` lives in `/tmp/rex-test`, removed at the end), the rebuild and source round trips, a tiny PE32+ rebuild, and `tests/golden.sh`, `tests/game.sh` and `tests/dyn.sh`.

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

The code that runs is the `runtime` string in `src/elf.c`: `rex_start`, `rex_print_int`, `rex_print_str`, `rex_putc`, `rex_read_int`, `rex_exec`, `rex_alloc`, `rex_free`, `rex_load`, `rex_fail`, `rex_strlen`, `rex_strcmp` and helpers. All of it is raw syscalls: read 0, write 1, open 2, mmap 9, munmap 11, fork 57, execve 59, exit 60, wait4 61. An `alloc` is one 4 KB page, 4088 bytes of it usable.

This is the only runtime. There is no libc runtime to drift from.

## Loaders (`src/loader.c`, `src/elfread.c`)

`rex_bin_open` / `rex_bin_parse` walk a registry of `RexLoader` entries (`name`, `probe`, `parse`). First matching probe wins.

- `elf64` (probe `\x7fELF`): `rex_elf_parse`. Treats the file as untrusted: every offset is bounds-checked (`in_file`), nothing runs. Accepts ELF64, little-endian, x86-64, OS ABI 0 or 3, `ET_EXEC`, and `ET_DYN` with an entry point (PIE). Dynamic programs (`PT_DYNAMIC` / `PT_INTERP`) load, and their PLT slots are named after the imports. Refuses 32-bit, big-endian, relocatable objects, shared libraries (no entry point), core dumps, and extended header counts (`E102`).
- `pe` (probe `MZ` at 0 and `PE\0\0` at `e_lfanew`): PE32+ x86-64 static images. The section table becomes synthetic `PT_LOAD`s; entry = ImageBase + EntryRVA. Refuses non-x86-64 (`E104`), PE32 (`E105`), imports (`E106`), relocations (`E107`), TLS (`E108`), .NET (`E109`), packed or no executable section (`E110`); a cut-off or out-of-bounds header is `E101`.

Anything else is `E100` (`unrecognized binary format: <up to 8 bytes as hex>`, exit 100). `look`, `show`, `ir`, `rebuild` and `tosource` all go through the registry, so `look` refuses the same files.

## Failure codes

Each failure prints a plain-English first line, then `E<nnn>: …` details. `rex explain E101` reprints the plain line. Every code, its sentence, its exit status where fixed, and a fix are in [errors.md](errors.md).

- E1xx: loader (`src/loader.c`, `src/elfread.c`)
- E2xx: decode (raised from `cfg_build`)
- E3xx: lift (`lfail` in `src/x86_lift.c`; E302 for div/idiv shapes)
- E4xx: CFG and structuring (E402 also from the decompiler)
- E5xx: rebuild (`cgfail` is always E500; E501 is a run-both mismatch; E503 a dynamic program)
- E6xx: source recovery and `match`

No silent partial output: a failure returns nonzero and prints the message.

## Run-both check (`src/verify.c`)

`compare`, `match` and `--verify` run both programs on four inputs: no arguments and empty stdin, then three argument and stdin sets that count only where the original gives the same result twice. They compare exit status, stdout and stderr byte for byte. Each run gets at most 20 s (`RUN_LIMIT_S`). `--ir` also lifts both sides and compares a normalized dump of `main` (identity `mov`, call return addresses and rip displacements are stripped).

## Decoder (`src/x86_decode.c`)

The decoder turns bytes into `X86Insn` with destination-first operands. Opcodes: mov, movzx/movsx/movsxd, cwde/cdqe, lea, push/pop, add/sub/and/or/xor, shl/shr/sar (by imm and by `%cl`), inc/dec, neg/not, imul (one, two and three operands), mul, idiv/div, cqo/cltd, cmp/test, jmp/jcc, call, ret, setcc, cmovcc, xchg, syscall, leave, hlt/ud2, endbr64/endbr32, and nop forms.

SSE (`decode_sse`):

- Moves: movaps/movups/movdqa/movdqu (load, store, register to register), movd/movq to and from a GPR, movq low-8 load and store, and the xorps/pxor self-zero idiom.
- Packed integer math, register sources only: paddd, psubd, pand, por, pxor, pcmpeqb/w/d, pcmpgtb/w/d, punpckl and punpckh (bw, wd, dq, qdq), pshufd with an immediate, psrlq/psllq with an immediate.
- Not decoded, so `E200`: the same ops with a memory source (`paddd m128`, `pshufd m128`), and every other SSE op (pmuludq, paddq, psrld, pmulld, ...).

Also `E200`: string instructions (`movs`, `stos`, `rep`), bt/bts/btr/btc, cmpxchg, xadd, and bytes cut off at the end of the code.

## CFG (`src/cfg.c`)

`cfg_build` does recursive descent from the entry point, then seeds more addresses from ELF `SYMTAB`/`DYNSYM` function symbols. No linear sweep. Direct calls start new functions; jumps stay inside the function, and a jump to another function's entry is a tail call. A rip-relative `lea` or `mov` also starts a function when the target begins with `push rbp` (0x55) or `endbr64`.

- `main`: the `main` symbol, else the first direct call from the entry, else the address a dynamic `_start` passes to the C library in `rdi`.
- Jump tables: absolute (`cmp`/`ja` then `jmp *T(,r,8)`, or a load then `jmp *reg`) and PIE-relative (32-bit offsets from the table) are read from a read-only section when every entry is code and the bounds check guards every path in. They become a compare chain.
- Other indirect jumps: a target from a global slot (function pointer, GOT entry) or a constant is an indirect tail call. Anything else is `E401`, as are unclear tables.
- Functions reached only through symbols (C runtime helpers) are built leniently and dropped if they fail; if `main` reaches one, it is built strictly.
- `hlt`/`ud2` are terminators. Symbol names rename functions.

## Machine IR (`src/ir.h`, `src/ir.c`)

Architecture-independent. Registers are plain numbers; the front end gives them meaning.

- `IrModule` → `IrFunc` (name, address) → `IrBlock` (id, address, `succ[2]`) → `IrInsn`.
- `IrInsn`: `op`, `cc`, operands `dst`, `a`, `b`, and `origin` (source address).
- `IrOperand` kinds: `REG`, `IMM`, `MEM` (base, index, scale, disp; base `IR_PC` is rip-relative), `BLOCK`, `ADDR`. Widths 1, 2, 4, 8 bytes.
- Ops: `MOV LOAD STORE ADDR`, `ADD SUB MUL DIVS REMS DIVU REMU MULHU MULHS`, `AND OR XOR SHL SHR SAR`, `NEG NOT ZEXT SEXT`, `CMP TEST SETCC CMOV`, `JMP BR CALL RET`, `PUSH POP SYSCALL TRAP`, `VEC`, `NOP`.
- `VEC` is a packed lane op (`IR_V_*`: add, sub, and, or, xor, cmpeq, cmpgt, shufd, unpckl/unpckh, srlq/sllq). An xmm register is a pair of 64-bit pseudo-registers (16+n low, 32+n high).
- Conditions: `EQ NE LT LE GT GE ULT ULE UGT UGE NEG POS`.
- Flags are one implicit value per function: only `CMP`/`TEST` write it; `BR`/`SETCC`/`CMOV` read it.
- `ir_link` checks that every block ends in a terminator and fills successors. `ir_print_func` is what `rex ir` prints.

## x86 lift (`src/x86_lift.c`)

IR register n is x86 register n (rax=0 … r15=15). `lift_insn` rules:

- `mov` becomes `LOAD`, `STORE` or `MOV` by operand kind. `lea` becomes `ADDR`.
- A 32-bit write is followed by an explicit `ZEXT`; 8/16-bit writes keep the upper bits.
- ALU ops are three-address (`dst = dst op src`). `inc`/`dec` become `ADD`/`SUB` 1.
- `cqo` becomes `MOV rdx, rax; SAR rdx, 63`. `cltd` sets `edx` to the sign bits of `eax`, then zero-extends.
- `idiv`: 64-bit after `cqo`/`cltd` or a zeroed rdx in the same block; 32-bit sign-extends both sides and divides at 64 bits.
- `div`: 32- and 64-bit after `xor edx, edx` or `mov edx, 0` in the block. A scratch register (r11) it borrows is saved and put back.
- One-operand `mul`/`imul`: 64/32-bit into rdx:rax, 16-bit into dx:ax, 8-bit into ax (`MULHU`/`MULHS` for the high half).
- `add`/`sub` without their own compare own the flags. When a branch reads flags from an ALU result, `need_flags` inserts the matching `TEST`.
- `jcc` ends its block and becomes `BR taken, fallthrough`. `call` keeps its return address in `b`. An exit syscall is followed by `TRAP`.
- `nop` / `endbr` emit nothing. `leave` becomes `mov rsp, rbp; pop rbp`. SSE moves and packed ops become `MOV`/`LOAD`/`STORE` on the xmm halves and `VEC`.
- Refused (`E300`, or `E302` for divides): `ah`/`bh`/`ch`/`dh`, 8/16-bit `div`, `div` without a zeroed rdx, other `idiv` forms, `cwtd`, 16-bit push/pop, flags set outside the block or by an unmodeled instruction, conditions that need carry/overflow from arithmetic, odd branch shapes, jumps outside the function, and any other instruction.

## Rebuild (`src/codegen.c`, `src/recompiler.c`)

`cg_emit_module` encodes each IR op back to x86-64 bytes (REX prefix, ModRM, SIB by hand) and lays out functions. Block jumps are local fixups; calls to an `ADDR` are rel32 relocations by original address; register calls become `call *reg`. `TRAP` emits nothing. It refuses SSE registers, pc-relative `ADDR`, 8/16-bit shifts, non-register divisors, and other forms it cannot encode exactly (`cgfail`, always `E500`).

`rex_recompile` refuses a program with `PT_INTERP` (`E503`): the new file would have no loader for the C library. Otherwise it copies every original `PT_LOAD` unchanged, adds one R+X segment above them, points the entry at the new `start`, and rebinds calls to lifted functions to the new code. Calls to anything else go to the original address. The image must stay below 2 GiB (rel32). `--poison` overwrites every decoded original instruction with `int3`. `--debug` prints counts and the old → new address map. A simple PE32+ rebuilds to a new PE with a `.rextext` section.

## Source recovery (`src/decompiler.c`)

`rex_decompile` lifts, refuses an irreducible `main` with `E402`, then `classify`:

- `start` is skipped. The function at `main_addr` is `main`. Others are `f<N>`.
- In a REX program, a function with a syscall is a runtime helper, guessed by shape: fork/execve → `exec`, read plus a digit compare → `read`, div plus 10 → `print`, mmap → `alloc`, munmap → `free`, a byte store → `putc`, else `print`. A syscall-free leaf is `strcmp` or `len` by shape; a `strcmp` call prints as `a == b`.
- Parameters come from early stores of argument registers (`a`, `b`, `c`, …), or, in gcc/clang code, from argument registers live at entry. Other stack slots become `t<N>`. In gcc/clang code, registers become `vN` and scalar globals `g_ADDR`.

`step` evaluates IR symbolically into expressions. Structuring uses dominators and postdominators: `if`/`else`, `while`, `do`/`while`, `break`/`continue`, `&&`/`||` chains, and `switch` from REX compare chains or jump tables. A function the structurer cannot nest prints as an exact dispatch loop (`let st = 0; while (1) { if (st == 0) { … } … }`); running out of the structurer budget is a clean `E402`.

gcc/clang (non-REX) programs:

- Data: if any function indexes or takes the address of `.data`/`.bss`/`.rodata`, those sections are copied into one heap block `gmem` at the top of `main`. Data addresses print as `(gmem + off)`.
- Stack: a function that indexes, takes the address of, or copies its stack, or has more locals than REX gives a function names, gets its frame in a heap block `fr`, allocated on entry and freed at each return.
- `gmem` or `fr` over 4088 bytes is `E606` for `match` and `--verify`.
- Unsigned divide prints `/` and `%` when both sides fit in 63 bits, else `udiv` / `urem` helpers emitted once at the top. High multiplies use `umulh` / `smulh`. Packed SSE lanes print as exact 64-bit integer math.
- A call through a pointer becomes `callp(p, args...)`, which picks the recovered function whose original address `p` holds (`E605` when it can't).
- In dynamic programs, library calls print by name through the PLT (`puts(...)`) and the C startup code is left out. `match` refuses them (`E602`).
- Register expressions that read memory are pinned in `xN` before a store or call that could change that memory. Caller-saved registers survive a call to a function that provably never writes them (a fixpoint over the call graph).

Output starts with two `//` header lines. `--verbose` prints each function's kind, argument count and builtin.

## Global state

Lexer and parser state is local. The rest of `src/rex.c` is file-scope: `g_out`, `g_lbl`, `g_fn`, `g_break`/`g_cont`, `g_macros`, `g_fns`/`g_arity`, `g_sd`, `g_globs`, `g_strs`, `g_err`, `g_src`/`g_path`, `g_panic`. `src/elf.c` keeps labels, relocations and the code buffer in globals too. Two compilations in one process interfere, which blocks a library API or a language server until this becomes a context struct. The back half passes state explicitly.

## Limits

- Fixed tables: 64 locals per function, 8 fields per struct, 16 struct types, 64 macros, 32 globals.
- Integer overflow is checked for decimal literals only, not for `+`, `*` or shifts at run time.
- One RWX segment. No W^X.
- `exec` is `fork` plus `/bin/sh -c`. Do not feed it outside input.
- No optimization anywhere. No second architecture: instruction names, syscall numbers and ELF headers are inline.
- Recovered gcc/clang source is exact but not pretty: names are invented, arrays are byte offsets in `gmem`/`fr`, and nested structs stay opaque.

The user-facing limits and the roadmap are in the [README](../README.md).

## Known issues

- A frame block `fr` is allocated on every call and freed at each return; mutual recursion through an unrecovered path could still leak.
- A call through a register, to a builtin or to an external address is treated as clobbering every caller-saved register.
- Nodes store a line, not a column. The caret uses a token column only when the caller passes one (`col_of`).
- Self-host is not done. `examples/rexcomp.rex` reaches a fixed point for its own subset only, not for `src/rex.c`.
