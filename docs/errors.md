# Error codes

Every refusal prints a plain sentence, then a line like `E103: <details>`. The
exit code is the number when it fits (for example 103); a bad command line exits
with 2. Run `rex explain E103` for any single code.

Each entry below is the plain sentence REX prints, then a one-line fix.

## Opening a file

- **E100** — I do not recognize this file type.
  Fix: give a Linux ELF or a Windows .exe/.dll.
- **E101** — This Windows program needs a feature I do not support yet.
  Fix: run `rex look <prog>` to see which part.
- **E102** — This Linux-style program file is a kind I can't open.
  Fix: use a 64-bit x86-64 ELF program. PIE and dynamically linked programs
  open; a shared library has no entry point, so it is not a program.
- **E103** — I could not read that file.
  Fix: check the path and that you can read it.
- **E104** — This Windows program is built for a different processor than x86-64.
  Fix: use an x86-64 Windows program.
- **E105** — This Windows program is 32-bit, and I only handle 64-bit ones.
  Fix: use a 64-bit (x86-64) build.
- **E106** — This Windows program borrows code from other files in a way I can't follow yet.
  Fix: use a program with no imports, or `rex look` to see them.
- **E107** — This Windows program needs its addresses adjusted when it loads, and I can't do that yet.
  Fix: use a non-relocatable build.
- **E108** — This Windows program keeps separate data for each task it runs at once, and I can't handle that yet.
  Fix: use a program without thread-local storage.
- **E109** — This is a .NET program, and I only read native code.
  Fix: use a .NET tool instead.
- **E110** — This program looks squeezed or scrambled, so I won't guess what it does.
  Fix: unpack it first, or `rex look` to see which parts.

## Reading the code

- **E200** — I found a processor instruction I don't know yet.
  Fix: run `rex show <prog>` to see where it stopped.
- **E201** — The file ends in the middle of an instruction.
  Fix: the file may be truncated; try another copy.
- **E300** — I couldn't translate that instruction into my own working format.
  Fix: try `rex tosource --c`, which skips what it can't follow.
- **E301** — I lost track of the processor's true/false flags at this spot.
  Fix: same as E300.
- **E302** — This divide step is written in a way I don't handle yet.
  Fix: same as E300.
- **E400** — I couldn't map out all the paths this program can take.
  Fix: run `rex show --cfg <prog>` to see where it broke.
- **E401** — The program jumps to a spot it only figures out while running, so I can't follow it.
  Raised for a computed goto, a switch table REX cannot read, or a table whose
  bounds check another path skips. A jump through a function pointer or a
  constant is a tail call, not E401.
  Fix: same as E400.
- **E402** — This program's paths are too tangled for me to follow right now.
  Fix: same as E400.
- **E403** — That address isn't in the part of the file that holds code.
  Fix: pick an address from `rex funcs`/`rex show`.

## Rebuilding and checking

- **E500** — I couldn't build the new program file.
  Fix: check the output folder and free disk space.
- **E501** — The new program acted differently from the original when I ran both.
  Fix: run `rex rebuild --poison --debug` to see which function changed.
- **E502** — I couldn't rebuild that Windows program correctly.
  Fix: use `rex tosource` to read it instead.
- **E600** — I couldn't turn this program back into readable code.
  Fix: try `rex tosource --c`.
- **E601** — The code I got back acted differently from the original when I ran both.
  Fix: this is a decompile gap; try `rex tosource --c` to read it instead.
- **E602** — This program calls code from a shared library (like printf), and I can't rebuild those calls yet.
  Fix: read it with `rex tosource`; library calls show by name. `match` and
  `decompile --verify` refuse because the rebuilt program has no library to call.
- **E603** — The code I got back doesn't build, so I can't check it against the original.
  Fix: this is a decompile gap; read the source with `rex tosource`. The detail
  names the first line the compiler stopped at.
- **E604** — The original program didn't finish within 20 seconds, so I had nothing to compare against.
  `match`, `compare` and `--verify` run each program for at most 20 s. Not a
  mismatch: the rebuilt program is not run. Exit status 92.
  Fix: use `rex tosource` (or `rebuild`) without checking, and run the result
  yourself.

- **E605** — This program calls a function through a pointer in a way I can't write in .rex yet.
  A call through a register or memory becomes `callp(pointer, args...)`, which
  picks the recovered function whose original address the pointer holds. That
  needs a recovered function with its address taken, taking at most 5
  arguments (the pointer is the sixth). A pointer to a C library function, or
  to a function with 6 arguments, is refused before building. `match` and
  `--verify` stop with exit status 93; `tosource` still writes the source.
  Fix: none yet in REX; the line names the function or the reason.

- **E606** — This program needs a bigger block of memory than .rex can hand out (4 KB).
  A REX `alloc` is one 4 KB page, 4088 bytes of it usable. A function whose
  stack lives in the frame block `fr` (it indexes or takes the address of its
  stack, or has more locals than REX gives a function names) or the data
  block `gmem` must fit in one. `match` and `--verify` stop with exit status
  94 before building; `tosource` still writes the source. The line names the
  function or the data sections and the size needed.
  Fix: none yet in REX.

## Not yet in the code

Shorter command-line, runtime, and `.rex` language codes (ranges E001–E012 and
E700–E705) have been proposed but are not emitted yet. They are future work and
are not promised by the current tool.
