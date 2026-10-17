# Contributing to REX

## Build and test

```sh
make                  # builds ./rex; must print 0 warnings
make test             # unit, CPU-diff, examples, round trips, golden decompile tests
make bench-decompile  # decompiler quality benchmark (writes CSV + markdown)
```

`make test` must pass before you open a PR. If you change the decompiler, run
`make bench-decompile` before and after your change and put both totals in the PR.

### Golden tests

`tests/golden/*.dec.rex` pin the exact `rex decompile` output for a set of
examples. `tests/golden.sh` (run by `make test`) diffs them, then checks
`match` on all of them and `match --ir` on the ones listed in `IR=`.

If you change decompiler output on purpose:

```sh
sh tests/golden.sh --update   # rewrite the golden files
git diff tests/golden         # read every change
sh tests/golden.sh            # must pass
```

Commit the golden changes in the same commit as the code that caused them,
and say why the new output is better. Never update goldens just to make a
failing test pass.

## Style

- Match the existing C style (C11, 4-space indent, short static helpers).
- 0 compiler warnings with the Makefile flags. All tests green.
- New refusals: a plain-English sentence first, then an E-code. Add the code
  to `src/rex_err.h` and to `docs/errors.md`, with a fix you have run.
- New command: give it an everyday alias. The everyday commands stay first in
  the README and in `rex help`.
- No tables in docs or help text, and no comparisons with other tools.
- Don't change the REX compile path (`src/rex.c`, `src/elf.c`, `src/codegen.c`)
  without tests that cover the change.
- State limits as they are. If something is measured, give the number.

## Pull requests

1. Fork the repo and create a branch from `main`.
2. Keep commits small and clear; one change per commit.
3. In the PR, describe what changed and why, which tests you ran, and which
   limits, E-codes or docs are affected.

## Welcome contributions

- Bug fixes (with a test that fails before the fix)
- Tests and fixtures
- Docs
- x86-64 decoder and lift coverage (with unit and CPU-diff tests)
- Decompiler recovery quality (with before/after benchmark numbers)
- Loaders for new formats (behind the `rex_bin_open` registry)

## Privacy

No personal data in fixtures, tests, binaries or logs: no names, emails,
home paths, tokens or real user files. Use small synthetic programs.

## License

By contributing you agree that your work is released under the
[MIT License](LICENSE).
