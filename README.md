# REX

REX is a small compiler. It turns a `.rex` file into a normal Linux program.

It is for Arch Linux. It also has a few XFCE files so Mousepad can color the code and you can open a `.rex` file from the menu.

## What you can write

```
fn main() {
    let x = 40;
    let y = 2;
    print(x + y);
}
```

That prints 42.

You can use `+ - * / %`. You can use `if`, `else if`, and `while`. You can make functions, but they cannot take arguments. `print` writes a number or some text. `read()` reads a number. `exec("command")` runs a shell command. Do not run a file you did not write.

A name does not work until its `let` line. `print(x); let x = 5;` is an error. You can only have 64 names in one function. The same name cannot be used twice in one function.

There is no `&&`, no `||`, and no `!`. Numbers have to fit in a normal 64-bit signed integer. Divide by zero stops the program and says so.

## Install

You need `base-devel`.

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

## Files

- `src/rex.c` is the compiler
- `src/rexrt.c` is the small helper linked into every program
- `examples/` has test programs
- `share/` has the XFCE launcher and the Mousepad color file

## Limits

No function arguments. No lists. No text except in `print` and `exec`. It only makes x86-64 Linux programs. A function that calls itself forever will crash. REX will tell you the program was killed.
