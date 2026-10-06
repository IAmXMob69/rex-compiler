# REX

REX is a small compiler. It turns a `.rex` file into a Linux program.

It writes the program itself. It does not call gcc. It does not call an assembler. The finished file is an ELF that talks to the kernel directly.

That is the point. chibicc, 8cc, and the Toomey tutorial stop at assembly and hand the rest to gcc. c4 interprets. TCC is a real C compiler and it is bigger. REX is not a C compiler. It is a finished compiler for a small language, in two files.

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

`for` and `while` loop. `break` leaves the loop.

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

You can take the address of a number, write through it, and ask the kernel for a heap block. A struct is a fixed group of numbers.

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

## Files

- `src/rex.c` is the compiler
- `src/elf.c` is the assembler and the ELF writer
- `src/rexrt.c` is the old helper. The ELF path does not use it
- `examples/` has test programs
- `share/` has the XFCE launcher and the Mousepad color file

## Limits

No pointer arithmetic. A struct stays in the function that created it. `alloc` memory stays until `free`. It only makes x86-64 Linux programs. A function that calls itself forever will crash. REX will tell you the program was killed. This is not a C compiler.
