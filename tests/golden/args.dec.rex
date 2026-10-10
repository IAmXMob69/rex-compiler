// recovered by rex decompile
// REX-built ELF64 only; names are invented

fn f2(a, b) {
    return a + b;
}

fn f4(a) {
    if (a <= 1) {
        return 1;
    } else {
        return a * f4(a - 1);
    }
}

fn main() {
    print(f2(40, 2));
    print(f4(5));
}

