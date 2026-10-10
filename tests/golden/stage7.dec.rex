// recovered by rex decompile
// REX-built ELF64 only; names are invented

fn f2(a, b, c, d, e, f) {
    let t7 = a + b;
    let t8 = t7 + c;
    let t9 = t8 + d;
    let t10 = t9 + e;
    return t10 + f;
}

fn main() {
    print(f2(5, 5, 10, 10, 10, 2));
}

