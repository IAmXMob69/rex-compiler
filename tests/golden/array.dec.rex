// recovered by rex decompile
// REX-built ELF64 only; names are invented

fn main() {
    let t1[3]; // hint: array, length from the bounds check
    t1[0] = 40;
    t1[1] = 2;
    t1[2] = t1[0] + t1[1];
    print(t1[2]);
    print(t1[0]);
}

