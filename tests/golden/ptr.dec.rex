// recovered by rex decompile
// REX-built ELF64 only; names are invented

fn main() {
    let t1 = 40;
    let t2 = &t1; // hint: pointer
    print(*(t2));
    *(t2) = 2;
    print(t1);
}

