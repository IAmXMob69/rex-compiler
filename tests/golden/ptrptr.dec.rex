// recovered by rex decompile
// REX-built ELF64 only; names are invented

fn main() {
    let t1 = 40;
    let t2 = &t1; // hint: pointer
    let t3 = &t2; // hint: pointer
    print(*(*(t3)));
    *(t2) = 2;
    print(*(*(t3)));
}

