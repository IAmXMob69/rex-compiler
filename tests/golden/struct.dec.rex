// recovered by rex decompile
// REX-built ELF64 only; names are invented

struct S1 { f0; f8; } // hint: recovered struct

fn main() {
    let t1 = S1; // hint: struct, fields named by byte offset
    t1.f0 = 40;
    t1.f8 = 2;
    print(t1.f0 + t1.f8);
}

