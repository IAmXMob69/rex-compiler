// recovered by rex decompile
// REX-built ELF64 only; names are invented

struct S1 { f0; f8; } // hint: recovered struct

fn main() {
    let t1 = S1; // hint: struct, fields named by byte offset
    t1.f0 = 40;
    t1.f8 = 2;
    let t3 = &t1; // hint: pointer to struct
    print(t3->f0 + t3->f8);
    t3->f0 = 7;
    print(t1.f0);
}

