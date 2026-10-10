// recovered by rex decompile
// REX-built ELF64 only; names are invented

fn main() {
    let t1 = 1;
    t1 = t1 + 40;
    t1 = t1 - 1;
    t1 = t1 * 2;
    print(t1);
    let t2 = 0;
    do {
        t2 = t2 + 1;
        if (t2 == 2) {
            continue;
        }
        if (t2 == 4) {
            break;
        }
    } while (t2 < 9);
    print(t2);
}

