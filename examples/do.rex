fn main() {
    let n = 1;
    n += 40;
    n -= 1;
    n *= 2;
    print(n);
    let k = 0;
    do {
        k += 1;
        if (k == 2) {
            continue;
        }
        if (k == 4) {
            break;
        }
    } while (k < 9);
    print(k);
}
