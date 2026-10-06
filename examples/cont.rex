fn main() {
    let n = 0;
    for let i = 0; i < 5; i = i + 1 {
        if (i == 2) {
            continue;
        }
        n = n + 1;
    }
    print(n);
}
