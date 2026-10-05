// Sum 1..10. A civilised compiler produces 55.
fn main() {
    let i = 1;
    let s = 0;
    while (i <= 10) {
        s = s + i;
        i = i + 1;
    }
    print(s);
}
