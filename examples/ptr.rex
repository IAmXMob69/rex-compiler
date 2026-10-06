fn main() {
    let x = 40;
    let p = &x;
    print(*p);
    *p = 2;
    print(x);
}
