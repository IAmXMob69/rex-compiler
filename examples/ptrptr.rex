fn main() {
    let x = 40;
    let p = &x;
    let q = &p;
    print(**q);
    *p = 2;
    print(**q);
}
