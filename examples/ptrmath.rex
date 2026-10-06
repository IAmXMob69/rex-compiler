fn main() {
    let a = alloc(3);
    a[0] = 10;
    a[1] = 20;
    a[2] = 30;
    let p = a;
    p = p + 1;
    print(*p);
    p = p + 1;
    print(*p);
    print((p - a));
    free(a);
}
