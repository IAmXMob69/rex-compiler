fn main() {
    let a = alloc(3);
    a[0] = 40;
    a[1] = 2;
    a[2] = a[0] + a[1];
    print(a[2]);
    print(len(a));
    free(a);
    let s = "REX";
    print(s[0]);
    print(len(s));
}
