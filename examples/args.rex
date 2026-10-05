fn add(a, b) {
    return a + b;
}

fn fact(n) {
    if (n <= 1) {
        return 1;
    }
    return n * fact(n - 1);
}

fn main() {
    print(add(40, 2));
    print(fact(5));
}
