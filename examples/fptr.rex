fn add(a, b) {
    return a + b;
}

fn sub(a, b) {
    return a - b;
}

fn main() {
    let op = add;
    print(op(40, 2));
    op = sub;
    print(op(40, 2));
}
