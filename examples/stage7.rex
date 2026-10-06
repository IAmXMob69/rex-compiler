fn add(a, b, c, d, e, f) {
    let s = a + b;
    let t = s + c;
    let u = t + d;
    let v = u + e;
    return v + f;
}

fn main() {
    print(add(5, 5, 10, 10, 10, 2));
}
