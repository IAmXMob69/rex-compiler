fn boom() {
    print(999);
    return 1;
}

fn main() {
    print(1 && 1);
    print(1 && 0);
    print(0 || 1);
    print(0 || 0);
    print(!0);
    print(!1);
    if (0 && boom()) {
        print(1);
    } else {
        print(0);
    }
    if (1 || boom()) {
        print(2);
    }
}
