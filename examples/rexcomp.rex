let pos = 0;

fn ch(s) {
    return s[pos];
}

fn skip(s) {
    while (ch(s) == 32) { pos = pos + 1; }
    while (ch(s) == 10) { pos = pos + 1; }
}

fn number(s) {
    let n = 0;
    skip(s);
    while (ch(s) >= 48) {
        if (ch(s) <= 57) {
            n = n * 10 + (ch(s) - 48);
            pos = pos + 1;
        }
    }
    return n;
}

fn expr(s) {
    let n = number(s);
    skip(s);
    if (ch(s) == 43) {
        pos = pos + 1;
        let m = number(s);
        put("    mov $");
        putn(n);
        print(", %rax");
        put("    push %rax");
        print("");
        put("    mov $");
        putn(m);
        print(", %rcx");
        put("    pop %rax");
        print("");
        put("    add %rcx, %rax");
        print("");
        return 0;
    }
    put("    mov $");
    putn(n);
    print(", %rax");
    return 0;
}

fn main() {
    let s = load("examples/stage.rex");
    print("    .text");
    print(".globl main");
    print("main:");
    print("    push %rbp");
    print("    mov %rsp, %rbp");
    while (ch(s) != 112) { pos = pos + 1; }
    while (ch(s) != 40) { pos = pos + 1; }
    pos = pos + 1;
    expr(s);
    print("    mov %rax, %rdi");
    print("    call rex_print_int");
    print("    xor %eax, %eax");
    print("    mov %rbp, %rsp");
    print("    pop %rbp");
    print("    ret");
}
