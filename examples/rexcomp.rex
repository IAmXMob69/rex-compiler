let pos = 0;
let lab = 2;
let nloc = 0;
let sid = 1;
let isstr = 0;
let src = 0;
let names = 0;
let lens = 0;
let offs = 0;
let firsts = 0;

fn skip() {
    let go = 1;
    while (go == 1) {
        go = 0;
        if (src[pos] == 32) {
            pos = pos + 1;
            go = 1;
        }
        if (src[pos] == 10) {
            pos = pos + 1;
            go = 1;
        }
    }
}

fn namelen() {
    let n = 0;
    let i = pos;
    let go = 1;
    while (go == 1) {
        go = 0;
        if (src[i] >= 97) {
            if (src[i] <= 122) {
                n = n + 1;
                i = i + 1;
                go = 1;
            }
        }
    }
    return n;
}

fn addloc() {
    let n = namelen();
    if (n == 0) { return 0; }
    let slot = nloc + 1;
    slot = slot * 8;
    names[nloc] = pos;
    lens[nloc] = n;
    firsts[nloc] = src[pos];
    offs[nloc] = slot;
    nloc = nloc + 1;
    pos = pos + n;
    return slot;
}

fn find() {
    let start = pos;
    let n = namelen();
    let ch = src[start];
    let i = 0;
    while (i < nloc) {
        if (i < 40) {
            if (lens[i] == n) {
                if (firsts[i] == ch) { return i; }
            }
        }
        i = i + 1;
    }
    return 0 - 1;
}

fn primary() {
    skip();
    isstr = 0;
    if (src[pos] >= 48) {
        if (src[pos] <= 57) {
            let n = 0;
            let go = 1;
            while (go == 1) {
                go = 0;
                if (src[pos] >= 48) {
                    if (src[pos] <= 57) {
                        let d = src[pos] - 48;
                        n = n * 10;
                        n = n + d;
                        pos = pos + 1;
                        go = 1;
                    }
                }
            }
            put("    mov $");
            putn(n);
            print(", %rax");
            return 0;
        }
    }
    if (src[pos] == 34) {
        isstr = 1;
        let id = sid;
        sid = sid + 1;
        put("    jmp .Ls");
        putn(id);
        print("x");
        put(".Ls");
        putn(id);
        print(":");
        put(".asciz ");
        putc(34);
        pos = pos + 1;
        while (src[pos] != 34) {
            putc(src[pos]);
            pos = pos + 1;
        }
        putc(34);
        print("");
        pos = pos + 1;
        put(".Ls");
        putn(id);
        print("x:");
        put("    lea .Ls");
        putn(id);
        print("(%rip), %rax");
        return 0;
    }
    if (src[pos] == 40) {
        pos = pos + 1;
        expr();
        if (src[pos] == 41) { pos = pos + 1; }
        return 0;
    }
    let slot = find();
    let nlen = namelen();
    let start = pos;
    pos = pos + nlen;
    skip();
    if (src[pos] == 40) {
        if (nlen == 4) {
            if (src[start] == 108) {
                if (src[start + 1] == 111) {
                    pos = pos + 1;
                    expr();
                    print("    mov %rax, %rdi");
                    print("    call rex_load");
                    if (src[pos] == 41) { pos = pos + 1; }
                    return 0;
                }
            }
        }
        if (nlen == 5) {
            if (src[start] == 97) {
                pos = pos + 1;
                expr();
                print("    mov %rax, %rdi");
                print("    call rex_alloc");
                if (src[pos] == 41) { pos = pos + 1; }
                return 0;
            }
        }
        pos = pos + 1;
        if (src[pos] == 41) { pos = pos + 1; }
        put("    call rexfn_");
        let j = 0;
        while (j < nlen) {
            putc(src[start + j]);
            j = j + 1;
        }
        print("");
        return 0;
    }
    if (src[pos] == 91) {
        pos = pos + 1;
        expr();
        print("    mov %rax, %rcx");
        put("    mov rex_g_");
        let j2 = 0;
        while (j2 < nlen) {
            putc(src[start + j2]);
            j2 = j2 + 1;
        }
        print("(%rip), %rax");
        if (src[start] == 115) { print("    movzbl (%rax,%rcx), %eax"); }
        if (src[start] != 115) { print("    mov (%rax,%rcx,8), %rax"); }
        if (src[pos] == 93) { pos = pos + 1; }
        return 0;
    }
    if (slot < 0) {
        put("    mov rex_g_");
        let j3 = 0;
        while (j3 < nlen) {
            putc(src[start + j3]);
            j3 = j3 + 1;
        }
        print("(%rip), %rax");
        return 0;
    }
    put("    mov -");
    putn(offs[slot]);
    print("(%rbp), %rax");
    return 0;
}

fn expr() {
    primary();
    skip();
    if (src[pos] == 43) {
        pos = pos + 1;
        print("    push %rax");
        primary();
        print("    mov %rax, %rcx");
        print("    pop %rax");
        print("    add %rcx, %rax");
        return 0;
    }
    if (src[pos] == 45) {
        pos = pos + 1;
        print("    push %rax");
        primary();
        print("    mov %rax, %rcx");
        print("    pop %rax");
        print("    sub %rcx, %rax");
        return 0;
    }
    if (src[pos] == 42) {
        pos = pos + 1;
        print("    push %rax");
        primary();
        print("    mov %rax, %rcx");
        print("    pop %rax");
        print("    imul %rcx, %rax");
        return 0;
    }
    if (src[pos] == 61) {
        pos = pos + 1;
        if (src[pos] == 61) { pos = pos + 1; }
        print("    push %rax");
        primary();
        print("    mov %rax, %rcx");
        print("    pop %rax");
        print("    cmp %rcx, %rax");
        print("    sete %al");
        print("    movzx %al, %eax");
        return 0;
    }
    if (src[pos] == 60) {
        pos = pos + 1;
        print("    push %rax");
        primary();
        print("    mov %rax, %rcx");
        print("    pop %rax");
        print("    cmp %rcx, %rax");
        print("    setl %al");
        print("    movzx %al, %eax");
        return 0;
    }
    if (src[pos] == 62) {
        pos = pos + 1;
        print("    push %rax");
        primary();
        print("    mov %rax, %rcx");
        print("    pop %rax");
        print("    cmp %rcx, %rax");
        print("    setg %al");
        print("    movzx %al, %eax");
        return 0;
    }
    return 0;
}

fn stmt() {
    skip();
    if (src[pos] == 0) { return 0; }
    if (src[pos] == 125) { return 0; }
    if (src[pos] == 108) {
        if (src[pos + 1] == 101) {
            pos = pos + 4;
            let off = addloc();
            skip();
            if (src[pos] == 61) { pos = pos + 1; }
            expr();
            put("    mov %rax, -");
            putn(off);
            print("(%rbp)");
            if (src[pos] == 59) { pos = pos + 1; }
            return 0;
        }
    }
    if (src[pos] == 105) {
        if (src[pos + 1] == 102) {
            pos = pos + 2;
            let el = lab;
            let en = lab + 1;
            lab = lab + 2;
            expr();
            print("    cmp $0, %rax");
            put("    je .L");
            putn(el);
            print("");
            skip();
            if (src[pos] == 123) { pos = pos + 1; }
            while (src[pos] != 125) {
                let old = pos;
                stmt();
                if (pos == old) { pos = pos + 1; }
                skip();
            }
            if (src[pos] == 125) { pos = pos + 1; }
            put("    jmp .L");
            putn(en);
            print("");
            put(".L");
            putn(el);
            print(":");
            put(".L");
            putn(en);
            print(":");
            return 0;
        }
    }
    if (src[pos] == 119) {
        if (src[pos + 1] == 104) {
            pos = pos + 5;
            let st = lab;
            let en2 = lab + 1;
            lab = lab + 2;
            put(".L");
            putn(st);
            print(":");
            expr();
            print("    cmp $0, %rax");
            put("    je .L");
            putn(en2);
            print("");
            skip();
            if (src[pos] == 123) { pos = pos + 1; }
            while (src[pos] != 125) {
                let old2 = pos;
                stmt();
                if (pos == old2) { pos = pos + 1; }
                skip();
            }
            if (src[pos] == 125) { pos = pos + 1; }
            put("    jmp .L");
            putn(st);
            print("");
            put(".L");
            putn(en2);
            print(":");
            return 0;
        }
    }
    if (src[pos] == 114) {
        if (src[pos + 1] == 101) {
            pos = pos + 6;
            expr();
            print("    jmp .Lret");
            if (src[pos] == 59) { pos = pos + 1; }
            return 0;
        }
    }
    if (src[pos] == 112) {
        if (src[pos + 1] == 114) {
            pos = pos + 5;
            if (src[pos] == 40) { pos = pos + 1; }
            expr();
            print("    mov %rax, %rdi");
            if (isstr == 1) { print("    call rex_print_str"); }
            if (isstr == 0) { print("    call rex_print_int"); }
            if (src[pos] == 41) { pos = pos + 1; }
            if (src[pos] == 59) { pos = pos + 1; }
            return 0;
        }
        if (src[pos + 1] == 117) {
            if (src[pos + 3] == 40) {
                pos = pos + 3;
                if (src[pos] == 40) { pos = pos + 1; }
                expr();
                print("    mov %rax, %rdi");
                print("    call rex_put_str");
                if (src[pos] == 41) { pos = pos + 1; }
                if (src[pos] == 59) { pos = pos + 1; }
                return 0;
            }
            if (src[pos + 3] == 110) {
                pos = pos + 4;
                if (src[pos] == 40) { pos = pos + 1; }
                expr();
                print("    mov %rax, %rdi");
                print("    call rex_put_int");
                if (src[pos] == 41) { pos = pos + 1; }
                if (src[pos] == 59) { pos = pos + 1; }
                return 0;
            }
            if (src[pos + 3] == 99) {
                pos = pos + 4;
                if (src[pos] == 40) { pos = pos + 1; }
                expr();
                print("    mov %rax, %rdi");
                print("    call rex_putc");
                if (src[pos] == 41) { pos = pos + 1; }
                if (src[pos] == 59) { pos = pos + 1; }
                return 0;
            }
        }
    }
    let slot2 = find();
    let n2 = namelen();
    let start2 = pos;
    pos = pos + n2;
    skip();
    if (src[pos] == 61) { pos = pos + 1; }
    expr();
    if (slot2 < 0) {
        put("    mov %rax, rex_g_");
        let j4 = 0;
        while (j4 < n2) {
            putc(src[start2 + j4]);
            j4 = j4 + 1;
        }
        print("(%rip)");
    }
    if (slot2 >= 0) {
        put("    mov %rax, -");
        putn(offs[slot2]);
        print("(%rbp)");
    }
    if (src[pos] == 59) { pos = pos + 1; }
    return 0;
}

fn main() {
    src = load("in.rex");
    names = alloc(256);
    lens = alloc(256);
    offs = alloc(256);
    firsts = alloc(256);
    print("    .text");
    skip();
    while (src[pos] != 0) {
        if (src[pos] == 108) {
            pos = pos + 3;
            skip();
            pos = pos + namelen();
            while (src[pos] != 59) { pos = pos + 1; }
            pos = pos + 1;
        }
        if (src[pos] == 102) {
            pos = pos + 2;
            skip();
            let ns = pos;
            let nn = namelen();
            if (src[ns] == 109) {
                print(".globl main");
                print("main:");
            }
            if (src[ns] != 109) {
                put("rexfn_");
                let j = 0;
                while (j < nn) {
                    putc(src[ns + j]);
                    j = j + 1;
                }
                print(":");
            }
            print("    push %rbp");
            print("    mov %rsp, %rbp");
            print("    sub $256, %rsp");
            nloc = 0;
            while (src[pos] != 123) { pos = pos + 1; }
            pos = pos + 1;
            skip();
            while (src[pos] != 125) {
                if (src[pos] == 0) { pos = pos + 1; }
                let old3 = pos;
                stmt();
                if (pos == old3) { pos = pos + 1; }
                skip();
            }
            pos = pos + 1;
            print(".Lret:");
            print("    mov %rbp, %rsp");
            print("    pop %rbp");
            print("    ret");
        }
        skip();
        if (src[pos] != 102) {
            if (src[pos] != 108) {
                if (src[pos] != 0) { pos = pos + 1; }
            }
        }
    }
}
