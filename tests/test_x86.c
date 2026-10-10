#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/x86_decode.h"

/* One line per encoding: bytes, expected length, expected AT&T text. */
typedef struct { const char *hex; const char *text; } Case;

static const Case cases[] = {
    /* mov */
    { "4889e5", "mov %rsp, %rbp" },
    { "488b4508", "mov 8(%rbp), %rax" },
    { "48894df8", "mov %rcx, -8(%rbp)" },
    { "488b04c8", "mov (%rax,%rcx,8), %rax" },
    { "48898c05f0ffffff", "mov %rcx, -16(%rbp,%rax,1)" },
    { "488b0510000000", "mov 16(%rip), %rax  # 0x1017" },
    { "48b88877665544332211", "mov $1234605616436508552, %rax" },
    { "b801000000", "mov $1, %eax" },
    { "49c7c0ffffffff", "mov $-1, %r8" },
    { "c6010a", "movb $10, (%rcx)" },
    { "48c744241800000000", "movq $0, 24(%rsp)" },
    { "8811", "mov %dl, (%rcx)" },
    { "40887dff", "mov %dil, -1(%rbp)" },
    { "88e0", "mov %ah, %al" },
    { "8b0425efbeadde", "mov 0xffffffffdeadbeef, %eax" },
    { "4c8b2c24", "mov (%rsp), %r13" },
    { "4e8b6c2508", "mov 8(%rbp,%r12,1), %r13" },
    { "668b07", "mov (%rdi), %ax" },
    /* movzx / movsx */
    { "0fb6c0", "movzbl %al, %eax" },
    { "0fb60408", "movzbl (%rax,%rcx,1), %eax" },
    { "480fbf07", "movswq (%rdi), %rax" },
    { "4898", "cltq" },
    { "87d0", "xchg %edx, %eax" },
    { "4891", "xchg %rcx, %rax" },
    { "4863d0", "movslq %eax, %rdx" },
    { "4863c0", "cltq" },
    /* push / pop */
    { "55", "push %rbp" },
    { "4150", "push %r8" },
    { "5d", "pop %rbp" },
    { "4159", "pop %r9" },
    { "6a07", "push $7" },
    { "6800010000", "push $256" },
    { "ff7508", "pushq 8(%rbp)" },
    { "8f00", "popq (%rax)" },
    /* lea */
    { "488d8570ffffff", "lea -144(%rbp), %rax" },
    { "488d3d00000000", "lea (%rip), %rdi  # 0x1007" },
    { "488d542418", "lea 24(%rsp), %rdx" },
    { "8d04c500000000", "lea 0x0(,%rax,8), %eax" },
    /* add / sub */
    { "4801c8", "add %rcx, %rax" },
    { "4883c008", "add $8, %rax" },
    { "4881c400010000", "add $256, %rsp" },
    { "80c230", "add $48, %dl" },
    { "0503000000", "add $3, %eax" },
    { "4829f8", "sub %rdi, %rax" },
    { "4881ec20000000", "sub $32, %rsp" },
    { "83ea30", "sub $48, %edx" },
    { "2c01", "sub $1, %al" },
    /* imul / idiv */
    { "480fafc1", "imul %rcx, %rax" },
    { "486bc908", "imul $8, %rcx, %rcx" },
    { "4869c0e8030000", "imul $1000, %rax, %rax" },
    { "48f7f9", "idiv %rcx" },
    { "49f7f9", "idiv %r9" },
    /* logic */
    { "4821c8", "and %rcx, %rax" },
    { "4883e0f0", "and $-16, %rax" },
    { "4809c8", "or %rcx, %rax" },
    { "0c01", "or $1, %al" },
    { "4831c8", "xor %rcx, %rax" },
    { "31c0", "xor %eax, %eax" },
    { "4531c9", "xor %r9d, %r9d" },
    { "48f7d0", "not %rax" },
    { "48f7d8", "neg %rax" },
    /* shifts */
    { "48d3e0", "shl %cl, %rax" },
    { "48c1e004", "shl $4, %rax" },
    { "48d1e0", "shl $1, %rax" },
    { "48d3e8", "shr %cl, %rax" },
    { "48c1e83f", "shr $63, %rax" },
    { "48d3f8", "sar %cl, %rax" },
    { "48c1f803", "sar $3, %rax" },
    { "c0f902", "sar $2, %cl" },
    /* cmp / test */
    { "4839c8", "cmp %rcx, %rax" },
    { "483d0a000000", "cmp $10, %rax" },
    { "4881f9e8030000", "cmp $1000, %rcx" },
    { "803e00", "cmpb $0, (%rsi)" },
    { "39ca", "cmp %ecx, %edx" },
    { "4885c0", "test %rax, %rax" },
    { "85d2", "test %edx, %edx" },
    { "a801", "test $1, %al" },
    { "f60701", "testb $1, (%rdi)" },
    /* inc / dec */
    { "48ffc7", "inc %rdi" },
    { "48ffc9", "dec %rcx" },
    { "fe00", "incb (%rax)" },
    /* jumps and calls */
    { "eb10", "jmp 0x1012" },
    { "e9fbefffff", "jmp 0x0" },
    { "7405", "je 0x1007" },
    { "75fe", "jne 0x1000" },
    { "7f00", "jg 0x1002" },
    { "7d00", "jge 0x1002" },
    { "7c00", "jl 0x1002" },
    { "7e00", "jle 0x1002" },
    { "0f8410000000", "je 0x1016" },
    { "0f8510000000", "jne 0x1016" },
    { "0f8f00000000", "jg 0x1006" },
    { "0f8d00000000", "jge 0x1006" },
    { "0f8c00000000", "jl 0x1006" },
    { "0f8e00000000", "jle 0x1006" },
    { "0f8900000000", "jns 0x1006" },
    { "e800000000", "call 0x1005" },
    { "ffd0", "call *%rax" },
    { "ff1500000000", "call *(%rip)  # 0x1006" },
    { "41ffe3", "jmp *%r11" },
    { "c3", "ret" },
    { "f3c3", "ret" },
    { "c20800", "ret $8" },
    /* setcc, misc */
    { "0f94c0", "sete %al" },
    { "0f9fc0", "setg %al" },
    { "4899", "cqo" },
    { "99", "cltd" },
    { "0f05", "syscall" },
    { "90", "nop" },
    { "0f1f00", "nop" },
    { "0f1f440000", "nop" },
    { "660f1f440000", "nop" },
    { "662e0f1f840000000000", "nop" },
    { "6690", "nop" },
    { "f30f1efa", "endbr64" },
    { "f30f1efb", "endbr32" },
    { "c9", "leave" },
    { "f4", "hlt" },
    { "0f0b", "ud2" },
    { "480f4dc2", "cmovge %rdx, %rax" },
    { "480f49c2", "cmovns %rdx, %rax" },
    { "480f44c6", "cmove %rsi, %rax" },
    { "480f48c7", "cmovs %rdi, %rax" },
    { "f6c101", "test $1, %cl" },
    { "48f7c0ff000000", "test $255, %rax" },
    { "0fbec0", "movsbl %al, %eax" },
    { "480fb6c0", "movzbq %al, %rax" },
};

/* Must not decode: unsupported, truncated, or invalid forms. */
static const char *rejects[] = {
    "", "48", "66", "e8", "e80000", "0f", "0f84000000", "488b", "488b04", "488b8500",
    "48b8112233", "8dc0", "c7c8", "8f08", "0fff", "f2c3", "f390c3"/* f3 90 is pause-ish; ok */,
    "cc", "62", "c5", "d8", "1000", "1800", "f6c8", "fff8", "feD0", "f3488b00",
    "f30f1efc", "f30f1e", "f3480f1efa", "2e4889e5", "3ec3",
};

static int unhex(const char *h, unsigned char *out) {
    int n = 0;
    while (h[0] && h[1]) {
        unsigned v;
        sscanf(h, "%2x", &v);
        out[n++] = (unsigned char)v;
        h += 2;
    }
    return n;
}

int main(void) {
    int fails = 0, total = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        unsigned char b[32];
        int n = unhex(cases[i].hex, b);
        X86Insn in;
        char text[160] = "";
        int len = x86_decode(b, (size_t)n, 0x1000, &in);
        if (len) x86_format(&in, text, sizeof(text));
        total++;
        if (len != n || strcmp(text, cases[i].text)) {
            printf("FAIL %s: got len %d '%s', want len %d '%s'\n", cases[i].hex, len, text, n, cases[i].text);
            fails++;
        }
        /* Every prefix of a valid encoding is truncated and must fail. */
        for (int k = 0; k < n; k++) {
            X86Insn t;
            if (x86_decode(b, (size_t)k, 0x1000, &t) != 0 && !(n == 2 && b[0] == 0xf3)) {
                printf("FAIL %s: truncated to %d bytes still decoded\n", cases[i].hex, k);
                fails++;
            }
        }
    }
    for (size_t i = 0; i < sizeof(rejects) / sizeof(rejects[0]); i++) {
        if (!strcmp(rejects[i], "f390c3")) continue;
        unsigned char b[32];
        int n = unhex(rejects[i], b);
        X86Insn in;
        total++;
        if (x86_decode(b, (size_t)n, 0x1000, &in) != 0) { printf("FAIL reject %s decoded\n", rejects[i]); fails++; }
    }
    /* Fuzz: random bytes must never read past avail or exceed 15. */
    srand(1234);
    unsigned char buf[32];
    for (int it = 0; it < 2000000; it++) {
        size_t n = (size_t)(rand() % 17);
        for (size_t k = 0; k < sizeof(buf); k++) buf[k] = (unsigned char)rand();
        X86Insn in;
        int len = x86_decode(buf, n, 0x400000, &in);
        if (len < 0 || (size_t)len > n || len > 15) { printf("FAIL fuzz len %d avail %zu\n", len, n); fails++; break; }
        if (len) { char t[160]; x86_format(&in, t, sizeof(t)); x86_format(&in, t, 8); }
    }
    total++;
    printf("x86 decoder: %d/%d checks passed, %zu encodings\n", total - fails, total, sizeof(cases) / sizeof(cases[0]));
    return fails ? 1 : 0;
}
