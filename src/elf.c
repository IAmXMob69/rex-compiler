#define _GNU_SOURCE
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* REX's own assembler. Turns the compiler's AT&T lines into one ELF64.
 * No gcc, no as, no libc. The program talks to the kernel directly.
 */

#define MAXB (1 << 20)
#define MAXL 8192

typedef struct { char name[96]; int off; } Lab;
static Lab labels[MAXL];
static int nlabels;
static unsigned char code[MAXB];
static int clen;
typedef struct { int at; char name[96]; } Rel;
static Rel rels[MAXL];
static int nrels;

static void die_elf(const char *m) { fprintf(stderr, "rex: elf: %s\n", m); exit(1); }
static void emitb(unsigned b) { if (clen >= MAXB) die_elf("code too big"); code[clen++] = (unsigned char)b; }
static void emit32(uint32_t v) { emitb(v); emitb(v >> 8); emitb(v >> 16); emitb(v >> 24); }
static void emit64(uint64_t v) { for (int i = 0; i < 8; i++) emitb((v >> (8 * i)) & 255); }

static int lab_find(const char *s) {
    for (int i = 0; i < nlabels; i++) if (!strcmp(labels[i].name, s)) return i;
    return -1;
}
static void lab_def(const char *s) {
    int i = lab_find(s);
    if (i < 0) {
        if (nlabels >= MAXL) die_elf("too many labels");
        i = nlabels++;
        snprintf(labels[i].name, sizeof(labels[i].name), "%s", s);
    }
    labels[i].off = clen;
}
static void rel32(const char *name) {
    if (nrels >= MAXL) die_elf("too many relocs");
    snprintf(rels[nrels].name, sizeof(rels[nrels].name), "%s", name);
    rels[nrels].at = clen;
    nrels++;
    emit32(0);
}

static char *trim(char *s) {
    while (*s == ' ' || *s == '\t') s++;
    char *e = s + strlen(s);
    while (e > s && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' ' || e[-1] == '\t')) *--e = 0;
    return s;
}

static int regn(const char *s) {
    if (!strcmp(s, "%rax") || !strcmp(s, "%eax") || !strcmp(s, "%al")) return 0;
    if (!strcmp(s, "%rcx") || !strcmp(s, "%ecx") || !strcmp(s, "%cl")) return 1;
    if (!strcmp(s, "%rdx") || !strcmp(s, "%edx") || !strcmp(s, "%dl")) return 2;
    if (!strcmp(s, "%rbx")) return 3;
    if (!strcmp(s, "%rsp")) return 4;
    if (!strcmp(s, "%rbp")) return 5;
    if (!strcmp(s, "%rsi")) return 6;
    if (!strcmp(s, "%rdi")) return 7;
    if (!strcmp(s, "%r8")) return 8;
    if (!strcmp(s, "%r9")) return 9;
    if (!strcmp(s, "%r10") || !strcmp(s, "%r10d")) return 10;
    if (!strcmp(s, "%r11")) return 11;
    return -1;
}

static int parse_imm(const char *s, long *out) {
    char *end = NULL;
    if (!strncmp(s, "0x", 2) || !strncmp(s, "0X", 2)) {
        unsigned long long v = strtoull(s, &end, 16);
        if (end == s || *end) return 0;
        *out = (long)v;
        return 1;
    }
    *out = strtol(s, &end, 10);
    return end != s && *end == 0;
}

static void mov_imm_reg(long imm, int rd) {
    if (rd < 8) { emitb(0x48); emitb(0xb8 + rd); }
    else { emitb(0x49); emitb(0xb8 + (rd - 8)); }
    emit64((uint64_t)imm);
}

static void asm_line(char *raw) {
    char *line = trim(raw);
    if (!*line || *line == '#') return;
    if (!strncmp(line, ".text", 5) || !strncmp(line, ".section", 8) || !strncmp(line, ".globl", 6)) return;
    if (!strncmp(line, ".asciz ", 7)) {
        char *q = strchr(line, '"');
        if (!q) die_elf("bad asciz");
        for (char *p = q + 1; *p && *p != '"'; p++) {
            unsigned char ch = (unsigned char)*p;
            if (ch == '\\' && p[1]) {
                p++;
                if (*p == 'n') ch = '\n';
                else if (*p == 't') ch = '\t';
                else if (*p == '0') ch = 0;
                else if (*p >= '0' && *p <= '7') {
                    int v = *p - '0';
                    if (p[1] >= '0' && p[1] <= '7') { p++; v = v * 8 + (*p - '0'); }
                    if (p[1] >= '0' && p[1] <= '7') { p++; v = v * 8 + (*p - '0'); }
                    ch = (unsigned char)v;
                } else ch = (unsigned char)*p;
            }
            emitb(ch);
        }
        emitb(0);
        return;
    }
    if (strchr(line, ':') && !strchr(line, ' ')) {
        char name[96];
        sscanf(line, "%95[^:]", name);
        lab_def(name);
        return;
    }

    long imm = 0;
    char name[96], r1[16], r2[16];

    if (!strcmp(line, "ret")) { emitb(0xc3); return; }
    if (!strcmp(line, "syscall")) { emitb(0x0f); emitb(0x05); return; }
    if (!strcmp(line, "cqo")) { emitb(0x48); emitb(0x99); return; }
    if (!strcmp(line, "neg %rax")) { emitb(0x48); emitb(0xf7); emitb(0xd8); return; }
    if (!strcmp(line, "push %rbp")) { emitb(0x55); return; }
    if (!strcmp(line, "pop %rbp")) { emitb(0x5d); return; }
    if (!strcmp(line, "push %rax")) { emitb(0x50); return; }
    if (!strcmp(line, "pop %rax")) { emitb(0x58); return; }
    if (!strcmp(line, "push %rcx")) { emitb(0x51); return; }
    if (!strcmp(line, "pop %rcx")) { emitb(0x59); return; }
    if (!strcmp(line, "push %rdi")) { emitb(0x57); return; }
    if (!strcmp(line, "pop %rdi")) { emitb(0x5f); return; }
    if (!strcmp(line, "push %rsi")) { emitb(0x56); return; }
    if (!strcmp(line, "pop %rsi")) { emitb(0x5e); return; }
    if (!strcmp(line, "push %rdx")) { emitb(0x52); return; }
    if (!strcmp(line, "pop %rdx")) { emitb(0x5a); return; }
    if (!strcmp(line, "push %r8")) { emitb(0x41); emitb(0x50); return; }
    if (!strcmp(line, "pop %r8")) { emitb(0x41); emitb(0x58); return; }
    if (!strcmp(line, "push %r9")) { emitb(0x41); emitb(0x51); return; }
    if (!strcmp(line, "pop %r9")) { emitb(0x41); emitb(0x59); return; }
    if (!strcmp(line, "mov %rsp, %rbp")) { emitb(0x48); emitb(0x89); emitb(0xe5); return; }
    if (!strcmp(line, "mov %rbp, %rsp")) { emitb(0x48); emitb(0x89); emitb(0xec); return; }
    if (!strcmp(line, "mov %rsp, %rsi")) { emitb(0x48); emitb(0x89); emitb(0xe6); return; }
    if (!strcmp(line, "mov %rax, %rcx")) { emitb(0x48); emitb(0x89); emitb(0xc1); return; }
    if (!strcmp(line, "mov %rax, %rdi")) { emitb(0x48); emitb(0x89); emitb(0xc7); return; }
    if (!strcmp(line, "mov %rdi, %rax")) { emitb(0x48); emitb(0x89); emitb(0xf8); return; }
    if (!strcmp(line, "mov %rax, %rsi")) { emitb(0x48); emitb(0x89); emitb(0xc6); return; }
    if (!strcmp(line, "mov %rdi, %rsi")) { emitb(0x48); emitb(0x89); emitb(0xfe); return; }
    if (!strcmp(line, "mov %rsi, %rdx")) { emitb(0x48); emitb(0x89); emitb(0xf2); return; }
    if (!strcmp(line, "mov %rcx, %rsi")) { emitb(0x48); emitb(0x89); emitb(0xce); return; }
    if (!strcmp(line, "mov %rdx, %rax")) { emitb(0x48); emitb(0x89); emitb(0xd0); return; }
    if (!strcmp(line, "mov %rax, %rdx")) { emitb(0x48); emitb(0x89); emitb(0xc2); return; }
    if (!strcmp(line, "sub %rdi, %rsi")) { emitb(0x48); emitb(0x29); emitb(0xfe); return; }
    if (!strcmp(line, "sub %rcx, %rdx")) { emitb(0x48); emitb(0x29); emitb(0xca); return; }
    if (!strcmp(line, "mov (%rax), %rax")) { emitb(0x48); emitb(0x8b); emitb(0x00); return; }
    if (!strcmp(line, "mov %rcx, (%rax)")) { emitb(0x48); emitb(0x89); emitb(0x08); return; }
    if (!strcmp(line, "mov %rdi, (%rax)")) { emitb(0x48); emitb(0x89); emitb(0x38); return; }
    if (!strcmp(line, "mov -8(%rax), %rdx")) { emitb(0x48); emitb(0x8b); emitb(0x50); emitb(0xf8); return; }
    if (!strcmp(line, "mov -8(%rax), %rax")) { emitb(0x48); emitb(0x8b); emitb(0x40); emitb(0xf8); return; }
    if (!strcmp(line, "mov (%rax,%rcx,8), %rax")) { emitb(0x48); emitb(0x8b); emitb(0x04); emitb(0xc8); return; }
    if (!strcmp(line, "mov %rdx, (%rax,%rcx,8)")) { emitb(0x48); emitb(0x89); emitb(0x14); emitb(0xc8); return; }
    if (!strcmp(line, "movzbl (%rax,%rcx), %eax")) { emitb(0x0f); emitb(0xb6); emitb(0x04); emitb(0x08); return; }
    if (!strcmp(line, "add %rcx, %rax")) { emitb(0x48); emitb(0x01); emitb(0xc8); return; }
    if (!strcmp(line, "add $8, %rax")) { emitb(0x48); emitb(0x83); emitb(0xc0); emitb(0x08); return; }
    if (!strcmp(line, "inc %rdi")) { emitb(0x48); emitb(0xff); emitb(0xc7); return; }
    if (!strcmp(line, "imul $8, %rcx")) { emitb(0x48); emitb(0x6b); emitb(0xc9); emitb(0x08); return; }
    if (!strcmp(line, "sub %rdi, %rax")) { emitb(0x48); emitb(0x29); emitb(0xf8); return; }
    if (!strcmp(line, "xor %r9d, %r9d")) { emitb(0x45); emitb(0x31); emitb(0xc9); return; }
    if (sscanf(line, "lea -%li(%%rbp), %%rax", &imm) == 1 && strstr(line, "%rax")) { emitb(0x48); emitb(0x8d); emitb(0x85); emit32((uint32_t)(-imm)); return; }
    if (!strcmp(line, "sub %rcx, %rax")) { emitb(0x48); emitb(0x29); emitb(0xc8); return; }
    if (!strcmp(line, "add %rdx, %rax")) { emitb(0x48); emitb(0x01); emitb(0xd0); return; }
    if (!strcmp(line, "imul %rcx, %rax")) { emitb(0x48); emitb(0x0f); emitb(0xaf); emitb(0xc1); return; }
    if (!strcmp(line, "idiv %rcx")) { emitb(0x48); emitb(0xf7); emitb(0xf9); return; }
    if (!strcmp(line, "idiv %r9")) { emitb(0x49); emitb(0xf7); emitb(0xf9); return; }
    if (!strcmp(line, "cmp %rcx, %rax")) { emitb(0x48); emitb(0x39); emitb(0xc8); return; }
    if (!strcmp(line, "cmp %rdx, %rax")) { emitb(0x48); emitb(0x39); emitb(0xd0); return; }
    if (!strcmp(line, "test %rax, %rax")) { emitb(0x48); emitb(0x85); emitb(0xc0); return; }
    if (!strcmp(line, "test %rcx, %rcx")) { emitb(0x48); emitb(0x85); emitb(0xc9); return; }
    if (!strcmp(line, "xor %eax, %eax")) { emitb(0x31); emitb(0xc0); return; }
    if (!strcmp(line, "xor %edx, %edx")) { emitb(0x31); emitb(0xd2); return; }
    if (!strcmp(line, "xor %edi, %edi")) { emitb(0x31); emitb(0xff); return; }
    if (!strcmp(line, "xor %esi, %esi")) { emitb(0x31); emitb(0xf6); return; }
    if (!strcmp(line, "xor %ecx, %ecx")) { emitb(0x31); emitb(0xc9); return; }
    if (!strcmp(line, "xor %r10d, %r10d")) { emitb(0x45); emitb(0x31); emitb(0xd2); return; }
    if (!strcmp(line, "inc %rsi")) { emitb(0x48); emitb(0xff); emitb(0xc6); return; }
    if (!strcmp(line, "inc %rdx")) { emitb(0x48); emitb(0xff); emitb(0xc2); return; }
    if (!strcmp(line, "dec %rcx")) { emitb(0x48); emitb(0xff); emitb(0xc9); return; }
    if (!strcmp(line, "cmpb $0, (%rsi)")) { emitb(0x80); emitb(0x3e); emitb(0x00); return; }
    if (!strcmp(line, "cmpb $0, (%rax)")) { emitb(0x80); emitb(0x38); emitb(0x00); return; }
    if (!strcmp(line, "cmp %rdx, %rcx")) { emitb(0x48); emitb(0x39); emitb(0xd1); return; }
    if (!strcmp(line, "inc %rax")) { emitb(0x48); emitb(0xff); emitb(0xc0); return; }
    if (!strcmp(line, "imul $8, %rdi")) { emitb(0x48); emitb(0x6b); emitb(0xff); emitb(0x08); return; }
    if (!strcmp(line, "imul $8, %rsi")) { emitb(0x48); emitb(0x6b); emitb(0xfe); emitb(0x08); return; }
    if (!strcmp(line, "sub $8, %rdi")) { emitb(0x48); emitb(0x83); emitb(0xef); emitb(0x08); return; }
    if (!strcmp(line, "cmpb $45, (%rsi)")) { emitb(0x80); emitb(0x3e); emitb(0x2d); return; }
    if (!strcmp(line, "cmpb $48, (%rsi)")) { emitb(0x80); emitb(0x3e); emitb(0x30); return; }
    if (!strcmp(line, "cmpb $57, (%rsi)")) { emitb(0x80); emitb(0x3e); emitb(0x39); return; }
    if (!strcmp(line, "movb $10, (%rcx)")) { emitb(0xc6); emitb(0x01); emitb(0x0a); return; }
    if (!strcmp(line, "movb $48, (%rcx)")) { emitb(0xc6); emitb(0x01); emitb(0x30); return; }
    if (!strcmp(line, "mov %dl, (%rcx)")) { emitb(0x88); emitb(0x11); return; }
    if (!strcmp(line, "movzbl (%rsi), %edx")) { emitb(0x0f); emitb(0xb6); emitb(0x16); return; }
    if (!strcmp(line, "add $48, %dl")) { emitb(0x80); emitb(0xc2); emitb(0x30); return; }
    if (!strcmp(line, "sub $48, %edx")) { emitb(0x83); emitb(0xea); emitb(0x30); return; }
    if (!strcmp(line, "sete %al")) { emitb(0x0f); emitb(0x94); emitb(0xc0); return; }
    if (!strcmp(line, "setne %al")) { emitb(0x0f); emitb(0x95); emitb(0xc0); return; }
    if (!strcmp(line, "setl %al")) { emitb(0x0f); emitb(0x9c); emitb(0xc0); return; }
    if (!strcmp(line, "setg %al")) { emitb(0x0f); emitb(0x9f); emitb(0xc0); return; }
    if (!strcmp(line, "setle %al")) { emitb(0x0f); emitb(0x9e); emitb(0xc0); return; }
    if (!strcmp(line, "setge %al")) { emitb(0x0f); emitb(0x9d); emitb(0xc0); return; }
    if (!strcmp(line, "movzx %al, %eax")) { emitb(0x0f); emitb(0xb6); emitb(0xc0); return; }
    if (!strcmp(line, "lea -1(%rbp), %rcx")) { emitb(0x48); emitb(0x8d); emitb(0x4d); emitb(0xff); return; }
    if (!strcmp(line, "lea -1(%rbp), %rdx")) { emitb(0x48); emitb(0x8d); emitb(0x55); emitb(0xff); return; }
    if (!strcmp(line, "lea -24(%rbp), %rsi")) { emitb(0x48); emitb(0x8d); emitb(0x75); emitb(0xe8); return; }
    if (!strcmp(line, "lea 24(%rsp), %rdx")) { emitb(0x48); emitb(0x8d); emitb(0x54); emitb(0x24); emitb(0x18); return; }
    if (!strcmp(line, "mov %rax, (%rsp)")) { emitb(0x48); emitb(0x89); emitb(0x04); emitb(0x24); return; }
    if (!strcmp(line, "mov %rax, 8(%rsp)")) { emitb(0x48); emitb(0x89); emitb(0x44); emitb(0x24); emitb(0x08); return; }
    if (!strcmp(line, "mov %rdi, 16(%rsp)")) { emitb(0x48); emitb(0x89); emitb(0x7c); emitb(0x24); emitb(0x10); return; }
    if (!strcmp(line, "movq $0, 24(%rsp)")) { emitb(0x48); emitb(0xc7); emitb(0x44); emitb(0x24); emitb(0x18); emit32(0); return; }

    if (sscanf(line, "mov $%95[^,], %%%15s", name, r1) == 2) {
        char immbuf[96];
        snprintf(immbuf, sizeof(immbuf), "%s", name);
        char regbuf[32];
        snprintf(regbuf, sizeof(regbuf), "%%%s", r1);
        int rd = regn(regbuf);
        if (rd >= 0 && parse_imm(immbuf, &imm)) { mov_imm_reg(imm, rd); return; }
    }
    if (sscanf(line, "cmp $%95[^,], %%%15s", name, r1) == 2 && parse_imm(name, &imm)) {
        char regbuf[32];
        snprintf(regbuf, sizeof(regbuf), "%%%s", r1);
        int rd = regn(regbuf);
        if (rd == 0) { emitb(0x48); emitb(0x3d); emit32((uint32_t)imm); return; }
        if (rd >= 0 && rd < 8) { emitb(0x48); emitb(0x81); emitb(0xf8 + rd); emit32((uint32_t)imm); return; }
    }
    if (sscanf(line, "sub $%li, %%rsp", &imm) == 1) { emitb(0x48); emitb(0x81); emitb(0xec); emit32((uint32_t)imm); return; }
    if (sscanf(line, "add $%li, %%rsp", &imm) == 1) { emitb(0x48); emitb(0x81); emitb(0xc4); emit32((uint32_t)imm); return; }
    if (sscanf(line, "imul $%li, %%rax", &imm) == 1) { emitb(0x48); emitb(0x6b); emitb(0xc0); emitb((unsigned)imm & 255); return; }
    if (sscanf(line, "mov %%rdi, -%li(%%rbp)", &imm) == 1) { emitb(0x48); emitb(0x89); emitb(0xbd); emit32((uint32_t)(-imm)); return; }
    if (sscanf(line, "mov %%rsi, -%li(%%rbp)", &imm) == 1) { emitb(0x48); emitb(0x89); emitb(0xb5); emit32((uint32_t)(-imm)); return; }
    if (sscanf(line, "mov %%rdx, -%li(%%rbp)", &imm) == 1) { emitb(0x48); emitb(0x89); emitb(0x95); emit32((uint32_t)(-imm)); return; }
    if (sscanf(line, "mov %%rcx, -%li(%%rbp, %%rax)", &imm) == 1 && strstr(line, "%rbp") && strstr(line, "%rax)")) { emitb(0x48); emitb(0x89); emitb(0x8c); emitb(0x05); emit32((uint32_t)(-imm)); return; }
    if (sscanf(line, "mov -%li(%%rbp, %%rax), %%rax", &imm) == 1 && strstr(line, "%rbp") && strstr(line, "%rax)")) { emitb(0x48); emitb(0x8b); emitb(0x84); emitb(0x05); emit32((uint32_t)(-imm)); return; }
    if (sscanf(line, "mov %%rcx, -%li(%%rbp)", &imm) == 1) { emitb(0x48); emitb(0x89); emitb(0x8d); emit32((uint32_t)(-imm)); return; }
    if (sscanf(line, "mov %%r8, -%li(%%rbp)", &imm) == 1) { emitb(0x4c); emitb(0x89); emitb(0x85); emit32((uint32_t)(-imm)); return; }
    if (sscanf(line, "mov %%r9, -%li(%%rbp)", &imm) == 1) { emitb(0x4c); emitb(0x89); emitb(0x8d); emit32((uint32_t)(-imm)); return; }
    if (sscanf(line, "mov %%rax, -%li(%%rbp)", &imm) == 1 && !strstr(line, "%rax)")) { emitb(0x48); emitb(0x89); emitb(0x85); emit32((uint32_t)(-imm)); return; }
    if (sscanf(line, "mov -%li(%%rbp), %%rdi", &imm) == 1 && strstr(line, ", %rdi")) { emitb(0x48); emitb(0x8b); emitb(0xbd); emit32((uint32_t)(-imm)); return; }
    if (sscanf(line, "mov -%li(%%rbp), %%rax", &imm) == 1 && strstr(line, ", %rax") && !strstr(line, "%rax)")) { emitb(0x48); emitb(0x8b); emitb(0x85); emit32((uint32_t)(-imm)); return; }
    if (sscanf(line, "movq $0, -%li(%%rbp)", &imm) == 1) { emitb(0x48); emitb(0xc7); emitb(0x85); emit32((uint32_t)(-imm)); emit32(0); return; }
    /* disp32 SIB so a 64-slot frame still indexes. */
    if (sscanf(line, "lea %95[^(](%%rip), %%%15s", name, r1) == 2) {
        char regbuf[32];
        snprintf(regbuf, sizeof(regbuf), "%%%s", r1);
        char expect[160];
        snprintf(expect, sizeof(expect), "lea %s(%%rip), %s", name, regbuf);
        if (!strcmp(line, expect)) {
            if (!strcmp(regbuf, "%rdi")) { emitb(0x48); emitb(0x8d); emitb(0x3d); rel32(name); return; }
            if (!strcmp(regbuf, "%rsi")) { emitb(0x48); emitb(0x8d); emitb(0x35); rel32(name); return; }
            if (!strcmp(regbuf, "%rax")) { emitb(0x48); emitb(0x8d); emitb(0x05); rel32(name); return; }
        }
    }
    if (sscanf(line, "call %95s", name) == 1 && !strchr(name, ' ')) { emitb(0xe8); rel32(name); return; }
    if (sscanf(line, "jmp %95s", name) == 1) { emitb(0xe9); rel32(name); return; }
    if (sscanf(line, "je %95s", name) == 1) { emitb(0x0f); emitb(0x84); rel32(name); return; }
    if (sscanf(line, "jne %95s", name) == 1 || sscanf(line, "jnz %95s", name) == 1) { emitb(0x0f); emitb(0x85); rel32(name); return; }
    if (sscanf(line, "jl %95s", name) == 1) { emitb(0x0f); emitb(0x8c); rel32(name); return; }
    if (sscanf(line, "jg %95s", name) == 1) { emitb(0x0f); emitb(0x8f); rel32(name); return; }
    if (sscanf(line, "jns %95s", name) == 1) { emitb(0x0f); emitb(0x89); rel32(name); return; }
    (void)r2;
    fprintf(stderr, "rex: elf: unhandled: %s\n", line);
    exit(1);
}

/* Runtime lives in the same load segment. Syscalls only. */
static const char *runtime =
    "rex_print_str:\n"
    "push %rbp\nmov %rsp, %rbp\nmov %rdi, %rsi\n"
    "rex_ps_len:\ncmpb $0, (%rsi)\nje rex_ps_go\ninc %rsi\njmp rex_ps_len\n"
    "rex_ps_go:\nsub %rdi, %rsi\nmov %rsi, %rdx\nmov %rdi, %rsi\nmov $1, %rax\nmov $1, %rdi\nsyscall\n"
    "mov $1, %rax\nmov $1, %rdi\nlea rex_nl(%rip), %rsi\nmov $1, %rdx\nsyscall\n"
    "pop %rbp\nret\n"
    "rex_print_int:\n"
    "push %rbp\nmov %rsp, %rbp\nsub $32, %rsp\nmov %rdi, %rax\n"
    "mov $0x8000000000000000, %rdx\ncmp %rdx, %rax\nje rex_pi_min\n"
    "test %rax, %rax\njns rex_pi_pos\nneg %rax\npush %rax\n"
    "mov $1, %rax\nmov $1, %rdi\nlea rex_minus(%rip), %rsi\nmov $1, %rdx\nsyscall\npop %rax\n"
    "rex_pi_pos:\nlea -1(%rbp), %rcx\nmovb $10, (%rcx)\n"
    "test %rax, %rax\njnz rex_pi_loop\ndec %rcx\nmovb $48, (%rcx)\njmp rex_pi_out\n"
    "rex_pi_loop:\ndec %rcx\nxor %edx, %edx\nmov $10, %r9\nidiv %r9\nadd $48, %dl\nmov %dl, (%rcx)\ntest %rax, %rax\njnz rex_pi_loop\n"
    "rex_pi_out:\nlea -1(%rbp), %rdx\nsub %rcx, %rdx\ninc %rdx\nmov %rcx, %rsi\nmov $1, %rax\nmov $1, %rdi\nsyscall\n"
    "mov %rbp, %rsp\npop %rbp\nret\n"
    "rex_pi_min:\nlea rex_min(%rip), %rdi\ncall rex_print_str\nmov %rbp, %rsp\npop %rbp\nret\n"
    "rex_fail:\npush %rbp\nmov %rsp, %rbp\nmov %rdi, %rsi\n"
    "rex_fail_len:\ncmpb $0, (%rsi)\nje rex_fail_go\ninc %rsi\njmp rex_fail_len\n"
    "rex_fail_go:\nsub %rdi, %rsi\nmov %rsi, %rdx\nmov %rdi, %rsi\nmov $1, %rax\nmov $2, %rdi\nsyscall\n"
    "mov $1, %rax\nmov $2, %rdi\nlea rex_nl(%rip), %rsi\nmov $1, %rdx\nsyscall\n"
    "mov $60, %rax\nmov $1, %rdi\nsyscall\n"
    "rex_read_int:\npush %rbp\nmov %rsp, %rbp\nsub $32, %rsp\n"
    "xor %eax, %eax\nxor %edi, %edi\nlea -24(%rbp), %rsi\nmov $16, %rdx\nsyscall\n"
    "lea -24(%rbp), %rsi\nxor %eax, %eax\nxor %ecx, %ecx\n"
    "cmpb $45, (%rsi)\njne rex_rd_loop\nmov $1, %rcx\ninc %rsi\n"
    "rex_rd_loop:\ncmpb $48, (%rsi)\njl rex_rd_done\ncmpb $57, (%rsi)\njg rex_rd_done\n"
    "imul $10, %rax\nmovzbl (%rsi), %edx\nsub $48, %edx\nadd %rdx, %rax\ninc %rsi\njmp rex_rd_loop\n"
    "rex_rd_done:\ntest %rcx, %rcx\nje rex_rd_ret\nneg %rax\n"
    "rex_rd_ret:\nmov %rbp, %rsp\npop %rbp\nret\n"
    "rex_exec:\npush %rbp\nmov %rsp, %rbp\nmov $57, %rax\nsyscall\ntest %rax, %rax\njnz rex_ex_parent\n"
    "sub $48, %rsp\nlea rex_sh(%rip), %rax\nmov %rax, (%rsp)\nlea rex_dashc(%rip), %rax\nmov %rax, 8(%rsp)\n"
    "mov %rdi, 16(%rsp)\nmovq $0, 24(%rsp)\nlea rex_sh(%rip), %rdi\nmov %rsp, %rsi\nlea 24(%rsp), %rdx\n"
    "mov $59, %rax\nsyscall\nmov $60, %rax\nmov $127, %rdi\nsyscall\n"
    "rex_ex_parent:\nmov %rax, %rdi\nxor %esi, %esi\nxor %edx, %edx\nxor %r10d, %r10d\nmov $61, %rax\nsyscall\n"
    "mov %rbp, %rsp\npop %rbp\nret\n"
    "rex_start:\ncall main\nmov %rax, %rdi\nmov $60, %rax\nsyscall\n"
    "rex_nl:\n.asciz \"\\n\"\n"
    "rex_minus:\n.asciz \"-\"\n"
    "rex_strlen:\nmov %rdi, %rax\nrex_sl:\ncmpb $0, (%rax)\nje rex_sl_done\ninc %rax\njmp rex_sl\nrex_sl_done:\nsub %rdi, %rax\nret\n"
    "rex_alloc:\npush %rbp\nmov %rsp, %rbp\npush %rdi\nmov $4096, %rsi\nxor %edi, %edi\nmov $3, %rdx\nmov $34, %r10\nmov $-1, %r8\nxor %r9d, %r9d\nmov $9, %rax\nsyscall\npop %rdi\nmov %rdi, (%rax)\nadd $8, %rax\nmov %rbp, %rsp\npop %rbp\nret\n"
    "rex_free:\nsub $8, %rdi\nmov $4096, %rsi\nmov $11, %rax\nsyscall\nret\n"
    "rex_min:\n.asciz \"-9223372036854775808\"\n"
    "rex_sh:\n.asciz \"/bin/sh\"\n"
    "rex_dashc:\n.asciz \"-c\"\n";

int rex_write_elf(const char *asm_text, const char *outpath) {
    nlabels = nrels = clen = 0;
    char *dup = strdup(asm_text);
    if (!dup) return 1;
    char *save = NULL;
    for (char *ln = strtok_r(dup, "\n", &save); ln; ln = strtok_r(NULL, "\n", &save)) asm_line(ln);
    free(dup);
    char *rt = strdup(runtime);
    if (!rt) return 1;
    save = NULL;
    for (char *ln = strtok_r(rt, "\n", &save); ln; ln = strtok_r(NULL, "\n", &save)) asm_line(ln);
    free(rt);
    for (int i = 0; i < nrels; i++) {
        int id = lab_find(rels[i].name);
        if (id < 0 || labels[id].off < 0) {
            fprintf(stderr, "rex: elf: undefined %s\n", rels[i].name);
            return 1;
        }
        int32_t v = labels[id].off - (rels[i].at + 4);
        memcpy(code + rels[i].at, &v, 4);
    }
    int start_id = lab_find("rex_start");
    if (start_id < 0) die_elf("no start");
    uint64_t base = 0x400000;
    unsigned char eh[64] = {0};
    eh[0] = 0x7f; memcpy(eh + 1, "ELF", 3); eh[4] = 2; eh[5] = 1; eh[6] = 1;
    eh[16] = 2; eh[18] = 62;
    uint64_t entry = base + 64 + 56 + (uint64_t)labels[start_id].off;
    uint64_t phoff = 64;
    memcpy(eh + 24, &entry, 8);
    memcpy(eh + 32, &phoff, 8);
    eh[52] = 64; eh[54] = 56; eh[56] = 1;
    unsigned char ph[56] = {0};
    ph[0] = 1; ph[4] = 5;
    uint64_t off = 0, va = base, filesz = 64 + 56 + (uint64_t)clen;
    memcpy(ph + 8, &off, 8);
    memcpy(ph + 16, &va, 8);
    memcpy(ph + 24, &va, 8);
    memcpy(ph + 32, &filesz, 8);
    memcpy(ph + 40, &filesz, 8);
    uint64_t align = 0x1000;
    memcpy(ph + 48, &align, 8);
    FILE *f = fopen(outpath, "wb");
    if (!f) return 1;
    fwrite(eh, 1, 64, f);
    fwrite(ph, 1, 56, f);
    fwrite(code, 1, (size_t)clen, f);
    fclose(f);
    chmod(outpath, 0755);
    return 0;
}
