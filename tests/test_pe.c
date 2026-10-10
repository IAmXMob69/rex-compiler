#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "../src/loader.h"
#include "../src/x86_decode.h"
#include "../src/cfg.h"
#include "../src/x86_lift.h"

static void put16(unsigned char *p, uint16_t v) { p[0]=(unsigned char)v; p[1]=(unsigned char)(v>>8); }
static void put32(unsigned char *p, uint32_t v) {
    p[0]=(unsigned char)v; p[1]=(unsigned char)(v>>8);
    p[2]=(unsigned char)(v>>16); p[3]=(unsigned char)(v>>24);
}
static void put64(unsigned char *p, uint64_t v) { put32(p,(uint32_t)v); put32(p+4,(uint32_t)(v>>32)); }

/* Tiny static PE32+ x86-64: one .text with mov rax,42; ret. No imports/relocs. */
static size_t build_pe(unsigned char *img, size_t cap) {
    memset(img, 0, cap);
    img[0]='M'; img[1]='Z';
    uint32_t e_lfanew = 0x80;
    put32(img + 0x3c, e_lfanew);
    img[e_lfanew]='P'; img[e_lfanew+1]='E';
    unsigned char *coff = img + e_lfanew + 4;
    put16(coff + 0, 0x8664);
    put16(coff + 2, 1); /* one section */
    uint16_t optsize = 112 + 15 * 8; /* PE32+ with 15 data dirs zeroed */
    put16(coff + 16, optsize);
    unsigned char *opt = coff + 20;
    put16(opt, 0x20b);
    put32(opt + 16, 0x1000);           /* EntryPoint RVA */
    put64(opt + 24, 0x140000000ULL);   /* ImageBase */
    put32(opt + 32, 0x1000);           /* SectionAlignment */
    put32(opt + 36, 0x200);            /* FileAlignment */
    put16(opt + 48, 6); put16(opt + 50, 0); /* OS version */
    put32(opt + 56, 0x2000);           /* SizeOfImage */
    put32(opt + 60, 0x200);            /* SizeOfHeaders */
    put16(opt + 68, 3);                /* console subsystem */
    put32(opt + 108, 15);              /* NumberOfRvaAndSizes */
    /* section table */
    size_t sec_off = (size_t)e_lfanew + 4 + 20 + optsize;
    unsigned char *sec = img + sec_off;
    memcpy(sec, ".text\0\0\0", 8);
    put32(sec + 8, 0x1000);   /* vsize */
    put32(sec + 12, 0x1000);  /* vaddr */
    put32(sec + 16, 0x200);   /* raw size */
    put32(sec + 20, 0x200);   /* raw ptr */
    put32(sec + 36, 0x60000020); /* code | exec | read */
    /* code at file offset 0x200 */
    unsigned char *code = img + 0x200;
    /* mov rax, 42; ret */
    code[0]=0x48; code[1]=0xc7; code[2]=0xc0; code[3]=0x2a; code[4]=0; code[5]=0; code[6]=0; code[7]=0xc3;
    return 0x400;
}

static size_t build_pe32(unsigned char *img, size_t cap) {
    size_t n = build_pe(img, cap);
    uint32_t e_lfanew = 0x80;
    unsigned char *opt = img + e_lfanew + 4 + 20;
    put16(opt, 0x10b); /* PE32 */
    return n;
}

int main(void) {
    int fails = 0, total = 0;
    unsigned char img[0x800];
    size_t n = build_pe(img, sizeof(img));
    RexElf e; char err[256];

    total++;
    int rc = rex_bin_parse(img, n, &e, err, sizeof(err));
    if (rc) { printf("FAIL pe load: %s\n", err); fails++; }
    else {
        if (e.type != 0xFE00) { printf("FAIL pe type\n"); fails++; }
        if (e.entry != 0x140001000ULL) { printf("FAIL pe entry %llx\n", (unsigned long long)e.entry); fails++; }
        if (rex_elf_exec_segments(&e) < 1) { printf("FAIL pe exec segs\n"); fails++; }
        size_t av = 0;
        const unsigned char *p = rex_elf_code_at(&e, e.entry, &av);
        if (!p || av < 8 || p[0] != 0x48) { printf("FAIL pe code_at\n"); fails++; }
        X86Insn in;
        if (!x86_decode(p, av, e.entry, &in) || in.op == X86_BAD) { printf("FAIL pe decode\n"); fails++; }
        CfgProgram cfg;
        if (cfg_build(&e, &cfg, err, sizeof(err))) { printf("FAIL pe cfg: %s\n", err); fails++; }
        else {
            IrModule *m = x86_lift(&cfg, err, sizeof(err));
            if (!m) { printf("FAIL pe lift: %s\n", err); fails++; }
            else ir_module_free(m);
            cfg_free(&cfg);
        }
        rex_elf_free(&e);
    }

    /* PE32 refused */
    n = build_pe32(img, sizeof(img));
    total++;
    rc = rex_bin_parse(img, n, &e, err, sizeof(err));
    if (rc != REX_E105_PE_MAGIC || !strstr(err, "E105:")) { printf("FAIL pe32 (%d %s)\n", rc, err); fails++; }

    /* i386 refused */
    n = build_pe(img, sizeof(img));
    put16(img + 0x80 + 4, 0x14c);
    total++;
    rc = rex_bin_parse(img, n, &e, err, sizeof(err));
    if (rc != REX_E104_PE_MACHINE || !strstr(err, "E104:")) { printf("FAIL i386 (%d %s)\n", rc, err); fails++; }

    printf("pe: %d/%d checks passed\n", total - fails, total);
    return fails ? 1 : 0;
}
