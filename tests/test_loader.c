#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../src/loader.h"

/* Tiny hand-built PE headers. No checked-in binaries. */

static void put16(unsigned char *p, uint16_t v) { p[0] = (unsigned char)v; p[1] = (unsigned char)(v >> 8); }
static void put32(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)v; p[1] = (unsigned char)(v >> 8);
    p[2] = (unsigned char)(v >> 16); p[3] = (unsigned char)(v >> 24);
}

/* Build MZ + PE\0\0 + COFF (machine, ...) + optional magic. Returns length. */
static size_t make_pe(unsigned char *img, size_t cap, uint16_t machine, uint16_t opt_magic) {
    memset(img, 0, cap);
    img[0] = 'M'; img[1] = 'Z';
    uint32_t e_lfanew = 0x80;
    put32(img + 0x3c, e_lfanew);
    img[e_lfanew] = 'P'; img[e_lfanew + 1] = 'E';
    unsigned char *coff = img + e_lfanew + 4;
    put16(coff + 0, machine);
    put16(coff + 2, 0);          /* NumberOfSections */
    put16(coff + 16, 2);         /* SizeOfOptionalHeader (just the magic) */
    put16(coff + 20, opt_magic); /* OptionalHeader.Magic */
    return e_lfanew + 4 + 20 + 2;
}

static int expect_fail(const unsigned char *img, size_t n, int want_rc, const char *needle, const char *tag) {
    RexElf e; char err[256];
    int rc = rex_bin_parse(img, n, &e, err, sizeof(err));
    if (rc == 0) { printf("FAIL %s: unexpectedly succeeded\n", tag); rex_elf_free(&e); return 1; }
    if (rc != want_rc) { printf("FAIL %s: rc %d want %d (%s)\n", tag, rc, want_rc, err); return 1; }
    if (needle && !strstr(err, needle)) { printf("FAIL %s: err '%s' missing '%s'\n", tag, err, needle); return 1; }
    return 0;
}

int main(void) {
    int fails = 0, total = 0;
    unsigned char img[256];

    /* PE x86-64 PE32+ */
    size_t n = make_pe(img, sizeof(img), 0x8664, 0x20b);
    total++; fails += expect_fail(img, n, REX_BIN_ERR_PE_STUB, "PE/COFF (x86-64, PE32+)", "pe64");
    total++; fails += expect_fail(img, n, REX_BIN_ERR_PE_STUB, "not implemented yet", "pe64-msg");

    /* PE i386 PE32 */
    n = make_pe(img, sizeof(img), 0x14c, 0x10b);
    total++; fails += expect_fail(img, n, REX_BIN_ERR_PE_STUB, "PE/COFF (i386, PE32)", "pei386");

    /* PE arm64 */
    n = make_pe(img, sizeof(img), 0xaa64, 0x20b);
    total++; fails += expect_fail(img, n, REX_BIN_ERR_PE_STUB, "PE/COFF (arm64, PE32+)", "pearm64");

    /* Probe only: MZ without PE signature is not PE and not ELF. */
    memset(img, 0, sizeof(img));
    img[0] = 'M'; img[1] = 'Z';
    put32(img + 0x3c, 0x80);
    total++; fails += expect_fail(img, 0x90, REX_BIN_ERR_UNRECOGNIZED, "unrecognized binary format", "mz-only");

    /* Garbage */
    unsigned char junk[] = { 0x00, 0x01, 0x02, 0x03, 0xde, 0xad };
    total++; fails += expect_fail(junk, sizeof(junk), REX_BIN_ERR_UNRECOGNIZED, "unrecognized binary format: 00 01 02 03 de ad", "junk");

    /* Empty */
    total++; fails += expect_fail(junk, 0, REX_BIN_ERR_UNRECOGNIZED, "unrecognized binary format", "empty");

    /* Real tiny ELF still loads through the registry (ET_EXEC x86-64). */
    {
        /* Minimal valid ELF from the ELF unit tests' builder style: reuse rex_elf_parse path via registry. */
        unsigned char elf[256];
        memset(elf, 0, sizeof(elf));
        memcpy(elf, "\177ELF", 4);
        elf[4] = 2; elf[5] = 1; elf[6] = 1; /* ELF64 LE */
        elf[16] = 2; elf[18] = 62;          /* ET_EXEC, EM_X86_64 */
        /* entry 0x400078, phoff 64, phentsize 56, phnum 1, ehsize 64 */
        put32(elf + 24, 0x400078); /* entry low 32 (LE) — write full 64 below */
        memset(elf + 24, 0, 8);
        elf[24] = 0x78; elf[25] = 0x00; elf[26] = 0x40; elf[27] = 0x00;
        elf[32] = 64; /* phoff */
        elf[52] = 64; elf[54] = 56; elf[56] = 1;
        /* One PT_LOAD RWX covering entry */
        unsigned char *ph = elf + 64;
        put32(ph, 1); put32(ph + 4, 7);
        /* offset 0, vaddr 0x400000, filesz 0x100, memsz 0x100, align 0x1000 */
        put32(ph + 16, 0x400000);
        put32(ph + 32, 0x100); put32(ph + 40, 0x100); put32(ph + 48, 0x1000);
        RexElf e; char err[128];
        total++;
        int rc = rex_bin_parse(elf, 0x100, &e, err, sizeof(err));
        if (rc != 0) { printf("FAIL elf-through-registry: %s\n", err); fails++; }
        else {
            if (e.entry != 0x400078 || rex_elf_exec_segments(&e) != 1) { printf("FAIL elf-through-registry: bad fields\n"); fails++; }
            rex_elf_free(&e);
        }
        /* Probe picks elf64 */
        total++;
        const RexLoader *L = rex_loader_find(elf, 0x100);
        if (!L || strcmp(L->name, "elf64")) { printf("FAIL find elf64\n"); fails++; }
        L = rex_loader_find(img, n = make_pe(img, sizeof(img), 0x8664, 0x20b));
        total++;
        if (!L || strcmp(L->name, "pe")) { printf("FAIL find pe\n"); fails++; }
    }

    printf("loader: %d/%d checks passed\n", total - fails, total);
    return fails ? 1 : 0;
}
