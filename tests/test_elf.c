#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/elfread.h"

/* Malformed-input tests for the ELF reader. Every case must come back
 * as a clean error, never a crash or an out-of-bounds read. */

static unsigned char img[0x400];
static size_t imglen;

static void w16(size_t o, uint16_t v) { img[o] = v & 255; img[o + 1] = v >> 8; }
static void w32(size_t o, uint32_t v) { for (int i = 0; i < 4; i++) img[o + i] = (v >> (8 * i)) & 255; }
static void w64(size_t o, uint64_t v) { for (int i = 0; i < 8; i++) img[o + i] = (v >> (8 * i)) & 255; }

/* ehdr, 1 phdr, code at 0x78, shstrtab at 0x100, 3 sections at 0x200 */
static void build(void) {
    memset(img, 0, sizeof(img));
    memcpy(img, "\177ELF", 4); img[4] = 2; img[5] = 1; img[6] = 1;
    w16(16, 2); w16(18, 62); w32(20, 1);
    w64(24, 0x400078); w64(32, 64); w64(40, 0x200);
    w16(52, 64); w16(54, 56); w16(56, 1); w16(58, 64); w16(60, 3); w16(62, 2);
    w32(64, 1); w32(68, 5); w64(72, 0); w64(80, 0x400000); w64(88, 0x400000);
    w64(96, 0x100); w64(104, 0x100); w64(112, 0x1000);
    img[0x78] = 0xc3;
    memcpy(img + 0x100, "\0.text\0.shstrtab\0", 17);
    /* [1] .text */
    w32(0x240, 1); w32(0x244, 1); w64(0x248, 6); w64(0x250, 0x400078); w64(0x258, 0x78); w64(0x260, 8);
    /* [2] .shstrtab */
    w32(0x280, 7); w32(0x284, 3); w64(0x298, 0x100); w64(0x2a0, 17);
    imglen = 0x2c0;
}

static int fails, total;

static void expect(int ok, const char *what) {
    RexElf e;
    char err[256] = "";
    int rc = rex_elf_parse(img, imglen, &e, err, sizeof(err));
    total++;
    if ((rc == 0) != ok) { printf("FAIL %s: rc %d (%s)\n", what, rc, err); fails++; }
    if (!ok && rc != 0 && !err[0]) { printf("FAIL %s: no message\n", what); fails++; }
    if (rc == 0) rex_elf_free(&e);
}

int main(void) {
    build(); expect(1, "valid");
    {
        RexElf e; char err[128];
        if (rex_elf_parse(img, imglen, &e, err, sizeof(err)) == 0) {
            total++;
            if (strcmp(e.sh[1].name, ".text") || e.entry != 0x400078 || rex_elf_exec_segments(&e) != 1) { printf("FAIL fields\n"); fails++; }
            size_t av; total++;
            if (!rex_elf_code_at(&e, 0x400078, &av) || av != 0x88 || rex_elf_code_at(&e, 0x400100, &av)) { printf("FAIL code_at\n"); fails++; }
            rex_elf_free(&e);
        }
    }
    for (size_t n = 0; n < 64; n++) { build(); imglen = n; expect(0, "short header"); }
    build(); img[0] = 0; expect(0, "magic");
    build(); img[4] = 1; expect(0, "elf32");
    build(); img[4] = 9; expect(0, "class");
    build(); img[5] = 2; expect(0, "big endian");
    build(); img[6] = 0; expect(0, "version");
    build(); img[7] = 9; expect(0, "osabi");
    build(); w16(18, 40); expect(0, "arm");
    build(); w16(16, 3); expect(0, "dyn");
    build(); w16(16, 1); expect(0, "rel");
    build(); w16(16, 4); expect(0, "core");
    build(); w16(52, 10); expect(0, "ehsize");
    build(); w16(54, 32); expect(0, "phentsize");
    build(); w16(56, 0); expect(0, "no phdrs");
    build(); w16(56, 0xffff); expect(0, "phnum xnum");
    build(); w16(56, 2000); expect(0, "phnum huge");
    build(); w64(32, 0xffffffffffffffffull); expect(0, "phoff overflow");
    build(); w64(32, imglen - 8); expect(0, "phoff tail");
    build(); w64(72, 0xfffffffffffffff0ull); expect(0, "seg offset overflow");
    build(); w64(96, 0x10000); w64(104, 0x10000); expect(0, "seg past end");
    build(); w64(104, 0x10); expect(0, "filesz > memsz");
    build(); w64(80, 0xfffffffffffff000ull); w64(104, 0x2000); w64(24, 0xfffffffffffff078ull); expect(0, "vaddr overflow");
    build(); w64(112, 0x1001); expect(0, "align");
    build(); w64(24, 0x500000); expect(0, "entry outside");
    build(); w32(68, 4); expect(0, "entry not exec");
    build(); w16(60, 0); expect(0, "shnum 0 with shoff");
    build(); w16(60, 9000); expect(0, "shnum huge");
    build(); w16(58, 40); expect(0, "shentsize");
    build(); w64(40, 0xffffffffffffffc0ull); expect(0, "shoff overflow");
    build(); w64(40, imglen - 64); expect(0, "shdrs past end");
    build(); w16(62, 7); expect(0, "shstrndx range");
    build(); w32(0x284, 1); expect(0, "shstrtab type");
    build(); w64(0x258, 0x7fffffffffffffffull); expect(0, "section offset");
    build(); w64(0x260, 0xffffffffffffffffull); expect(0, "section size");
    /* Names are labels: unterminated or out-of-table names are tolerated. */
    build(); w32(0x240, 1000); expect(1, "name index past table");
    build(); memset(img + 0x101, 'A', 16); expect(1, "unterminated names");
    build(); w64(40, 0); w16(60, 0); w16(62, 0); expect(1, "no sections");

    /* Fuzz: random byte flips over the valid image. */
    srand(42);
    for (int it = 0; it < 300000; it++) {
        build();
        int flips = 1 + rand() % 8;
        for (int k = 0; k < flips; k++) {
            size_t at = (size_t)(rand() % (int)imglen);
            img[at] = (unsigned char)(rand() % 3 == 0 ? 0xff : rand());
        }
        if (rand() % 5 == 0) imglen = (size_t)(rand() % 0x2c1);
        RexElf e; char err[128];
        if (rex_elf_parse(img, imglen, &e, err, sizeof(err)) == 0) {
            size_t av;
            const unsigned char *p = rex_elf_code_at(&e, e.entry, &av);
            if (!p || av == 0 || p < e.data || p + av > e.data + e.size) { printf("FAIL fuzz code_at\n"); fails++; break; }
            for (int i = 0; i < e.nsh; i++) if (strlen(e.sh[i].name) >= sizeof(e.sh[i].name)) { printf("FAIL fuzz name\n"); fails++; }
            rex_elf_free(&e);
        }
    }
    total++;
    printf("elf reader: %d/%d checks passed\n", total - fails, total);
    return fails ? 1 : 0;
}
