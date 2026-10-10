#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../src/loader.h"
#include "../src/rex_err.h"

static void put16(unsigned char *p, uint16_t v) { p[0]=(unsigned char)v; p[1]=(unsigned char)(v>>8); }
static void put32(unsigned char *p, uint32_t v) {
    p[0]=(unsigned char)v; p[1]=(unsigned char)(v>>8);
    p[2]=(unsigned char)(v>>16); p[3]=(unsigned char)(v>>24);
}

int main(void) {
    int fails = 0, total = 0;
    unsigned char img[256];
    RexElf e; char err[256];

    /* E100 */
    unsigned char junk[] = { 0xaa, 0xbb };
    total++;
    int rc = rex_bin_parse(junk, sizeof(junk), &e, err, sizeof(err));
    if (rc != REX_E100_UNRECOGNIZED || !strstr(err, "E100:") || !strstr(err, "do not recognize")) { printf("FAIL E100 (%d %s)\n", rc, err); fails++; }

    /* E101 */
    memset(img, 0, sizeof(img));
    img[0]='M'; img[1]='Z'; put32(img+0x3c, 0x80);
    img[0x80]='P'; img[0x81]='E';
    put16(img+0x84, 0x8664); put16(img+0x84+16, 2); put16(img+0x84+20, 0x20b);
    total++;
    rc = rex_bin_parse(img, 0x84+22, &e, err, sizeof(err));
    if (rc != REX_E101_PE_STUB || !strstr(err, "E101:") || !strstr(err, "Windows")) { printf("FAIL E101 (%d %s)\n", rc, err); fails++; }

    /* E102 — 32-bit ELF */
    unsigned char elf[64]; memset(elf, 0, sizeof(elf));
    memcpy(elf, "\177ELF", 4); elf[4]=1; elf[5]=1; elf[6]=1;
    total++;
    rc = rex_bin_parse(elf, sizeof(elf), &e, err, sizeof(err));
    if (rc != REX_E102_ELF || !strstr(err, "E102:")) { printf("FAIL E102 (%d %s)\n", rc, err); fails++; }

    printf("err codes: %d/%d checks passed\n", total - fails, total);
    return fails ? 1 : 0;
}
