#include "loader.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- PE recognition stub (no image produced) ---- */

static uint16_t pe_u16(const unsigned char *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}
static uint32_t pe_u32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int pe_probe(const unsigned char *data, size_t len) {
    if (len < 0x40) return 0;
    if (data[0] != 'M' || data[1] != 'Z') return 0;
    uint32_t e_lfanew = pe_u32(data + 0x3c);
    if (e_lfanew > len - 4) return 0;
    if (e_lfanew + 4 > len) return 0;
    return data[e_lfanew] == 'P' && data[e_lfanew + 1] == 'E' &&
           data[e_lfanew + 2] == 0 && data[e_lfanew + 3] == 0;
}

static const char *pe_machine(uint16_t m) {
    switch (m) {
    case 0x8664: return "x86-64";
    case 0x14c:  return "i386";
    case 0xaa64: return "arm64";
    case 0x1c0:  return "arm";
    default:     return "unknown-machine";
    }
}

static int pe_parse(const unsigned char *data, size_t len, RexElf *out, char *err, size_t errlen) {
    (void)out;
    if (!pe_probe(data, len)) {
        snprintf(err, errlen, "not a PE/COFF file");
        return 1;
    }
    uint32_t e_lfanew = pe_u32(data + 0x3c);
    /* PE signature (4) + COFF header (20) + optional header magic (2). */
    if (e_lfanew + 4 + 20 + 2 > len) {
        snprintf(err, errlen, "PE/COFF header truncated");
        return 1;
    }
    const unsigned char *coff = data + e_lfanew + 4;
    uint16_t machine = pe_u16(coff + 0);
    uint16_t optsize = pe_u16(coff + 16);
    const unsigned char *opt = coff + 20;
    const char *magic = "unknown";
    if (optsize >= 2 && e_lfanew + 4 + 20 + 2 <= len) {
        uint16_t m = pe_u16(opt);
        if (m == 0x10b) magic = "PE32";
        else if (m == 0x20b) magic = "PE32+";
        else magic = "bad-optional-magic";
    }
    snprintf(err, errlen, "PE/COFF (%s, %s) recognized; PE loading not implemented yet",
             pe_machine(machine), magic);
    return REX_BIN_ERR_PE_STUB;
}

/* ---- ELF wrapper (real implementation stays in elfread.c) ---- */

static int elf_probe(const unsigned char *data, size_t len) {
    return len >= 4 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F';
}

static int elf_parse(const unsigned char *data, size_t len, RexElf *out, char *err, size_t errlen) {
    return rex_elf_parse(data, len, out, err, errlen);
}

static const RexLoader loaders[] = {
    { "elf64", elf_probe, elf_parse },
    { "pe",    pe_probe,  pe_parse  },
};

const RexLoader *rex_loader_find(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < sizeof(loaders) / sizeof(loaders[0]); i++)
        if (loaders[i].probe(data, len)) return &loaders[i];
    return NULL;
}

static void hex_prefix(const unsigned char *data, size_t len, char *out, size_t outn) {
    size_t n = len < 8 ? len : 8;
    size_t k = 0;
    for (size_t i = 0; i < n && k + 3 < outn; i++)
        k += (size_t)snprintf(out + k, outn - k, "%s%02x", i ? " " : "", data[i]);
    if (k < outn) out[k] = 0;
}

int rex_bin_parse(const unsigned char *data, size_t len, RexElf *out, char *err, size_t errlen) {
    memset(out, 0, sizeof(*out));
    const RexLoader *L = rex_loader_find(data, len);
    if (!L) {
        char hx[40];
        hex_prefix(data, len, hx, sizeof(hx));
        snprintf(err, errlen, "unrecognized binary format%s%s", hx[0] ? ": " : "", hx);
        return REX_BIN_ERR_UNRECOGNIZED;
    }
    return L->parse(data, len, out, err, errlen);
}

int rex_bin_open(const char *path, RexElf *out, char *err, size_t errlen) {
    memset(out, 0, sizeof(*out));
    FILE *f = fopen(path, "rb");
    if (!f) { snprintf(err, errlen, "%s: %s", path, strerror(errno)); return 1; }
    size_t cap = 1 << 16, len = 0;
    unsigned char *buf = malloc(cap);
    if (!buf) { fclose(f); snprintf(err, errlen, "out of memory"); return 1; }
    for (;;) {
        if (len == cap) {
            if (cap >= REX_ELF_MAX_FILE + 1) { free(buf); fclose(f); snprintf(err, errlen, "%s: file too large", path); return 1; }
            size_t nc = cap * 2;
            if (nc > REX_ELF_MAX_FILE + 1) nc = REX_ELF_MAX_FILE + 1;
            unsigned char *nb = realloc(buf, nc);
            if (!nb) { free(buf); fclose(f); snprintf(err, errlen, "out of memory"); return 1; }
            buf = nb; cap = nc;
        }
        size_t r = fread(buf + len, 1, cap - len, f);
        len += r;
        if (r == 0) break;
    }
    int ioerr = ferror(f);
    fclose(f);
    if (ioerr) { free(buf); snprintf(err, errlen, "%s: read error", path); return 1; }
    int rc = rex_bin_parse(buf, len, out, err, errlen);
    free(buf);
    return rc;
}
