#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "elfread.h"
#include "rex_err.h"

static int fail(char *err, size_t n, const char *fmt, ...) {
    char body[192];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);
    return rex_errf(err, n, REX_E102_ELF, "%s", body);
}

static uint16_t rd16(const unsigned char *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t rd32(const unsigned char *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t rd64(const unsigned char *p) { return (uint64_t)rd32(p) | (uint64_t)rd32(p + 4) << 32; }

/* off + len lies inside size, without overflowing. */
static int in_file(uint64_t off, uint64_t len, size_t size) {
    return off <= size && len <= size - off;
}

void rex_elf_free(RexElf *e) {
    if (!e) return;
    free(e->data);
    free(e->ph);
    free(e->sh);
    free(e->imp);
    memset(e, 0, sizeof(*e));
}

/* File bytes behind [vaddr, vaddr+len) inside any PT_LOAD, NULL if not all there. */
static unsigned char *file_at(RexElf *e, uint64_t vaddr, uint64_t len) {
    for (int i = 0; i < e->nph; i++) {
        const RexPhdr *h = &e->ph[i];
        if (h->type != REX_PT_LOAD || vaddr < h->vaddr) continue;
        uint64_t d = vaddr - h->vaddr;
        if (d > h->filesz || len > h->filesz - d) continue;
        return e->data + h->offset + d;
    }
    return NULL;
}

static int sec_named(const RexElf *e, uint32_t type, const char *name) {
    for (int i = 0; i < e->nsh; i++)
        if (e->sh[i].type == type && !strcmp(e->sh[i].name, name)) return i;
    return -1;
}

/* Library imports from the relocation tables (JUMP_SLOT and GLOB_DAT name a
 * GOT slot after a .dynsym entry), then the PLT stub that jumps through each
 * slot. A PIE is read at base 0, so its RELATIVE relocations are applied to
 * the copy: a pointer stored in data then reads as the address it names.
 * Malformed tables are skipped, never trusted. Returns nonzero only on OOM. */
static int read_imports(RexElf *e) {
    int ds = sec_named(e, 11, ".dynsym"), dst = sec_named(e, 3, ".dynstr");
    for (int ri = 0; ri < e->nsh; ri++) {
        const RexShdr *r = &e->sh[ri];
        if (r->type != 4 || r->size % 24) continue;             /* SHT_RELA */
        for (uint64_t off = 0; off + 24 <= r->size; off += 24) {
            const unsigned char *p = e->data + r->offset + off;
            uint64_t where = rd64(p), info = rd64(p + 8), addend = rd64(p + 16);
            uint32_t rtype = (uint32_t)info, rsym = (uint32_t)(info >> 32);
            if (rtype == 8) {                                     /* R_X86_64_RELATIVE */
                unsigned char *w = e->pie ? file_at(e, where, 8) : NULL;
                if (w) for (int k = 0; k < 8; k++) w[k] = (unsigned char)(addend >> (8 * k));
                continue;
            }
            if (rtype != 6 && rtype != 7) continue;               /* GLOB_DAT / JUMP_SLOT */
            if (ds < 0 || dst < 0 || rsym == 0) continue;
            const RexShdr *sy = &e->sh[ds], *st = &e->sh[dst];
            if (sy->size % 24 || (uint64_t)rsym >= sy->size / 24) continue;
            uint32_t nm = rd32(e->data + sy->offset + (uint64_t)rsym * 24);
            if (nm >= st->size) continue;
            const unsigned char *s = e->data + st->offset + nm;
            uint64_t left = st->size - nm;
            char name[48]; size_t k = 0;
            while (k < left && k < sizeof(name) - 1 && s[k] && s[k] != '@') {
                unsigned char c = s[k];
                name[k] = ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') ? (char)c : '_';
                k++;
            }
            name[k] = 0;
            if (!k || (name[0] >= '0' && name[0] <= '9')) continue;
            if (e->nimp >= REX_ELF_MAX_IMPORTS) continue;
            RexImport *ni = realloc(e->imp, (size_t)(e->nimp + 1) * sizeof(RexImport));
            if (!ni) return 1;
            e->imp = ni;
            RexImport *im = &e->imp[e->nimp++];
            memset(im, 0, sizeof(*im));
            im->got = where;
            memcpy(im->name, name, k + 1);
        }
    }
    /* PLT stubs: jmp *slot(%rip), optionally bnd-prefixed and after endbr64. */
    for (int si = 0; si < e->nsh && e->nimp; si++) {
        const RexShdr *sc = &e->sh[si];
        if (sc->type != 1 || !(sc->flags & 4) || strncmp(sc->name, ".plt", 4)) continue;
        const unsigned char *b = e->data + sc->offset;
        for (uint64_t j = 0; j + 6 <= sc->size; j++) {
            if (b[j] != 0xff || b[j + 1] != 0x25) continue;
            int32_t disp = (int32_t)rd32(b + j + 2);
            uint64_t slot = sc->addr + j + 6 + (uint64_t)(int64_t)disp;
            for (int k = 0; k < e->nimp; k++) {
                if (e->imp[k].got != slot || e->imp[k].plt) continue;
                uint64_t s0 = j;
                if (s0 >= 1 && b[s0 - 1] == 0xf2) s0--;
                if (s0 >= 4 && b[s0 - 4] == 0xf3 && b[s0 - 3] == 0x0f && b[s0 - 2] == 0x1e && b[s0 - 1] == 0xfa) s0 -= 4;
                e->imp[k].plt = sc->addr + s0;
                break;
            }
        }
    }
    return 0;
}

const char *rex_elf_import_at(const RexElf *e, uint64_t addr) {
    for (int k = 0; k < e->nimp; k++)
        if (e->imp[k].plt && e->imp[k].plt == addr) return e->imp[k].name;
    return NULL;
}

const char *rex_elf_import_got(const RexElf *e, uint64_t got) {
    for (int k = 0; k < e->nimp; k++)
        if (e->imp[k].got == got) return e->imp[k].name;
    return NULL;
}

int rex_elf_parse(const unsigned char *data, size_t size, RexElf *out, char *err, size_t errlen) {
    memset(out, 0, sizeof(*out));
    if (size > REX_ELF_MAX_FILE) return fail(err, errlen, "file too large");
    if (size < 64) return fail(err, errlen, "too small for an ELF header");
    if (memcmp(data, "\177ELF", 4)) return fail(err, errlen, "not an ELF file (bad magic)");
    if (data[4] == 1) return fail(err, errlen, "unsupported: 32-bit ELF (only ELF64)");
    if (data[4] != 2) return fail(err, errlen, "bad ELF class %u", data[4]);
    if (data[5] == 2) return fail(err, errlen, "unsupported: big-endian ELF");
    if (data[5] != 1) return fail(err, errlen, "bad ELF data encoding %u", data[5]);
    if (data[6] != 1) return fail(err, errlen, "bad ELF version %u", data[6]);
    if (data[7] != 0 && data[7] != 3) return fail(err, errlen, "unsupported OS ABI %u (only Linux/SysV)", data[7]);

    uint16_t type = rd16(data + 16), machine = rd16(data + 18);
    /* REX's own writer leaves e_version 0; the kernel ignores it too. */
    if (rd32(data + 20) > 1) return fail(err, errlen, "bad ELF version field");
    if (machine != 62) return fail(err, errlen, "unsupported machine %u (only x86-64)", machine);
    if (type == 1) return fail(err, errlen, "unsupported: relocatable object, not an executable");
    /* ET_DYN is a PIE program when it has an entry point; a plain shared
     * library has none and is not a program. */
    if (type == 3 && rd64(data + 24) == 0) return fail(err, errlen, "unsupported: shared library, not a program (no entry point)");
    if (type == 4) return fail(err, errlen, "unsupported: core dump");
    if (type != 2 && type != 3) return fail(err, errlen, "unsupported ELF type %u", type);

    uint64_t entry = rd64(data + 24), phoff = rd64(data + 32), shoff = rd64(data + 40);
    uint16_t ehsize = rd16(data + 52), phentsize = rd16(data + 54), phnum = rd16(data + 56);
    uint16_t shentsize = rd16(data + 58), shnum = rd16(data + 60), shstrndx = rd16(data + 62);
    if (ehsize < 64) return fail(err, errlen, "bad header size %u", ehsize);

    if (phnum == 0xffff) return fail(err, errlen, "unsupported: extended program header count");
    if (phnum == 0) return fail(err, errlen, "no program headers");
    if (phnum > REX_ELF_MAX_PHDRS) return fail(err, errlen, "too many program headers (%u)", phnum);
    if (phentsize != 56) return fail(err, errlen, "bad program header size %u", phentsize);
    if (!in_file(phoff, (uint64_t)phnum * 56, size)) return fail(err, errlen, "program headers out of bounds");

    RexElf e = {0};
    e.type = type; e.machine = machine; e.entry = entry;
    e.ph = calloc(phnum, sizeof(RexPhdr));
    if (!e.ph) return fail(err, errlen, "out of memory");
    e.nph = phnum;
    int entry_ok = 0;
    for (int i = 0; i < phnum; i++) {
        const unsigned char *p = data + phoff + (uint64_t)i * 56;
        RexPhdr *h = &e.ph[i];
        h->type = rd32(p); h->flags = rd32(p + 4);
        h->offset = rd64(p + 8); h->vaddr = rd64(p + 16);
        h->filesz = rd64(p + 32); h->memsz = rd64(p + 40); h->align = rd64(p + 48);
        if (h->type == 2 || h->type == 3) e.dynamic = 1;   /* PT_DYNAMIC / PT_INTERP */
        if (h->type == 3) e.interp = 1;
        if (h->type != REX_PT_LOAD) continue;
        if (!in_file(h->offset, h->filesz, size)) { rex_elf_free(&e); return fail(err, errlen, "segment %d out of bounds", i); }
        if (h->filesz > h->memsz) { rex_elf_free(&e); return fail(err, errlen, "segment %d file size exceeds memory size", i); }
        if (h->vaddr + h->memsz < h->vaddr) { rex_elf_free(&e); return fail(err, errlen, "segment %d address overflow", i); }
        if (h->align > 1 && (h->align & (h->align - 1))) { rex_elf_free(&e); return fail(err, errlen, "segment %d bad alignment", i); }
        if ((h->flags & REX_PF_X) && entry >= h->vaddr && entry - h->vaddr < h->filesz) entry_ok = 1;
    }
    if (!entry_ok) { rex_elf_free(&e); return fail(err, errlen, "entry point 0x%llx is not in an executable segment", (unsigned long long)entry); }

    if (shoff != 0 || shnum != 0) {
        if (shnum == 0) { rex_elf_free(&e); return fail(err, errlen, "unsupported: extended section count"); }
        if (shnum > REX_ELF_MAX_SHDRS) { rex_elf_free(&e); return fail(err, errlen, "too many sections (%u)", shnum); }
        if (shentsize != 64) { rex_elf_free(&e); return fail(err, errlen, "bad section header size %u", shentsize); }
        if (!in_file(shoff, (uint64_t)shnum * 64, size)) { rex_elf_free(&e); return fail(err, errlen, "section headers out of bounds"); }
        if (shstrndx != 0 && shstrndx >= shnum) { rex_elf_free(&e); return fail(err, errlen, "section name table index out of range"); }
        e.sh = calloc(shnum, sizeof(RexShdr));
        if (!e.sh) { rex_elf_free(&e); return fail(err, errlen, "out of memory"); }
        e.nsh = shnum;
        for (int i = 0; i < shnum; i++) {
            const unsigned char *p = data + shoff + (uint64_t)i * 64;
            RexShdr *s = &e.sh[i];
            s->type = rd32(p + 4); s->flags = rd64(p + 8); s->addr = rd64(p + 16);
            s->offset = rd64(p + 24); s->size = rd64(p + 32);
            if (s->type != 8 && s->type != 0 && !in_file(s->offset, s->size, size)) {
                rex_elf_free(&e); return fail(err, errlen, "section %d out of bounds", i);
            }
        }
        /* Names are labels only. Copy at most 63 bytes and stop at the table end. */
        if (shstrndx != 0) {
            const RexShdr *st = &e.sh[shstrndx];
            if (st->type != 3) { rex_elf_free(&e); return fail(err, errlen, "section name table is not a string table"); }
            for (int i = 0; i < shnum; i++) {
                uint32_t nm = rd32(data + shoff + (uint64_t)i * 64);
                if (nm >= st->size) continue;
                const unsigned char *s = data + st->offset + nm;
                uint64_t left = st->size - nm;
                size_t k = 0;
                while (k < left && k < sizeof(e.sh[i].name) - 1 && s[k]) {
                    unsigned char c = s[k];
                    e.sh[i].name[k] = (c >= 32 && c < 127) ? (char)c : '?';
                    k++;
                }
                e.sh[i].name[k] = 0;
            }
        }
    }

    e.data = malloc(size);
    if (!e.data) { rex_elf_free(&e); return fail(err, errlen, "out of memory"); }
    memcpy(e.data, data, size);
    e.size = size;
    e.pie = type == 3;
    if (read_imports(&e)) { rex_elf_free(&e); return fail(err, errlen, "out of memory"); }
    *out = e;
    return 0;
}

int rex_elf_open(const char *path, RexElf *out, char *err, size_t errlen) {
    memset(out, 0, sizeof(*out));
    FILE *f = fopen(path, "rb");
    if (!f) return fail(err, errlen, "%s: %s", path, strerror(errno));
    size_t cap = 1 << 16, len = 0;
    unsigned char *buf = malloc(cap);
    if (!buf) { fclose(f); return fail(err, errlen, "out of memory"); }
    for (;;) {
        if (len == cap) {
            if (cap >= REX_ELF_MAX_FILE + 1) { free(buf); fclose(f); return fail(err, errlen, "%s: file too large", path); }
            size_t nc = cap * 2;
            if (nc > REX_ELF_MAX_FILE + 1) nc = REX_ELF_MAX_FILE + 1;
            unsigned char *nb = realloc(buf, nc);
            if (!nb) { free(buf); fclose(f); return fail(err, errlen, "out of memory"); }
            buf = nb; cap = nc;
        }
        size_t r = fread(buf + len, 1, cap - len, f);
        len += r;
        if (r == 0) break;
    }
    int ioerr = ferror(f);
    fclose(f);
    if (ioerr) { free(buf); return fail(err, errlen, "%s: read error", path); }
    int rc = rex_elf_parse(buf, len, out, err, errlen);
    free(buf);
    return rc;
}

int rex_elf_exec_segments(const RexElf *e) {
    int n = 0;
    for (int i = 0; i < e->nph; i++)
        if (e->ph[i].type == REX_PT_LOAD && (e->ph[i].flags & REX_PF_X)) n++;
    return n;
}

const unsigned char *rex_elf_code_at(const RexElf *e, uint64_t vaddr, size_t *avail) {
    for (int i = 0; i < e->nph; i++) {
        const RexPhdr *h = &e->ph[i];
        if (h->type != REX_PT_LOAD || !(h->flags & REX_PF_X)) continue;
        if (vaddr < h->vaddr || vaddr - h->vaddr >= h->filesz) continue;
        uint64_t d = vaddr - h->vaddr;
        if (avail) *avail = (size_t)(h->filesz - d);
        return e->data + h->offset + d;
    }
    if (avail) *avail = 0;
    return NULL;
}
