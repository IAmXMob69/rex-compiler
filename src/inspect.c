#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "loader.h"
#include "rex_err.h"
#include "x86_decode.h"
#include "cfg.h"
#include "x86_lift.h"

/* rex inspect / rex disasm. Read-only: the input is never run. */

static const char *ptype(uint32_t t) {
    switch (t) {
    case 0: return "NULL"; case 1: return "LOAD"; case 2: return "DYNAMIC"; case 3: return "INTERP";
    case 4: return "NOTE"; case 6: return "PHDR"; case 7: return "TLS";
    case 0x6474e550: return "GNU_EH_FRAME"; case 0x6474e551: return "GNU_STACK"; case 0x6474e552: return "GNU_RELRO";
    case 0x6474e553: return "GNU_PROPERTY";
    default: return "OTHER";
    }
}

static void pflags(uint32_t f, char *b) {
    b[0] = (f & REX_PF_R) ? 'r' : '-';
    b[1] = (f & REX_PF_W) ? 'w' : '-';
    b[2] = (f & REX_PF_X) ? 'x' : '-';
    b[3] = 0;
}

int rex_cmd_inspect(const char *path) {
    RexElf e;
    char err[256];
    { int _rc = rex_bin_open(path, &e, err, sizeof(err)); if (_rc) { fprintf(stderr, "rex: %s\n", err); return _rc; } }
    if (e.type == 0xFE00)
        printf("PE32+ x86-64\n");
    else
        printf("ELF64 x86-64 executable\n");
    printf("Entry: 0x%llx\n", (unsigned long long)e.entry);
    printf("Size: %zu bytes\n", e.size);
    printf("Executable segments: %d\n", rex_elf_exec_segments(&e));
    printf("%s: %d\n", e.type == 0xFE00 ? "Sections" : "Program headers", e.nph);
    for (int i = 0; i < e.nph; i++) {
        const RexPhdr *h = &e.ph[i];
        char f[4];
        pflags(h->flags, f);
        const char *lab = (e.type == 0xFE00 && i < e.nsh && e.sh[i].name[0]) ? e.sh[i].name : ptype(h->type);
        printf("  %-12s %s  off 0x%06llx  vaddr 0x%08llx  filesz 0x%06llx  memsz 0x%06llx\n", lab, f,
               (unsigned long long)h->offset, (unsigned long long)h->vaddr,
               (unsigned long long)h->filesz, (unsigned long long)h->memsz);
    }
    if (e.type != 0xFE00) printf("Sections: %d\n", e.nsh);
    for (int i = 0; e.type != 0xFE00 && i < e.nsh; i++) {
        const RexShdr *s = &e.sh[i];
        printf("  [%2d] %-20s type %-3u addr 0x%08llx  off 0x%06llx  size 0x%06llx\n", i, s->name[0] ? s->name : "-",
               s->type, (unsigned long long)s->addr, (unsigned long long)s->offset, (unsigned long long)s->size);
    }
    rex_elf_free(&e);
    return 0;
}

static void disasm_range(const RexElf *e, uint64_t va, const unsigned char *p, size_t n) {
    size_t i = 0;
    while (i < n) {
        X86Insn in;
        uint64_t a = va + i;
        int len = x86_decode(p + i, n - i, a, &in);
        if (a == e->entry) printf("\n<entry>:\n");
        if (len <= 0) {
            printf("  %8llx:  %02x                     .byte 0x%02x\n", (unsigned long long)a, p[i], p[i]);
            i++;
            continue;
        }
        char text[160], hex[64];
        size_t k = 0;
        for (int j = 0; j < len && k + 4 < sizeof(hex); j++) k += (size_t)snprintf(hex + k, sizeof(hex) - k, "%02x ", p[i + (size_t)j]);
        x86_format(&in, text, sizeof(text));
        printf("  %8llx:  %-22s %s\n", (unsigned long long)a, hex, text);
        i += (size_t)len;
    }
}

static void print_func(const CfgFunc *f) {
    printf("%s @0x%llx: %d blocks, %d instructions\n", f->name, (unsigned long long)f->addr, f->nblocks, f->ninsns);
    for (int b = 0; b < f->nblocks; b++) {
        const CfgBlock *bl = &f->blocks[b];
        printf("  block %d  0x%llx-0x%llx  ->", b, (unsigned long long)bl->start, (unsigned long long)bl->end);
        if (!bl->nsucc) printf(bl->exits ? " exit" : " return");
        for (int k = 0; k < bl->nsucc; k++) printf(" %d", bl->succ[k]);
        printf("\n");
        for (int i = 0; i < bl->n; i++) {
            char text[160];
            x86_format(&f->insns[bl->first + i], text, sizeof(text));
            printf("    %8llx:  %s\n", (unsigned long long)f->insns[bl->first + i].addr, text);
        }
    }
}

/* name: start, main, fn_ADDR, or a hex address. */
static int pick_func(const CfgProgram *p, const char *name) {
    if (!strcmp(name, "main")) return p->main_addr ? cfg_find_func(p, p->main_addr) : -1;
    for (int i = 0; i < p->nfuncs; i++) if (!strcmp(p->funcs[i].name, name)) return i;
    char *end;
    unsigned long long a = strtoull(name, &end, 16);
    if (*name && !*end) return cfg_find_func(p, a);
    return -1;
}

int rex_cmd_disasm_func(const char *path, const char *fname) {
    RexElf e;
    CfgProgram p;
    char err[256];
    { int _rc = rex_bin_open(path, &e, err, sizeof(err)); if (_rc) { fprintf(stderr, "rex: %s\n", err); return _rc; } }
    { int _c = cfg_build(&e, &p, err, sizeof(err)); if (_c) { fprintf(stderr, "rex: %s\n", err); rex_elf_free(&e); return _c; } }
    int rc = 0;
    if (!fname) {
        for (int i = 0; i < p.nfuncs; i++) print_func(&p.funcs[i]);
    } else {
        int k = pick_func(&p, fname);
        if (k < 0) { fprintf(stderr, "rex: disasm: no function '%s'\n", fname); rc = 1; }
        else print_func(&p.funcs[k]);
    }
    cfg_free(&p);
    rex_elf_free(&e);
    return rc;
}

int rex_cmd_disasm(const char *path) {
    RexElf e;
    char err[256];
    { int _rc = rex_bin_open(path, &e, err, sizeof(err)); if (_rc) { fprintf(stderr, "rex: %s\n", err); return _rc; } }
    for (int s = 0; s < e.nph; s++) {
        const RexPhdr *h = &e.ph[s];
        if (h->type != REX_PT_LOAD || !(h->flags & REX_PF_X) || h->filesz == 0) continue;
        uint64_t start = 0;
        /* Skip the ELF and program headers when they sit inside the segment. */
        if (h->offset == 0) {
            uint64_t hdr = 64 + (uint64_t)e.nph * 56;
            uint64_t phoff = 0;
            memcpy(&phoff, e.data + 32, 8);
            if (phoff + (uint64_t)e.nph * 56 > hdr) hdr = phoff + (uint64_t)e.nph * 56;
            start = hdr < h->filesz ? hdr : h->filesz;
        }
        printf("segment %d: 0x%llx-0x%llx\n", s, (unsigned long long)(h->vaddr + start),
               (unsigned long long)(h->vaddr + h->filesz));
        disasm_range(&e, h->vaddr + start, e.data + h->offset + start, (size_t)(h->filesz - start));
    }
    rex_elf_free(&e);
    return 0;
}

int rex_cmd_ir(const char *path, const char *fname) {
    RexElf e;
    CfgProgram p;
    char err[256];
    { int _rc = rex_bin_open(path, &e, err, sizeof(err)); if (_rc) { fprintf(stderr, "rex: %s\n", err); return _rc; } }
    { int _c = cfg_build(&e, &p, err, sizeof(err)); if (_c) { fprintf(stderr, "rex: %s\n", err); rex_elf_free(&e); return _c; } }
    IrModule *m = x86_lift(&p, err, sizeof(err));
    int rc = 0;
    if (!m) { fprintf(stderr, "rex: %s\n", err); rc = REX_E300_LIFT; }
    else {
        int k = fname ? pick_func(&p, fname) : -1;
        if (fname && k < 0) { fprintf(stderr, "rex: ir: no function '%s'\n", fname); rc = 1; }
        for (int i = 0; i < m->nfuncs && !rc; i++) if (!fname || i == k) ir_print_func(stdout, m, &m->funcs[i]);
        ir_module_free(m);
    }
    cfg_free(&p);
    rex_elf_free(&e);
    return rc;
}
