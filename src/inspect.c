#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "elfread.h"
#include "x86_decode.h"

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
    if (rex_elf_open(path, &e, err, sizeof(err))) { fprintf(stderr, "rex: inspect: %s\n", err); return 1; }
    printf("ELF64 x86-64 executable\n");
    printf("Entry: 0x%llx\n", (unsigned long long)e.entry);
    printf("Size: %zu bytes\n", e.size);
    printf("Executable segments: %d\n", rex_elf_exec_segments(&e));
    printf("Program headers: %d\n", e.nph);
    for (int i = 0; i < e.nph; i++) {
        const RexPhdr *h = &e.ph[i];
        char f[4];
        pflags(h->flags, f);
        printf("  %-12s %s  off 0x%06llx  vaddr 0x%08llx  filesz 0x%06llx  memsz 0x%06llx\n", ptype(h->type), f,
               (unsigned long long)h->offset, (unsigned long long)h->vaddr,
               (unsigned long long)h->filesz, (unsigned long long)h->memsz);
    }
    printf("Sections: %d\n", e.nsh);
    for (int i = 0; i < e.nsh; i++) {
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

int rex_cmd_disasm(const char *path) {
    RexElf e;
    char err[256];
    if (rex_elf_open(path, &e, err, sizeof(err))) { fprintf(stderr, "rex: disasm: %s\n", err); return 1; }
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
