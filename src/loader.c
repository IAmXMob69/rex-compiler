#include "loader.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- PE32+ x86-64 loader (sections -> synthetic PT_LOAD) ---- */

static uint16_t pe_u16(const unsigned char *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}
static uint32_t pe_u32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t pe_u64(const unsigned char *p) {
    return (uint64_t)pe_u32(p) | ((uint64_t)pe_u32(p + 4) << 32);
}

static int pe_probe(const unsigned char *data, size_t len) {
    if (len < 0x40) return 0;
    if (data[0] != 'M' || data[1] != 'Z') return 0;
    uint32_t e_lfanew = pe_u32(data + 0x3c);
    if (e_lfanew > len - 4 || e_lfanew + 4 > len) return 0;
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

/* Map PE section characteristics to PF_* */
static uint32_t pe_sec_flags(uint32_t ch) {
    uint32_t f = 0;
    if (ch & 0x40000000u) f |= REX_PF_R;   /* IMAGE_SCN_MEM_READ */
    if (ch & 0x80000000u) f |= REX_PF_W;   /* IMAGE_SCN_MEM_WRITE */
    if (ch & 0x20000000u) f |= REX_PF_X;   /* IMAGE_SCN_MEM_EXECUTE */
    if (!f) f = REX_PF_R;
    return f;
}

static int pe_parse(const unsigned char *data, size_t len, RexElf *out, char *err, size_t errlen) {
    memset(out, 0, sizeof(*out));
    if (!pe_probe(data, len))
        return rex_errf(err, errlen, REX_E100_UNRECOGNIZED, "not a PE/COFF file");
    uint32_t e_lfanew = pe_u32(data + 0x3c);
    if (e_lfanew + 4 + 20 > len)
        return rex_errf(err, errlen, REX_E101_PE_STUB, "PE/COFF header truncated");
    const unsigned char *coff = data + e_lfanew + 4;
    uint16_t machine = pe_u16(coff + 0);
    uint16_t nsec = pe_u16(coff + 2);
    uint16_t optsize = pe_u16(coff + 16);
    if (machine != 0x8664)
        return rex_errf(err, errlen, REX_E104_PE_MACHINE,
                        "PE/COFF machine %s (0x%x); only x86-64", pe_machine(machine), machine);
    if (e_lfanew + 4 + 20 + optsize > len || optsize < 2)
        return rex_errf(err, errlen, REX_E101_PE_STUB, "PE optional header truncated");
    const unsigned char *opt = coff + 20;
    uint16_t magic = pe_u16(opt);
    if (magic == 0x10b)
        return rex_errf(err, errlen, REX_E105_PE_MAGIC, "PE32 (32-bit); only PE32+");
    if (magic != 0x20b)
        return rex_errf(err, errlen, REX_E105_PE_MAGIC, "bad optional magic 0x%x", magic);
    /* PE32+ optional: EntryPoint RVA @16, ImageBase @24, SizeOfImage @56, SizeOfHeaders @60,
     * Subsystem @68, DllCharacteristics @70, NumberOfRvaAndSizes @108, data dirs @112. */
    if (optsize < 112)
        return rex_errf(err, errlen, REX_E101_PE_STUB, "PE32+ optional header too small (%u)", optsize);
    uint32_t entry_rva = pe_u32(opt + 16);
    uint64_t image_base = pe_u64(opt + 24);
    uint32_t size_of_image = pe_u32(opt + 56);
    uint32_t size_of_headers = pe_u32(opt + 60);
    uint16_t subsystem = pe_u16(opt + 68);
    uint32_t ndirs = pe_u32(opt + 108);
    (void)subsystem;
    /* Data directories: 0 export, 1 import, 2 resource, 5 basereloc, 9 TLS, 14 CLR */
    uint32_t import_rva = 0, import_size = 0, reloc_rva = 0, reloc_size = 0;
    uint32_t tls_rva = 0, clr_rva = 0;
    if (ndirs >= 2 && optsize >= 112 + 2 * 8) {
        import_rva = pe_u32(opt + 112 + 1 * 8);
        import_size = pe_u32(opt + 112 + 1 * 8 + 4);
    }
    if (ndirs >= 6 && optsize >= 112 + 6 * 8) {
        reloc_rva = pe_u32(opt + 112 + 5 * 8);
        reloc_size = pe_u32(opt + 112 + 5 * 8 + 4);
    }
    if (ndirs >= 10 && optsize >= 112 + 10 * 8)
        tls_rva = pe_u32(opt + 112 + 9 * 8);
    if (ndirs >= 15 && optsize >= 112 + 15 * 8)
        clr_rva = pe_u32(opt + 112 + 14 * 8);

    if (clr_rva)
        return rex_errf(err, errlen, REX_E109_PE_DOTNET, "CLR runtime header present");
    if (tls_rva)
        return rex_errf(err, errlen, REX_E108_PE_TLS, "TLS directory RVA 0x%x", tls_rva);
    /* Relocations: refuse if the image is not known to be loadable at ImageBase without them.
     * For a simple static image with no reloc dir, OK. If reloc dir is non-empty, refuse for now. */
    if (reloc_rva && reloc_size)
        return rex_errf(err, errlen, REX_E107_PE_RELOCS,
                        "base relocations present (RVA 0x%x size %u)", reloc_rva, reloc_size);
    /* Imports: allow empty import table (fully static). Non-empty -> E106 for now so we stay honest
     * about not resolving IAT; look/show/ir of .text still work if we choose to load anyway.
     * Spec: "Imports/... get explicit E1xx refusals" — refuse when import directory non-empty. */
    if (import_rva && import_size)
        return rex_errf(err, errlen, REX_E106_PE_IMPORTS,
                        "import directory present (RVA 0x%x); static images only for now", import_rva);

    size_t sec_off = (size_t)e_lfanew + 4 + 20 + optsize;
    if (nsec > 96)
        return rex_errf(err, errlen, REX_E110_PE_PACKED, "too many sections (%u)", nsec);
    if (sec_off + (size_t)nsec * 40 > len)
        return rex_errf(err, errlen, REX_E101_PE_STUB, "section table out of bounds");

    /* Packed heuristic: no executable section, or SizeOfHeaders wildly small with huge first section gap. */
    int nexec = 0;
    for (int i = 0; i < nsec; i++) {
        const unsigned char *sec = data + sec_off + (size_t)i * 40;
        uint32_t ch = pe_u32(sec + 36);
        if (ch & 0x20000000u) nexec++;
    }
    if (nexec == 0)
        return rex_errf(err, errlen, REX_E110_PE_PACKED, "no executable section");

    RexElf e = {0};
    e.type = 2; /* pretend ET_EXEC */
    e.machine = 62; /* EM_X86_64 */
    e.entry = image_base + entry_rva;
    e.nph = nsec;
    e.ph = calloc((size_t)nsec, sizeof(RexPhdr));
    e.nsh = nsec;
    e.sh = calloc((size_t)nsec, sizeof(RexShdr));
    if (!e.ph || !e.sh) {
        free(e.ph); free(e.sh);
        return rex_errf(err, errlen, REX_E101_PE_STUB, "out of memory");
    }
    int entry_ok = 0;
    for (int i = 0; i < nsec; i++) {
        const unsigned char *sec = data + sec_off + (size_t)i * 40;
        char name[9];
        memcpy(name, sec, 8); name[8] = 0;
        uint32_t vsize = pe_u32(sec + 8);
        uint32_t vaddr = pe_u32(sec + 12);
        uint32_t rawsz = pe_u32(sec + 16);
        uint32_t rawptr = pe_u32(sec + 20);
        uint32_t ch = pe_u32(sec + 36);
        if (rawsz && (rawptr > len || rawsz > len - rawptr)) {
            rex_elf_free(&e);
            return rex_errf(err, errlen, REX_E101_PE_STUB, "section %d raw data out of bounds", i);
        }
        RexPhdr *h = &e.ph[i];
        h->type = REX_PT_LOAD;
        h->flags = pe_sec_flags(ch);
        h->offset = rawptr;
        h->vaddr = image_base + vaddr;
        h->filesz = rawsz;
        h->memsz = vsize > rawsz ? vsize : rawsz;
        h->align = 0x1000;
        RexShdr *sh = &e.sh[i];
        snprintf(sh->name, sizeof(sh->name), "%s", name);
        sh->type = 1;
        sh->flags = h->flags;
        sh->addr = h->vaddr;
        sh->offset = rawptr;
        sh->size = rawsz ? rawsz : vsize;
        if ((h->flags & REX_PF_X) && e.entry >= h->vaddr && e.entry - h->vaddr < (h->filesz ? h->filesz : h->memsz))
            entry_ok = 1;
    }
    if (!entry_ok) {
        /* Entry in headers (rare) or wrong — still allow if any RX section exists and entry inside image. */
        if (e.entry < image_base || e.entry - image_base >= size_of_image) {
            rex_elf_free(&e);
            return rex_errf(err, errlen, REX_E101_PE_STUB,
                            "entry 0x%llx not inside image", (unsigned long long)e.entry);
        }
    }
    (void)size_of_headers;
    e.data = malloc(len);
    if (!e.data) { rex_elf_free(&e); return rex_errf(err, errlen, REX_E101_PE_STUB, "out of memory"); }
    memcpy(e.data, data, len);
    e.size = len;
    /* Mark as PE for inspect: reuse type field high bit? Use machine+name via inspect.
     * Store a tag in unused way: e.type = 0xFE00 means PE. */
    e.type = 0xFE00;
    *out = e;
    return 0;
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
        return rex_errf(err, errlen, REX_E100_UNRECOGNIZED,
                        "unrecognized binary format%s%s", hx[0] ? ": " : "", hx);
    }
    return L->parse(data, len, out, err, errlen);
}

int rex_bin_open(const char *path, RexElf *out, char *err, size_t errlen) {
    memset(out, 0, sizeof(*out));
    FILE *f = fopen(path, "rb");
    if (!f) return rex_errf(err, errlen, REX_E103_IO, "%s: %s", path, strerror(errno));
    size_t cap = 1 << 16, len = 0;
    unsigned char *buf = malloc(cap);
    if (!buf) { fclose(f); return rex_errf(err, errlen, REX_E103_IO, "out of memory"); }
    for (;;) {
        if (len == cap) {
            if (cap >= REX_ELF_MAX_FILE + 1) { free(buf); fclose(f); return rex_errf(err, errlen, REX_E103_IO, "%s: file too large", path); }
            size_t nc = cap * 2;
            if (nc > REX_ELF_MAX_FILE + 1) nc = REX_ELF_MAX_FILE + 1;
            unsigned char *nb = realloc(buf, nc);
            if (!nb) { free(buf); fclose(f); return rex_errf(err, errlen, REX_E103_IO, "out of memory"); }
            buf = nb; cap = nc;
        }
        size_t r = fread(buf + len, 1, cap - len, f);
        len += r;
        if (r == 0) break;
    }
    int ioerr = ferror(f);
    fclose(f);
    if (ioerr) { free(buf); return rex_errf(err, errlen, REX_E103_IO, "%s: read error", path); }
    int rc = rex_bin_parse(buf, len, out, err, errlen);
    free(buf);
    return rc;
}
