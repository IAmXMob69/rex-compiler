#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "recompiler.h"
#include "loader.h"
#include "rex_err.h"
#include "cfg.h"
#include "x86_lift.h"
#include "codegen.h"

/* The original PT_LOAD segments are copied unchanged at their old
 * addresses: data, strings and globals stay where the code expects them.
 * The new code goes in its own segment above them and the entry point
 * moves there. The old code bytes remain mapped, so function pointers
 * taken by the program still work (they run the original code).
 */

static void put16(unsigned char *p, uint16_t v) { p[0] = v & 255; p[1] = v >> 8; }
static void put32(unsigned char *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (v >> (8 * i)) & 255; }
static void put64(unsigned char *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (v >> (8 * i)) & 255; }

int rex_recompile(const char *inpath, const char *outpath, int debug) {
    RexElf e;
    CfgProgram p;
    char err[256];
    { int _rc = rex_bin_open(inpath, &e, err, sizeof(err)); if (_rc) { fprintf(stderr, "rex: %s\n", err); return _rc; } }
    int is_pe = (e.type == 0xFE00);
    { int _c = cfg_build(&e, &p, err, sizeof(err)); if (_c) { fprintf(stderr, "rex: %s\n", err); rex_elf_free(&e); return _c; } }
    IrModule *m = x86_lift(&p, err, sizeof(err));
    if (!m) { fprintf(stderr, "rex: %s\n", err); cfg_free(&p); rex_elf_free(&e); return REX_E300_LIFT; }
    CgResult cg;
    if (cg_emit_module(m, &cg, err, sizeof(err))) { fprintf(stderr, "rex: %s\n", err); ir_module_free(m); cfg_free(&p); rex_elf_free(&e); return REX_E500_RECOMPILE; }

    if (is_pe) {
        /* Simple PE32+ rebuild: keep original sections, append a new RX
         * .rextext with recompiled code, point AddressOfEntryPoint there.
         * No imports/relocs (loader already refused those). */
        uint64_t image_base = 0;
        for (int i = 0; i < e.nph; i++)
            if (!image_base || e.ph[i].vaddr < image_base) image_base = e.ph[i].vaddr & ~0xfffull;
        if (!image_base) image_base = 0x140000000ULL;
        uint64_t top = 0;
        for (int i = 0; i < e.nph; i++) {
            uint64_t end = e.ph[i].vaddr + e.ph[i].memsz;
            if (end > top) top = end;
        }
        uint32_t new_rva = (uint32_t)(((top - image_base) + 0xfff) & ~0xfffull);
        if (new_rva == 0) new_rva = 0x1000;
        uint64_t new_va = image_base + new_rva;
        /* Resolve call relocs into the new section. */
        for (int i = 0; i < cg.nrelocs; i++) {
            uint64_t t = cg.relocs[i].target;
            uint64_t dest = t;
            for (int f = 0; f < m->nfuncs; f++) if (m->funcs[f].addr == t) { dest = new_va + cg.func_off[f]; break; }
            int64_t rel = (int64_t)dest - (int64_t)(new_va + (uint64_t)cg.relocs[i].at + 4);
            if (rel < -2147483648LL || rel > 2147483647LL) {
                fprintf(stderr, "rex: recompile: PE call out of range\n"); goto fail;
            }
            int32_t v = (int32_t)rel;
            memcpy(cg.code + cg.relocs[i].at, &v, 4);
        }
        int fe = -1;
        for (int f = 0; f < m->nfuncs; f++) if (m->funcs[f].addr == e.entry) fe = f;
        if (fe < 0) { fprintf(stderr, "rex: recompile: PE entry function missing\n"); goto fail; }

        uint32_t file_align = 0x200, sect_align = 0x1000;
        uint32_t nsec = (uint32_t)e.nph + 1;
        uint32_t e_lfanew = 0x80;
        uint16_t optsize = 112 + 15 * 8;
        size_t sec_table = (size_t)e_lfanew + 4 + 20 + optsize;
        size_t headers = (sec_table + (size_t)nsec * 40 + (file_align - 1)) & ~(size_t)(file_align - 1);
        size_t *raw_off = calloc(nsec, sizeof(size_t));
        if (!raw_off) goto fail;
        size_t off = headers;
        for (uint32_t i = 0; i < (uint32_t)e.nph; i++) {
            raw_off[i] = off;
            size_t sz = (size_t)e.ph[i].filesz;
            off = (off + sz + file_align - 1) & ~(size_t)(file_align - 1);
        }
        raw_off[e.nph] = off;
        size_t code_raw = (cg.len + file_align - 1) & ~(size_t)(file_align - 1);
        size_t total = off + code_raw;
        unsigned char *img = calloc(total, 1);
        if (!img) { free(raw_off); goto fail; }
        img[0] = 'M'; img[1] = 'Z';
        put32(img + 0x3c, e_lfanew);
        img[e_lfanew] = 'P'; img[e_lfanew+1] = 'E';
        unsigned char *coff = img + e_lfanew + 4;
        put16(coff + 0, 0x8664);
        put16(coff + 2, (uint16_t)nsec);
        put16(coff + 16, optsize);
        put16(coff + 18, 0x22); /* EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE */
        unsigned char *opt = coff + 20;
        put16(opt, 0x20b);
        put32(opt + 16, new_rva + (uint32_t)cg.func_off[fe]); /* EntryPoint */
        put64(opt + 24, image_base);
        put32(opt + 32, sect_align);
        put32(opt + 36, file_align);
        put16(opt + 48, 6); /* MajorOperatingSystemVersion */
        put32(opt + 56, new_rva + (uint32_t)((cg.len + sect_align - 1) & ~(sect_align - 1))); /* SizeOfImage */
        put32(opt + 60, (uint32_t)headers);
        put16(opt + 68, 3); /* console */
        put32(opt + 108, 15);
        for (uint32_t i = 0; i < (uint32_t)e.nph; i++) {
            unsigned char *sec = img + sec_table + (size_t)i * 40;
            const char *nm = (e.sh && e.sh[i].name[0]) ? e.sh[i].name : ".raw";
            memset(sec, 0, 40);
            memcpy(sec, nm, strlen(nm) < 8 ? strlen(nm) : 8);
            uint32_t vsize = (uint32_t)e.ph[i].memsz;
            uint32_t vaddr = (uint32_t)(e.ph[i].vaddr - image_base);
            put32(sec + 8, vsize);
            put32(sec + 12, vaddr);
            put32(sec + 16, (uint32_t)e.ph[i].filesz);
            put32(sec + 20, (uint32_t)raw_off[i]);
            uint32_t ch = 0x40000000; /* IMAGE_SCN_MEM_READ */
            if (e.ph[i].flags & REX_PF_X) { ch |= 0x20000000 | 0x20; } /* EXEC|CODE */
            if (e.ph[i].flags & REX_PF_W) ch |= 0x80000000; /* WRITE */
            if (!(e.ph[i].flags & REX_PF_X)) ch |= 0x40; /* IDATA */
            put32(sec + 36, ch);
            if (e.ph[i].filesz)
                memcpy(img + raw_off[i], e.data + e.ph[i].offset, (size_t)e.ph[i].filesz);
        }
        {
            unsigned char *sec = img + sec_table + (size_t)e.nph * 40;
            memcpy(sec, ".rextext", 8);
            put32(sec + 8, (uint32_t)cg.len);
            put32(sec + 12, new_rva);
            put32(sec + 16, (uint32_t)code_raw);
            put32(sec + 20, (uint32_t)raw_off[e.nph]);
            put32(sec + 36, 0x60000020); /* CODE|EXEC|READ */
            memcpy(img + raw_off[e.nph], cg.code, cg.len);
        }
        /* Fix SizeOfImage properly */
        put32(opt + 56, new_rva + (uint32_t)((cg.len + sect_align - 1) & ~(uint32_t)(sect_align - 1)));
        FILE *fo = fopen(outpath, "wb");
        if (!fo || fwrite(img, 1, total, fo) != total) {
            fprintf(stderr, "rex: recompile: cannot write %s\n", outpath);
            if (fo) fclose(fo);
            free(img); free(raw_off); goto fail;
        }
        fclose(fo);
        free(img); free(raw_off);
        if (debug & 1)
            fprintf(stderr, "rex: recompile: PE %d functions, %zu code bytes at RVA 0x%x\n",
                    m->nfuncs, cg.len, new_rva);
        cg_free(&cg); ir_module_free(m); cfg_free(&p); rex_elf_free(&e);
        return 0;
    }

    uint64_t top = 0;
    int nload = 0;
    for (int i = 0; i < e.nph; i++) {
        if (e.ph[i].type != REX_PT_LOAD) continue;
        nload++;
        if (e.ph[i].vaddr + e.ph[i].memsz > top) top = e.ph[i].vaddr + e.ph[i].memsz;
    }
    uint64_t newbase = ((top + 0xfff) & ~0xfffull) + 0x100000;
    if (newbase + cg.len >= 0x7fffffffull) { fprintf(stderr, "rex: recompile: image too high for 32-bit addressing\n"); goto fail; }

    /* Resolve calls: lifted function -> new code, anything else -> original address. */
    for (int i = 0; i < cg.nrelocs; i++) {
        uint64_t t = cg.relocs[i].target;
        uint64_t dest = t;
        for (int f = 0; f < m->nfuncs; f++) if (m->funcs[f].addr == t) { dest = newbase + cg.func_off[f]; break; }
        int64_t rel = (int64_t)dest - (int64_t)(newbase + (uint64_t)cg.relocs[i].at + 4);
        if (rel < -2147483648LL || rel > 2147483647LL) { fprintf(stderr, "rex: recompile: call out of range\n"); goto fail; }
        int32_t v = (int32_t)rel;
        memcpy(cg.code + cg.relocs[i].at, &v, 4);
    }
    int fe = -1;
    for (int f = 0; f < m->nfuncs; f++) if (m->funcs[f].addr == e.entry) fe = f;
    if (fe < 0) { fprintf(stderr, "rex: recompile: entry function missing\n"); goto fail; }

    int nph = nload + 1;
    size_t hdr = 64 + (size_t)nph * 56;
    size_t off = (hdr + 0xfff) & ~(size_t)0xfff;
    size_t *segoff = calloc((size_t)e.nph + 1, sizeof(size_t));
    if (!segoff) goto fail;
    for (int i = 0; i < e.nph; i++) {
        if (e.ph[i].type != REX_PT_LOAD) continue;
        segoff[i] = off + (size_t)(e.ph[i].vaddr & 0xfff);
        off = (segoff[i] + (size_t)e.ph[i].filesz + 0xfff) & ~(size_t)0xfff;
    }
    size_t codeoff = off;
    size_t total = codeoff + cg.len;
    unsigned char *img = calloc(total, 1);
    if (!img) { free(segoff); goto fail; }
    memcpy(img, "\177ELF", 4); img[4] = 2; img[5] = 1; img[6] = 1;
    put16(img + 16, 2); put16(img + 18, 62); put32(img + 20, 1);
    put64(img + 24, newbase + cg.func_off[fe]);
    put64(img + 32, 64);
    put16(img + 52, 64); put16(img + 54, 56); put16(img + 56, (uint16_t)nph);
    unsigned char *ph = img + 64;
    for (int i = 0; i < e.nph; i++) {
        const RexPhdr *h = &e.ph[i];
        if (h->type != REX_PT_LOAD) continue;
        put32(ph, 1); put32(ph + 4, h->flags);
        put64(ph + 8, segoff[i]); put64(ph + 16, h->vaddr); put64(ph + 24, h->vaddr);
        put64(ph + 32, h->filesz); put64(ph + 40, h->memsz); put64(ph + 48, 0x1000);
        memcpy(img + segoff[i], e.data + h->offset, (size_t)h->filesz);
        ph += 56;
    }
    put32(ph, 1); put32(ph + 4, REX_PF_R | REX_PF_X);
    put64(ph + 8, codeoff); put64(ph + 16, newbase); put64(ph + 24, newbase);
    put64(ph + 32, cg.len); put64(ph + 40, cg.len); put64(ph + 48, 0x1000);
    memcpy(img + codeoff, cg.code, cg.len);
    /* --poison: fill the old code with int3 to prove the new code is what runs. */
    if (debug & 2) {
        for (int f = 0; f < p.nfuncs; f++)
            for (int k = 0; k < p.funcs[f].ninsns; k++) {
                const X86Insn *in = &p.funcs[f].insns[k];
                for (int i = 0; i < e.nph; i++) {
                    const RexPhdr *h = &e.ph[i];
                    if (h->type == REX_PT_LOAD && in->addr >= h->vaddr && in->addr + (uint64_t)in->size <= h->vaddr + h->filesz)
                        memset(img + segoff[i] + (in->addr - h->vaddr), 0xcc, (size_t)in->size);
                }
            }
    }
    free(segoff);

    FILE *fo = fopen(outpath, "wb");
    if (!fo || fwrite(img, 1, total, fo) != total) { fprintf(stderr, "rex: recompile: cannot write %s\n", outpath); if (fo) fclose(fo); free(img); goto fail; }
    fclose(fo);
    chmod(outpath, 0755);
    free(img);
    if (debug & 1) {
        int nb = 0, ni = 0;
        for (int f = 0; f < m->nfuncs; f++) { nb += m->funcs[f].nblocks; for (int b = 0; b < m->funcs[f].nblocks; b++) ni += m->funcs[f].blocks[b].ninsns; }
        fprintf(stderr, "rex: recompile: %d functions, %d blocks, %d IR instructions, %zu code bytes at 0x%llx\n",
                m->nfuncs, nb, ni, cg.len, (unsigned long long)newbase);
        for (int f = 0; f < m->nfuncs; f++)
            fprintf(stderr, "  %-14s 0x%llx -> 0x%llx\n", m->funcs[f].name, (unsigned long long)m->funcs[f].addr,
                    (unsigned long long)(newbase + cg.func_off[f]));
    }
    cg_free(&cg); ir_module_free(m); cfg_free(&p); rex_elf_free(&e);
    return 0;
fail:
    cg_free(&cg); ir_module_free(m); cfg_free(&p); rex_elf_free(&e);
    return 1;
}
