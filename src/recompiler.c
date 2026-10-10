#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "recompiler.h"
#include "elfread.h"
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
    if (rex_elf_open(inpath, &e, err, sizeof(err))) { fprintf(stderr, "rex: recompile: %s\n", err); return 1; }
    if (cfg_build(&e, &p, err, sizeof(err))) { fprintf(stderr, "rex: recompile: %s\n", err); rex_elf_free(&e); return 1; }
    IrModule *m = x86_lift(&p, err, sizeof(err));
    if (!m) { fprintf(stderr, "rex: recompile: %s\n", err); cfg_free(&p); rex_elf_free(&e); return 1; }
    CgResult cg;
    if (cg_emit_module(m, &cg, err, sizeof(err))) { fprintf(stderr, "rex: recompile: %s\n", err); ir_module_free(m); cfg_free(&p); rex_elf_free(&e); return 1; }

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
