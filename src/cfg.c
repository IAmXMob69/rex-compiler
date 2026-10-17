#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cfg.h"
#include "rex_err.h"

static int fail(char *err, size_t n, const char *fmt, ...) {
    char body[192];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);
    return rex_errf(err, n, REX_E400_CFG, "%s", body);
}

typedef struct { uint64_t *v; int n, cap; } AddrList;

static int al_push(AddrList *l, uint64_t a) {
    if (l->n == l->cap) {
        int nc = l->cap ? l->cap * 2 : 64;
        if (nc > CFG_MAX_INSNS * 2) return -1;
        uint64_t *nv = realloc(l->v, (size_t)nc * sizeof(uint64_t));
        if (!nv) return -1;
        l->v = nv; l->cap = nc;
    }
    l->v[l->n++] = a;
    return 0;
}

/* Address set: open addressing, grows at half load. */
typedef struct { uint64_t *keys; int *vals; size_t cap, n; } Map;

static size_t hash(uint64_t a) { a ^= a >> 33; a *= 0xff51afd7ed558ccdull; a ^= a >> 33; return (size_t)a; }

static int map_get(const Map *m, uint64_t k) {
    if (!m->cap) return -1;
    for (size_t i = hash(k) & (m->cap - 1);; i = (i + 1) & (m->cap - 1)) {
        if (m->vals[i] < 0) return -1;
        if (m->keys[i] == k) return m->vals[i];
    }
}
static int map_put(Map *m, uint64_t k, int v) {
    if ((m->n + 1) * 2 > m->cap) {
        size_t nc = m->cap ? m->cap * 2 : 256;
        uint64_t *nk = malloc(nc * sizeof(uint64_t));
        int *nv = malloc(nc * sizeof(int));
        if (!nk || !nv) { free(nk); free(nv); return -1; }
        for (size_t i = 0; i < nc; i++) nv[i] = -1;
        for (size_t i = 0; i < m->cap; i++) {
            if (m->vals[i] < 0) continue;
            size_t j = hash(m->keys[i]) & (nc - 1);
            while (nv[j] >= 0) j = (j + 1) & (nc - 1);
            nk[j] = m->keys[i]; nv[j] = m->vals[i];
        }
        free(m->keys); free(m->vals);
        m->keys = nk; m->vals = nv; m->cap = nc;
    }
    size_t i = hash(k) & (m->cap - 1);
    while (m->vals[i] >= 0 && m->keys[i] != k) i = (i + 1) & (m->cap - 1);
    if (m->vals[i] < 0) m->n++;
    m->keys[i] = k; m->vals[i] = v;
    return 0;
}
static void map_free(Map *m) { free(m->keys); free(m->vals); memset(m, 0, sizeof(*m)); }

/* exit(2) or exit_group(2): mov $60/$231 into rax/eax right before syscall. */
int cfg_is_exit(const X86Insn *prev, const X86Insn *in) {
    if (in->op != X86_SYSCALL || !prev || prev->op != X86_MOV) return 0;
    const X86Operand *d = &prev->ops[0], *s = &prev->ops[1];
    return d->kind == XO_REG && d->reg == 0 && d->size >= 4 && s->kind == XO_IMM && (s->imm == 60 || s->imm == 231);
}

static int cmp_insn(const void *a, const void *b) {
    uint64_t x = ((const X86Insn *)a)->addr, y = ((const X86Insn *)b)->addr;
    return x < y ? -1 : x > y;
}

int cfg_find_block(const CfgFunc *f, uint64_t addr) {
    int lo = 0, hi = f->nblocks - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (f->blocks[mid].start == addr) return mid;
        if (f->blocks[mid].start < addr) lo = mid + 1; else hi = mid - 1;
    }
    return -1;
}

int cfg_find_func(const CfgProgram *p, uint64_t addr) {
    for (int i = 0; i < p->nfuncs; i++) if (p->funcs[i].addr == addr) return i;
    return -1;
}

static int jump_table(const RexElf *e, const X86Insn *in, const X86Insn *hist, int nhist, CfgJumpTable *jt);

/* Function symbols a jmp may tail-call: STT_FUNC entries in code, except gcc's
 * .cold parts, which share their parent's frame and jump back into it. */
static void seed_tail_targets(const RexElf *e, AddrList *out) {
    for (int si = 0; si < e->nsh; si++) {
        const RexShdr *s = &e->sh[si];
        if (s->type != 2 && s->type != 11) continue;
        if (s->size == 0 || s->size % 24) continue;
        const char *want = s->type == 11 ? ".dynstr" : ".strtab";
        int str = -1;
        for (int j = 0; j < e->nsh; j++)
            if (e->sh[j].type == 3 && !strcmp(e->sh[j].name, want)) { str = j; break; }
        if (str < 0) continue;
        const RexShdr *st = &e->sh[str];
        for (uint64_t off = 0; off + 24 <= s->size; off += 24) {
            const unsigned char *sym = e->data + s->offset + off;
            uint32_t name = (uint32_t)sym[0] | (uint32_t)sym[1]<<8 | (uint32_t)sym[2]<<16 | (uint32_t)sym[3]<<24;
            uint64_t val = 0; for (int k = 0; k < 8; k++) val |= (uint64_t)sym[8+k] << (8*k);
            if ((sym[4] & 0xf) != 2 || !val || name >= st->size) continue;
            const char *nm = (const char *)(e->data + st->offset + name);
            size_t left = st->size - name, k = 0;
            int cold = 0;
            while (k < left && nm[k]) { if (k + 5 <= left && !strncmp(nm + k, ".cold", 5)) cold = 1; k++; }
            if (cold || !rex_elf_code_at(e, val, NULL)) continue;
            al_push(out, val);
        }
    }
}

static int tail_target(const RexElf *e, const AddrList *ft, uint64_t t, uint64_t self) {
    if (t == self) return 0;
    if (rex_elf_import_at(e, t)) return 1;          /* jmp puts@plt */
    for (int i = 0; ft && i < ft->n; i++) if (ft->v[i] == t) return 1;
    return 0;
}

int cfg_is_tail(const CfgFunc *f, uint64_t insn_addr) {
    for (int i = 0; i < f->ntails; i++) if (f->tails[i] == insn_addr) return 1;
    return 0;
}

static int build_func(const RexElf *e, CfgFunc *f, AddrList *calls, const AddrList *ft, char *err, size_t errlen) {
    Map seen = {0};
    AddrList work = {0}, leaders = {0};
    X86Insn *ins = NULL;
    int n = 0, cap = 0, rc = -1;
    if (al_push(&work, f->addr) || al_push(&leaders, f->addr)) goto oom;
    while (work.n) {
        uint64_t a = work.v[--work.n];
        const X86Insn *prev = NULL;
        X86Insn prevbuf;
        X86Insn hist[4]; int nhist = 0;
        for (;;) {
            if (map_get(&seen, a) >= 0) break;
            size_t avail;
            const unsigned char *p = rex_elf_code_at(e, a, &avail);
            if (!p) { rex_errf(err, errlen, REX_E403_NO_CODE, "%s: code at 0x%llx is outside executable segments", f->name, (unsigned long long)a); goto out; }
            if (n >= CFG_MAX_INSNS) { fail(err, errlen, "%s: too many instructions", f->name); goto out; }
            if (n == cap) {
                int nc = cap ? cap * 2 : 256;
                X86Insn *ni = realloc(ins, (size_t)nc * sizeof(X86Insn));
                if (!ni) goto oom;
                ins = ni; cap = nc;
            }
            X86Insn *in = &ins[n];
            if (!x86_decode(p, avail, a, in)) {
                rex_errf(err, errlen, REX_E200_OPCODE, "%s: unsupported or invalid instruction at 0x%llx (byte %02x)", f->name, (unsigned long long)a, p[0]);
                goto out;
            }
            if (map_put(&seen, a, n)) goto oom;
            n++;
            uint64_t next = a + (uint64_t)in->size;
            if (in->op == X86_RET || in->op == X86_HLT || in->op == X86_UD2) break;
            if (in->op == X86_JMP) {
                if (in->ops[0].kind != XO_REL) {
                    CfgJumpTable jt;
                    int jr = jump_table(e, in, hist, nhist, &jt);
                    /* jmp *reg that is not a table dispatch: an indirect tail jump
                     * (crt code does this). The block ends with no successors. */
                    const X86Operand *jo = &in->ops[0];
                    int tablelike = jo->kind == XO_MEM && jo->index != X86_NOREG && jo->scale == 8;
                    if (jr == 1 && !tablelike) break;   /* also PLT-style jmp *GOT(%rip) */
                    if (jr) {
                        rex_errf(err, errlen, REX_E401_INDIRECT_JMP, "%s: indirect jump at 0x%llx (%s)", f->name,
                                 (unsigned long long)in->addr,
                                 jr == 1 ? "no bounds check right before it" : jr == 2 ? "table is not in a read-only section" :
                                 "a table entry is not code");
                        goto out;
                    }
                    CfgJumpTable *nj = realloc(f->jt, (size_t)(f->njt + 1) * sizeof(*nj));
                    if (!nj) { free(jt.targets); goto oom; }
                    f->jt = nj; f->jt[f->njt++] = jt;
                    for (int k = 0; k < jt.n; k++)
                        if (al_push(&work, jt.targets[k]) || al_push(&leaders, jt.targets[k])) goto oom;
                    break;
                }
                /* jmp to another function's entry is a tail call: the block ends
                 * here and the target stays a function of its own. */
                if (tail_target(e, ft, in->ops[0].target, f->addr)) {
                    uint64_t *nt = realloc(f->tails, (size_t)(f->ntails + 1) * sizeof(*nt));
                    if (!nt) goto oom;
                    f->tails = nt; f->tails[f->ntails++] = in->addr;
                    if (!rex_elf_import_at(e, in->ops[0].target) && al_push(calls, in->ops[0].target)) goto oom;
                    break;
                }
                if (al_push(&work, in->ops[0].target) || al_push(&leaders, in->ops[0].target)) goto oom;
                break;
            }
            if (in->op == X86_JCC) {
                if (al_push(&work, in->ops[0].target) || al_push(&leaders, in->ops[0].target) || al_push(&leaders, next)) goto oom;
            }
            /* A call to a PLT stub is a library call (puts, printf), not a function of ours. */
            if (in->op == X86_CALL && in->ops[0].kind == XO_REL && !rex_elf_import_at(e, in->ops[0].target) &&
                al_push(calls, in->ops[0].target)) goto oom;
            if ((in->op == X86_LEA || in->op == X86_MOV) && in->nops >= 2) {
                const X86Operand *so = &in->ops[1];
                uint64_t t = 0;
                if (so->kind == XO_MEM && so->base == X86_RIP) t = so->target;
                if (t && !rex_elf_import_at(e, t)) {
                    size_t av = 0;
                    const unsigned char *p = rex_elf_code_at(e, t, &av);
                    if (p && av >= 1 && (p[0] == 0x55 || (av >= 4 && p[0] == 0xf3 && p[1] == 0x0f))) {
                        if (al_push(calls, t)) goto oom;
                    }
                }
            }
            if (cfg_is_exit(prev, in)) { if (al_push(&leaders, next)) goto oom; break; }
            prevbuf = *in;
            prev = &prevbuf;
            if (nhist == 4) { memmove(hist, hist + 1, 3 * sizeof(X86Insn)); nhist = 3; }
            hist[nhist++] = *in;
            a = next;
        }
    }
    qsort(ins, (size_t)n, sizeof(X86Insn), cmp_insn);
    for (int i = 0; i + 1 < n; i++)
        if (ins[i].addr + (uint64_t)ins[i].size > ins[i + 1].addr) {
            fail(err, errlen, "%s: overlapping instructions at 0x%llx", f->name, (unsigned long long)ins[i + 1].addr);
            goto out;
        }
    map_free(&seen);
    for (int i = 0; i < n; i++) if (map_put(&seen, ins[i].addr, i)) goto oom;
    for (int i = 0; i < leaders.n; i++) {
        if (map_get(&seen, leaders.v[i]) < 0 && leaders.v[i] != f->addr) {
            /* fallthrough past an exit or the end of a jcc chain that was never decoded */
            continue;
        }
    }
    /* Mark block starts. */
    char *start = calloc((size_t)n + 1, 1);
    if (!start && n) goto oom;
    for (int i = 0; i < leaders.n; i++) { int k = map_get(&seen, leaders.v[i]); if (k >= 0) start[k] = 1; }
    for (int i = 0; i < n; i++) {
        X86Opcode op = ins[i].op;
        int term = op == X86_RET || op == X86_HLT || op == X86_UD2 || op == X86_JMP || op == X86_JCC || (i > 0 && cfg_is_exit(&ins[i - 1], &ins[i]));
        if (term && i + 1 < n) start[i + 1] = 1;
        if (i > 0 && ins[i - 1].addr + (uint64_t)ins[i - 1].size != ins[i].addr) start[i] = 1;
    }
    if (n) start[0] = 1;
    int nb = 0;
    for (int i = 0; i < n; i++) nb += start[i];
    f->blocks = calloc((size_t)(nb ? nb : 1), sizeof(CfgBlock));
    if (!f->blocks) { free(start); goto oom; }
    int b = -1;
    for (int i = 0; i < n; i++) {
        if (start[i]) { b++; f->blocks[b].first = i; f->blocks[b].start = ins[i].addr; }
        f->blocks[b].n++;
        f->blocks[b].end = ins[i].addr + (uint64_t)ins[i].size;
    }
    free(start);
    f->nblocks = nb;
    f->insns = ins; f->ninsns = n;
    ins = NULL;
    for (int i = 0; i < nb; i++) {
        CfgBlock *bl = &f->blocks[i];
        const X86Insn *last = &f->insns[bl->first + bl->n - 1];
        const X86Insn *pl = bl->n > 1 ? last - 1 : (bl->first > 0 ? last - 1 : NULL);
        bl->nsucc = 0;
        if (last->op == X86_RET || last->op == X86_HLT || last->op == X86_UD2) continue;
        if (last->op == X86_JMP && last->ops[0].kind != XO_REL) continue; /* indirect: unknown targets */
        if (last->op == X86_JMP && cfg_is_tail(f, last->addr)) continue;   /* tail call: returns for us */
        if (pl && cfg_is_exit(pl, last)) { bl->exits = 1; continue; }
        if (last->op == X86_JMP || last->op == X86_JCC) {
            int t = cfg_find_block(f, last->ops[0].target);
            if (t < 0) { fail(err, errlen, "%s: jump into the middle of an instruction at 0x%llx", f->name, (unsigned long long)last->addr); goto out; }
            bl->succ[bl->nsucc++] = t;
            if (last->op == X86_JMP) continue;
        }
        if (i + 1 >= nb || f->blocks[i + 1].start != bl->end) {
            fail(err, errlen, "%s: block at 0x%llx falls into undecoded bytes", f->name, (unsigned long long)bl->start);
            goto out;
        }
        if (bl->nsucc == 0 || bl->succ[0] != i + 1) bl->succ[bl->nsucc++] = i + 1;
    }
    rc = 0;
    goto out;
oom:
    fail(err, errlen, "out of memory");
out:
    free(ins);
    free(work.v);
    free(leaders.v);
    map_free(&seen);
    return rc;
}

/* Bound from "cmp|sub x, N-1; ja default" in the recent history. */
static int ja_bound(const X86Insn *hist, int nhist, int reg) {
    for (int k = nhist - 1; k >= 1; k--) {
        const X86Insn *ja = &hist[k], *cmp = &hist[k - 1];
        if (ja->op != X86_JCC || ja->cc != 7) continue;
        if (cmp->op != X86_CMP && !(reg < 0 && cmp->op == X86_SUB)) return -1;
        if (cmp->ops[0].kind != XO_REG || (reg >= 0 && cmp->ops[0].reg != reg) || cmp->ops[1].kind != XO_IMM) return -1;
        if (cmp->ops[1].imm < 0 || cmp->ops[1].imm > 1024) return -1;
        return (int)cmp->ops[1].imm + 1;
    }
    return -1;
}

/* Non-PIE gcc/clang switch tables:
 *   cmp r, N-1; ja default; [mov r32,r32]; jmp *T(,r,8)            (gcc, clang -O1+)
 *   cmp|sub x, N-1; ja default; ...; mov q, T(,i,8); jmp *q          (clang -O0)
 * T must lie in a read-only allocated section and every entry must be code.
 * Returns 0 and fills jt, or 1 no bound / unknown shape, 2 table not
 * read-only, 3 bad entry. */
static int jump_table(const RexElf *e, const X86Insn *in, const X86Insn *hist, int nhist, CfgJumpTable *jt) {
    const X86Operand *o = &in->ops[0];
    memset(jt, 0, sizeof(*jt));
    int n, reg, byaddr = 0;
    if (o->kind == XO_REG && o->size == 8) {
        if (nhist < 1) return 1;
        const X86Insn *ld = &hist[nhist - 1];
        if (ld->op != X86_MOV || ld->ops[0].kind != XO_REG || ld->ops[0].reg != o->reg || ld->ops[1].kind != XO_MEM) return 1;
        reg = o->reg; byaddr = 1;
        o = &ld->ops[1];
        if (o->base != X86_NOREG || o->index == X86_NOREG || o->scale != 8) return 1;
        n = ja_bound(hist, nhist - 1, -1);
    } else {
        if (o->kind != XO_MEM || o->base != X86_NOREG || o->index == X86_NOREG || o->scale != 8) return 1;
        reg = o->index;
        n = ja_bound(hist, nhist, reg);
        /* only harmless moves after the bound check */
        for (int j = nhist - 1; j >= 0 && n > 0; j--) {
            const X86Insn *m = &hist[j];
            if (m->op == X86_JCC) break;
            int same = m->op == X86_MOV && m->ops[0].kind == XO_REG && m->ops[1].kind == XO_REG && m->ops[0].reg == reg && m->ops[1].reg == reg;
            int other = m->nops >= 1 && m->ops[0].kind == XO_REG && m->ops[0].reg != reg && m->op != X86_CALL;
            if (!same && !other) return 1;
        }
    }
    if (n < 0) return 1;
    uint64_t t = (uint64_t)o->disp;
    const RexShdr *sec = NULL;
    for (int i = 0; i < e->nsh; i++) {
        const RexShdr *s = &e->sh[i];
        if ((s->flags & 2) && !(s->flags & 1) && s->type != 8 && t >= s->addr && t + 8 * (uint64_t)n <= s->addr + s->size) sec = s;
    }
    if (!sec) return 2;
    uint64_t off = sec->offset + (t - sec->addr);
    if (off + 8 * (uint64_t)n > e->size) return 2;
    jt->targets = malloc((size_t)n * sizeof(uint64_t));
    if (!jt->targets) return 3;
    for (int k = 0; k < n; k++) {
        uint64_t v;
        memcpy(&v, e->data + off + 8 * (uint64_t)k, 8);
        size_t av;
        if (!rex_elf_code_at(e, v, &av) || v > 0x7fffffff) { free(jt->targets); jt->targets = NULL; return 3; }
        jt->targets[k] = v;
    }
    jt->at = in->addr; jt->reg = reg; jt->n = n; jt->byaddr = byaddr;
    return 0;
}

static void cfg_func_free(CfgFunc *f) {
    free(f->insns); free(f->blocks); free(f->tails);
    for (int k = 0; k < f->njt; k++) free(f->jt[k].targets);
    free(f->jt);
    memset(f, 0, sizeof(*f));
}

void cfg_free(CfgProgram *p) {
    for (int i = 0; i < p->nfuncs; i++) cfg_func_free(&p->funcs[i]);
    free(p->funcs);
    memset(p, 0, sizeof(*p));
}


static void seed_symbols(const RexElf *e, AddrList *calls) {
    /* Best-effort: SHT_SYMTAB -> .strtab, SHT_DYNSYM -> .dynstr. */
    for (int si = 0; si < e->nsh; si++) {
        const RexShdr *s = &e->sh[si];
        if (s->type != 2 && s->type != 11) continue; /* SYMTAB / DYNSYM */
        if (s->size == 0 || s->size % 24) continue;   /* ELF64 Elf64_Sym = 24 */
        const char *want = s->type == 11 ? ".dynstr" : ".strtab";
        int str = -1;
        for (int j = 0; j < e->nsh; j++)
            if (e->sh[j].type == 3 && !strcmp(e->sh[j].name, want)) { str = j; break; }
        if (str < 0) continue;
        const RexShdr *st = &e->sh[str];
        for (uint64_t off = 0; off + 24 <= s->size; off += 24) {
            const unsigned char *sym = e->data + s->offset + off;
            uint32_t name = (uint32_t)sym[0] | (uint32_t)sym[1]<<8 | (uint32_t)sym[2]<<16 | (uint32_t)sym[3]<<24;
            unsigned char info = sym[4];
            uint64_t val = 0; for (int k = 0; k < 8; k++) val |= (uint64_t)sym[8+k] << (8*k);
            if (!val || name >= st->size) continue;
            unsigned type = info & 0xf;
            if (type != 2) continue; /* STT_FUNC */
            size_t av = 0;
            if (!rex_elf_code_at(e, val, &av) || av < 1) continue;
            al_push(calls, val);
        }
    }
}

int cfg_build(const RexElf *e, CfgProgram *p, char *err, size_t errlen) {
    memset(p, 0, sizeof(*p));
    AddrList calls = {0}, ft = {0};
    if (al_push(&calls, e->entry)) return fail(err, errlen, "out of memory");
    seed_tail_targets(e, &ft);
    p->funcs = calloc(CFG_MAX_FUNCS, sizeof(CfgFunc));
    if (!p->funcs) { free(calls.v); free(ft.v); return fail(err, errlen, "out of memory"); }
    /* Phase 1: everything reachable from the entry through direct calls and
     * jump tables. A failure here is fatal — this code really runs. */
    for (int ci = 0; ci < calls.n; ci++) {
        uint64_t a = calls.v[ci];
        if (cfg_find_func(p, a) >= 0) continue;
        if (p->nfuncs >= CFG_MAX_FUNCS) { cfg_free(p); free(calls.v); free(ft.v); return fail(err, errlen, "too many functions"); }
        CfgFunc *f = &p->funcs[p->nfuncs];
        memset(f, 0, sizeof(*f));
        f->addr = a;
        f->reachable = 1;
        if (a == e->entry) snprintf(f->name, sizeof(f->name), "start");
        else snprintf(f->name, sizeof(f->name), "fn_%llx", (unsigned long long)a);
        if (build_func(e, f, &calls, &ft, err, errlen)) { cfg_func_free(f); cfg_free(p); free(calls.v); free(ft.v); return -1; }
        p->nfuncs++;
        if (a == e->entry) {
            for (int i = 0; i < f->ninsns; i++)
                if (f->insns[i].op == X86_CALL && f->insns[i].ops[0].kind == XO_REL &&
                    !rex_elf_import_at(e, f->insns[i].ops[0].target)) { p->main_addr = f->insns[i].ops[0].target; break; }
        }
    }
    /* Phase 2: functions named only by the symbol table and not reached above
     * (library helpers like memcpy the linker pulled in). Build them so their
     * names and bodies are available, but if one uses something we can't model
     * yet, drop just that function instead of failing the whole program —
     * nothing reachable calls it. */
    AddrList syms = {0};
    seed_symbols(e, &syms);
    for (int si = 0; si < syms.n; si++) {
        uint64_t a = syms.v[si];
        if (cfg_find_func(p, a) >= 0) continue;
        if (p->nfuncs >= CFG_MAX_FUNCS) break;
        CfgFunc *f = &p->funcs[p->nfuncs];
        memset(f, 0, sizeof(*f));
        f->addr = a;
        f->reachable = 0;
        snprintf(f->name, sizeof(f->name), "fn_%llx", (unsigned long long)a);
        char tmperr[256];
        if (build_func(e, f, &syms, &ft, tmperr, sizeof(tmperr))) { cfg_func_free(f); continue; }
        p->nfuncs++;
    }
    free(syms.v);
    /* Name functions from symbols; set main_addr if main is present. */
    for (int si = 0; si < e->nsh; si++) {
        const RexShdr *sec = &e->sh[si];
        if (sec->type != 2 && sec->type != 11) continue;
        if (sec->size == 0 || sec->size % 24) continue;
        const char *want = sec->type == 11 ? ".dynstr" : ".strtab";
        int str = -1;
        for (int j = 0; j < e->nsh; j++)
            if (e->sh[j].type == 3 && !strcmp(e->sh[j].name, want)) { str = j; break; }
        if (str < 0) continue;
        const RexShdr *st = &e->sh[str];
        for (uint64_t off = 0; off + 24 <= sec->size; off += 24) {
            const unsigned char *sym = e->data + sec->offset + off;
            uint32_t name = (uint32_t)sym[0] | (uint32_t)sym[1]<<8 | (uint32_t)sym[2]<<16 | (uint32_t)sym[3]<<24;
            unsigned type = sym[4] & 0xf;
            uint64_t val = 0; for (int k = 0; k < 8; k++) val |= (uint64_t)sym[8+k] << (8*k);
            if (type != 2 || !val || name >= st->size) continue;
            const char *nm = (const char *)(e->data + st->offset + name);
            size_t maxlen = st->size - name;
            /* Stop at NUL or @ (versioned symbols). */
            char buf[64]; size_t k = 0;
            while (k + 1 < sizeof(buf) && k < maxlen && nm[k] && nm[k] != '@') {
                unsigned char c = (unsigned char)nm[k];
                buf[k] = (c >= 32 && c < 127) ? (char)c : '_'; k++;
            }
            buf[k] = 0;
            if (!k) continue;
            if (!strcmp(buf, "main")) p->main_addr = val;
            for (int fi = 0; fi < p->nfuncs; fi++)
                if (p->funcs[fi].addr == val) {
                    snprintf(p->funcs[fi].name, sizeof(p->funcs[fi].name), "%.*s", (int)sizeof(p->funcs[fi].name) - 1, buf);
                }
        }
    }
    free(calls.v);
    free(ft.v);
    return 0;
}
