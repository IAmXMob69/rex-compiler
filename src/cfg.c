#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cfg.h"

static int fail(char *err, size_t n, const char *fmt, ...) {
    if (err && n) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err, n, fmt, ap);
        va_end(ap);
    }
    return -1;
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

static int build_func(const RexElf *e, CfgFunc *f, AddrList *calls, char *err, size_t errlen) {
    Map seen = {0};
    AddrList work = {0}, leaders = {0};
    X86Insn *ins = NULL;
    int n = 0, cap = 0, rc = -1;
    if (al_push(&work, f->addr) || al_push(&leaders, f->addr)) goto oom;
    while (work.n) {
        uint64_t a = work.v[--work.n];
        const X86Insn *prev = NULL;
        X86Insn prevbuf;
        for (;;) {
            if (map_get(&seen, a) >= 0) break;
            size_t avail;
            const unsigned char *p = rex_elf_code_at(e, a, &avail);
            if (!p) { fail(err, errlen, "%s: code at 0x%llx is outside executable segments", f->name, (unsigned long long)a); goto out; }
            if (n >= CFG_MAX_INSNS) { fail(err, errlen, "%s: too many instructions", f->name); goto out; }
            if (n == cap) {
                int nc = cap ? cap * 2 : 256;
                X86Insn *ni = realloc(ins, (size_t)nc * sizeof(X86Insn));
                if (!ni) goto oom;
                ins = ni; cap = nc;
            }
            X86Insn *in = &ins[n];
            if (!x86_decode(p, avail, a, in)) {
                fail(err, errlen, "%s: unsupported or invalid instruction at 0x%llx (byte %02x)", f->name, (unsigned long long)a, p[0]);
                goto out;
            }
            if (map_put(&seen, a, n)) goto oom;
            n++;
            uint64_t next = a + (uint64_t)in->size;
            if (in->op == X86_RET) break;
            if (in->op == X86_JMP) {
                if (in->ops[0].kind != XO_REL) { fail(err, errlen, "%s: indirect jump at 0x%llx", f->name, (unsigned long long)a); goto out; }
                if (al_push(&work, in->ops[0].target) || al_push(&leaders, in->ops[0].target)) goto oom;
                break;
            }
            if (in->op == X86_JCC) {
                if (al_push(&work, in->ops[0].target) || al_push(&leaders, in->ops[0].target) || al_push(&leaders, next)) goto oom;
            }
            if (in->op == X86_CALL && in->ops[0].kind == XO_REL && al_push(calls, in->ops[0].target)) goto oom;
            if (cfg_is_exit(prev, in)) { if (al_push(&leaders, next)) goto oom; break; }
            prevbuf = *in;
            prev = &prevbuf;
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
        int term = op == X86_RET || op == X86_JMP || op == X86_JCC || (i > 0 && cfg_is_exit(&ins[i - 1], &ins[i]));
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
        if (last->op == X86_RET) continue;
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

void cfg_free(CfgProgram *p) {
    for (int i = 0; i < p->nfuncs; i++) { free(p->funcs[i].insns); free(p->funcs[i].blocks); }
    free(p->funcs);
    memset(p, 0, sizeof(*p));
}

int cfg_build(const RexElf *e, CfgProgram *p, char *err, size_t errlen) {
    memset(p, 0, sizeof(*p));
    AddrList calls = {0};
    if (al_push(&calls, e->entry)) return fail(err, errlen, "out of memory");
    p->funcs = calloc(CFG_MAX_FUNCS, sizeof(CfgFunc));
    if (!p->funcs) { free(calls.v); return fail(err, errlen, "out of memory"); }
    for (int ci = 0; ci < calls.n; ci++) {
        uint64_t a = calls.v[ci];
        if (cfg_find_func(p, a) >= 0) continue;
        if (p->nfuncs >= CFG_MAX_FUNCS) { cfg_free(p); free(calls.v); return fail(err, errlen, "too many functions"); }
        CfgFunc *f = &p->funcs[p->nfuncs++];
        f->addr = a;
        if (a == e->entry) snprintf(f->name, sizeof(f->name), "start");
        else snprintf(f->name, sizeof(f->name), "fn_%llx", (unsigned long long)a);
        if (build_func(e, f, &calls, err, errlen)) { cfg_free(p); free(calls.v); return -1; }
        if (a == e->entry) {
            for (int i = 0; i < f->ninsns; i++)
                if (f->insns[i].op == X86_CALL && f->insns[i].ops[0].kind == XO_REL) { p->main_addr = f->insns[i].ops[0].target; break; }
        }
    }
    free(calls.v);
    return 0;
}
