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
static int pie_table(const RexElf *e, const X86Insn *in, const X86Insn *hist, int nhist, const X86Insn *done, int ndone, CfgJumpTable *jt);
enum { HIST = 12 };   /* straight-line history kept for table matching */

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
        X86Insn hist[HIST]; int nhist = 0;
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
                    int h4 = nhist < 4 ? nhist : 4;
                    int jr = jump_table(e, in, hist + nhist - h4, h4, &jt);
                    if (jr == 1) {
                        int pr = pie_table(e, in, hist, nhist, ins, n - 1, &jt);
                        if (pr != 1) jr = pr;
                    }
                    const X86Operand *jo = &in->ops[0];
                    int tablelike = jo->kind == XO_MEM && jo->index != X86_NOREG && jo->scale == 8;
                    if (jr == 1 && !tablelike) {
                        /* Not a table REX can read. Only a target taken from a global
                         * slot (a function pointer or GOT entry: jmp *g(%rip), or
                         * mov g(%rip),%r; jmp *%r in the same straight line) or a
                         * constant (mov $addr,%r, as the C runtime does) is an
                         * indirect tail call: call it and return its result.
                         * Anything else may be a switch or a computed goto into this
                         * function, and is refused. */
                        int global = jo->kind == XO_MEM && jo->index == X86_NOREG && (jo->base == X86_RIP || jo->base == X86_NOREG);
                        if (jo->kind == XO_REG)
                            for (int k = nhist - 1; k >= 0; k--) {
                                const X86Insn *w = &hist[k];
                                if (w->op == X86_JMP || w->op == X86_JCC || w->op == X86_CALL) break;
                                if (w->nops < 1 || w->ops[0].kind != XO_REG || w->ops[0].reg != jo->reg ||
                                    w->op == X86_CMP || w->op == X86_TEST || w->op == X86_PUSH) continue;
                                if (w->op == X86_MOV && w->ops[0].size == 8 && w->ops[1].kind == XO_MEM && w->ops[1].index == X86_NOREG &&
                                    (w->ops[1].base == X86_RIP || w->ops[1].base == X86_NOREG)) global = 1;
                                if (w->op == X86_MOV && w->ops[0].size >= 4 && w->ops[1].kind == XO_IMM) global = 1;   /* a constant address */
                                break;
                            }
                        if (!global && !f->reachable) {
                            /* a symbol-only helper (C runtime code): left unfollowed
                             * as before; if main turns out to reach it, it is built
                             * again as code that runs, and this refuses */
                            f->lenient++;
                            break;
                        }
                        if (!global) {
                            rex_errf(err, errlen, REX_E401_INDIRECT_JMP, "%s: indirect jump at 0x%llx (its target is not a table REX can read)",
                                     f->name, (unsigned long long)in->addr);
                            goto out;
                        }
                        uint64_t *nt = realloc(f->tails, (size_t)(f->ntails + 1) * sizeof(*nt));
                        if (!nt) goto oom;
                        f->tails = nt; f->tails[f->ntails++] = in->addr;
                        break;
                    }
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
            if (nhist == HIST) { memmove(hist, hist + 1, (HIST - 1) * sizeof(X86Insn)); nhist = HIST - 1; }
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
    /* A PIE table's bounds check holds only if the code from it to the jmp is
     * entered by falling through the ja: one block, no other way in. */
    for (int k = 0; k < f->njt; k++) {
        const CfgJumpTable *jt = &f->jt[k];
        if (!jt->guard) continue;
        int b = cfg_find_block(f, jt->guard), bad = b <= 0 || f->blocks[b].end <= jt->at;
        for (int i = 0; i < nb && !bad; i++)
            for (int s = 0; s < f->blocks[i].nsucc; s++)
                if (f->blocks[i].succ[s] == b && i != b - 1) bad = 1;
        for (int q = 0; q < f->njt && !bad; q++)
            for (int t = 0; t < f->jt[q].n; t++) if (f->jt[q].targets[t] == jt->guard) bad = 1;
        if (!bad) {
            const CfgBlock *pb = &f->blocks[b - 1];
            const X86Insn *ja = &f->insns[pb->first + pb->n - 1];
            if (pb->end != jt->guard || ja->op != X86_JCC || ja->cc != 7) bad = 1;
            /* what the match read before the ja (the bound, a zero-extending write,
             * the slot the bounded value was saved to) is in the ja's own block */
            if (jt->dep < pb->start) bad = 1;
        }
        if (!bad && jt->hoisted) {
            /* The table address register was set by one lea outside the code
             * evaluated: that lea must dominate the jmp, and nothing on any path
             * from it to the jmp may write the register (no call either). */
            int lb = -1, li = -1, jb = -1, nlea = 0;
            for (int i = 0; i < nb; i++) {
                const CfgBlock *bl = &f->blocks[i];
                for (int q = bl->first; q < bl->first + bl->n; q++) {
                    const X86Insn *w = &f->insns[q];
                    if (w->addr == jt->at) jb = i;
                    if (w->op == X86_LEA && w->ops[0].kind == XO_REG && w->ops[0].reg == jt->breg) {
                        nlea++;
                        if (w->ops[0].size == 8 && w->ops[1].kind == XO_MEM && w->ops[1].base == X86_RIP && w->ops[1].target == jt->base) { lb = i; li = q; }
                    }
                }
            }
            if (nlea != 1 || lb < 0 || jb < 0 || lb == jb) bad = 1;
            char *fw = bad ? NULL : calloc((size_t)nb, 1), *bw = bad ? NULL : calloc((size_t)nb, 1);
            int *stk = bad ? NULL : malloc((size_t)(nb + 1) * sizeof(int)), sp = 0;
            if (!bad && (!fw || !bw || !stk)) bad = 1;
            if (!bad) {
                /* dominance: from the entry, avoiding the lea's block, the jmp is unreachable */
                char *vis = fw;
                if (lb != 0) {
                    stk[sp++] = 0; vis[0] = 1;
                    while (sp) {
                        int v = stk[--sp];
                        for (int s2 = 0; s2 < f->blocks[v].nsucc; s2++) {
                            int t = f->blocks[v].succ[s2];
                            if (t == lb || vis[t]) continue;
                            vis[t] = 1; stk[sp++] = t;
                        }
                    }
                    if (vis[jb]) bad = 1;
                }
                memset(fw, 0, (size_t)nb);
            }
            if (!bad) {
                /* blocks on a path lea -> jmp: forward from the lea's block and backward from the jmp's, not through the lea's */
                for (int s2 = 0; s2 < f->blocks[lb].nsucc; s2++) { int t = f->blocks[lb].succ[s2]; if (t != lb && !fw[t]) { fw[t] = 1; stk[sp++] = t; } }
                while (sp) {
                    int v = stk[--sp];
                    for (int s2 = 0; s2 < f->blocks[v].nsucc; s2++) { int t = f->blocks[v].succ[s2]; if (t != lb && !fw[t]) { fw[t] = 1; stk[sp++] = t; } }
                }
                bw[jb] = 1; stk[sp++] = jb;
                while (sp) {
                    int v = stk[--sp];
                    for (int u = 0; u < nb; u++) {
                        if (u == lb || bw[u]) continue;
                        for (int s2 = 0; s2 < f->blocks[u].nsucc; s2++) if (f->blocks[u].succ[s2] == v) { bw[u] = 1; stk[sp++] = u; break; }
                    }
                }
                for (int i = 0; i < nb && !bad; i++) {
                    if (i != lb && !(fw[i] && bw[i])) continue;
                    const CfgBlock *bl = &f->blocks[i];
                    int q0 = i == lb ? li + 1 : bl->first;
                    for (int q = q0; q < bl->first + bl->n && !bad; q++) {
                        const X86Insn *w = &f->insns[q];
                        if (w->addr == jt->at) break;
                        if (w->op == X86_CALL || w->op == X86_SYSCALL || w->op == X86_CQO || w->op == X86_IDIV || w->op == X86_DIV || X86_IS_MUL1(w) ||
                            w->op == X86_XCHG || w->op == X86_POP || w->op == X86_LEAVE) {
                            if (w->op == X86_CALL || w->op == X86_SYSCALL || w->op == X86_XCHG || w->op == X86_POP || w->op == X86_LEAVE ||
                                jt->breg == 0 || jt->breg == 2) bad = 1;
                        }
                        if (w->nops >= 1 && w->ops[0].kind == XO_REG && !w->ops[0].xmm && w->ops[0].reg == jt->breg &&
                            w->op != X86_CMP && w->op != X86_TEST && w->op != X86_PUSH) bad = 1;
                    }
                    /* the lea's block: if the path leaves it before the lea is reached again it
                     * only matters after the lea, which is what was scanned */
                }
            }
            free(fw); free(bw); free(stk);
        }
        if (bad) {
            rex_errf(err, errlen, REX_E401_INDIRECT_JMP, "%s: indirect jump at 0x%llx (code can reach it past the bounds check)",
                     f->name, (unsigned long long)jt->at);
            goto out;
        }
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

/* PIE switch tables hold 32-bit offsets from the table itself:
 *   cmp $N-1, %eI; ja default; mov %eI,%eI; lea T(%rip),%rB;
 *       movslq (%rB,%rI,4),%rD; add %rB,%rD; jmp *%rD               (gcc, clang -O1+)
 *   mov %rI,M; sub $N-1,%rI; ja default; mov M,%rI; lea T(%rip),%rB;
 *       movslq (%rB,%rI,4),%rI; add %rB,%rI; jmp *%rI               (clang -O0)
 *   cmpl $N-1,M; ja default; mov M,%eax; lea 0(,%rax,4),%rS; lea T(%rip),%rX;
 *       mov (%rS,%rX),%eax; cltq; lea T(%rip),%rB; add %rB,%rax; jmp *%rax   (gcc -O0)
 * and the non-PIE tables the matcher above does not take, whose bound is on a
 * stack slot or a register written in the same block:
 *   cmpl $N-1,M; ja default; mov M,%eax; mov T(,%rax,8),%rax; jmp *%rax  (gcc -O0)
 *   cmp $N-1,%al; ja default; movzbl %al,%eax; jmp *T(,%rax,8)      (char switch)
 *   cmp $N-1,%edi; ja default; mov %edi,%r8d; jmp *T(,%r8,8)        (clang -O2)
 * The straight-line code from the ja to the jmp is evaluated symbolically:
 * every register is the bounded value V (zero-extended or only its low half),
 * 4*V, the table address T, a 32-bit entry T[V] (before or after sign
 * extension), T + T[V], or unknown. The jmp must go to T + T[V] with V bounded
 * by the ja; nothing in between may store, call or branch. Returns 0 and fills
 * jt (byaddr: the lift compares the target itself), 1 unknown shape, 2 table
 * not read-only, 3 bad entry. The caller checks no path skips the ja. */
enum { PV_UNK, PV_V32, PV_V64, PV_V4, PV_TB, PV_E32, PV_E64, PV_TGT, PV_ABS, PV_V8, PV_V16 };
static int same_mem(const X86Operand *a, const X86Operand *b) {
    return a->kind == XO_MEM && b->kind == XO_MEM && a->base == b->base && a->index == b->index &&
           a->scale == b->scale && a->disp == b->disp && a->base != X86_RIP;
}
static int pie_table(const RexElf *e, const X86Insn *in, const X86Insn *hist, int nhist, const X86Insn *done, int ndone, CfgJumpTable *jt) {
    memset(jt, 0, sizeof(*jt));
    const X86Operand *jo = &in->ops[0];
    int memform = jo->kind == XO_MEM && jo->base == X86_NOREG && jo->index >= 0 && jo->index < 16 && jo->scale == 8 && jo->disp > 0;
    if (!memform && (jo->kind != XO_REG || jo->size != 8)) return 1;
    int ka = -1;
    for (int k = nhist - 1; k >= 1; k--) {
        if (hist[k].op == X86_JCC) { if (hist[k].cc == 7) ka = k; break; }
    }
    if (ka < 1) return 1;
    const X86Insn *bc = &hist[ka - 1];
    if ((bc->op != X86_CMP && bc->op != X86_SUB) || bc->ops[1].kind != XO_IMM || bc->ops[1].imm < 0 || bc->ops[1].imm > 1024) return 1;
    int n = (int)bc->ops[1].imm + 1, vsz = bc->ops[0].size;
    uint64_t dep = bc->addr;
    int st[16]; uint64_t tb[16];
    int hoist = -1;
    for (int r = 0; r < 16; r++) { st[r] = PV_UNK; tb[r] = 0; }
    X86Operand vmem; int has_vmem = 0, vmsz = 0, vmzx = 0;   /* slot holding V: its size; 8 bytes of zero-extended V */
    if (bc->op == X86_CMP && bc->ops[0].kind == XO_REG && !bc->ops[0].xmm && !bc->ops[0].high8 && (vsz == 1 || vsz == 2)) {
        st[bc->ops[0].reg] = vsz == 1 ? PV_V8 : PV_V16;        /* char/short switch: made whole by movzx */
    } else if (bc->op == X86_CMP && bc->ops[0].kind == XO_REG && !bc->ops[0].xmm && !bc->ops[0].high8 && vsz >= 4) {
        int vr = bc->ops[0].reg, zx = vsz == 8;
        /* a 32-bit write zero-extends: if that is how the register got its
         * value, the bounded low half is the whole register */
        for (int k = ka - 2; k >= 0 && !zx; k--) {
            const X86Insn *w = &hist[k];
            if (w->op == X86_CMP || w->op == X86_TEST || w->op == X86_PUSH || w->nops < 1) continue;
            if (w->op == X86_JMP || w->op == X86_JCC || w->op == X86_CALL || w->op == X86_XCHG || w->op == X86_CQO ||
                w->op == X86_IDIV || w->op == X86_DIV || X86_IS_MUL1(w) || w->op == X86_POP) break;
            if (w->ops[0].kind == XO_REG && !w->ops[0].xmm && w->ops[0].reg == vr) {
                if (w->ops[0].size == 4 && !w->ops[0].high8) { zx = 1; dep = w->addr; }
                break;
            }
        }
        st[vr] = zx ? PV_V64 : PV_V32;
    }
    else if (bc->op == X86_CMP && bc->ops[0].kind == XO_MEM && bc->ops[0].base != X86_RIP && vsz >= 4) { vmem = bc->ops[0]; has_vmem = 1; vmsz = vsz; }
    else if (bc->op == X86_SUB && bc->ops[0].kind == XO_REG && ka >= 2 && vsz >= 4) {
        /* the value before the sub, kept in memory: stored from the register
         * itself, or from a 32-bit copy of it (which zero-extends) */
        const X86Insn *sv = &hist[ka - 2];
        int sr = bc->ops[0].reg;
        if (sv->op != X86_MOV || sv->ops[0].kind != XO_MEM || sv->ops[0].base == X86_RIP || sv->ops[1].kind != XO_REG || sv->ops[1].xmm) return 1;
        if (sv->ops[1].reg == sr && sv->ops[0].size == vsz) { vmsz = vsz; }
        else if (ka >= 3 && vsz == 4 && sv->ops[0].size == 8 && hist[ka - 3].op == X86_MOV && hist[ka - 3].ops[0].kind == XO_REG &&
                 hist[ka - 3].ops[0].reg == sv->ops[1].reg && hist[ka - 3].ops[0].size == 4 && hist[ka - 3].ops[1].kind == XO_REG &&
                 hist[ka - 3].ops[1].reg == sr && hist[ka - 3].ops[1].size == 4) { vmsz = 8; vmzx = 1; }
        else return 1;
        dep = vmzx ? hist[ka - 3].addr : sv->addr;
        vmem = sv->ops[0]; has_vmem = 1;
    } else return 1;
    for (int k = ka + 1; k < nhist; k++) {
        const X86Insn *x = &hist[k];
        const X86Operand *d = &x->ops[0], *s = &x->ops[1];
        if (x->op == X86_NOP || x->op == X86_ENDBR) continue;
        if (x->op == X86_JMP || x->op == X86_JCC || x->op == X86_CALL || x->op == X86_RET || x->op == X86_PUSH ||
            x->op == X86_POP || x->op == X86_LEAVE || x->op == X86_XCHG || x->op == X86_SYSCALL || x->op == X86_SSE ||
            x->op == X86_CQO || x->op == X86_IDIV || x->op == X86_DIV || X86_IS_MUL1(x)) return 1;
        if (x->nops >= 1 && d->kind == XO_MEM && x->op != X86_CMP && x->op != X86_TEST) return 1;   /* a store */
        if (x->nops < 1 || d->kind != XO_REG || x->op == X86_CMP || x->op == X86_TEST) continue;
        if (d->xmm || d->high8 || d->size < 4 || d->reg < 0 || d->reg > 15) {
            if (d->reg >= 0 && d->reg < 16 && !d->xmm) st[d->reg] = PV_UNK;
            continue;
        }
        int nv = PV_UNK; uint64_t nt = 0;
        if (x->op == X86_MOVZX && s->kind == XO_REG && !s->xmm && !s->high8 && s->reg >= 0 && s->reg < 16 &&
            ((st[s->reg] == PV_V8 && s->size == 1) || (st[s->reg] == PV_V16 && s->size == 2))) {
            nv = PV_V64;                              /* movzbl/movzwl of the bounded byte or word */
        } else if (x->op == X86_MOV && s->kind == XO_REG && !s->xmm && s->reg >= 0 && s->reg < 16) {
            int ss = st[s->reg];
            if ((ss == PV_V32 || ss == PV_V64) && d->size >= 4 && s->size >= 4) nv = PV_V64;
            else if (d->size == 8 && s->size == 8) { nv = ss; nt = tb[s->reg]; }
        } else if (x->op == X86_MOV && has_vmem && same_mem(s, &vmem) &&
                   (s->size == vmsz ? (vmsz == vsz || vmzx) : (s->size == 4 && vmzx))) {
            nv = PV_V64;                              /* reload of the bounded value; 32-bit loads zero-extend */
        } else if (x->op == X86_LEA && s->kind == XO_MEM && s->base == X86_RIP && d->size == 8) {
            nv = PV_TB; nt = s->target;
        } else if (x->op == X86_LEA && s->kind == XO_MEM && s->base == X86_NOREG && s->index >= 0 && s->index < 16 &&
                   st[s->index] == PV_V64 && s->scale == 4 && s->disp == 0 && d->size == 8) {
            nv = PV_V4;
        } else if ((x->op == X86_MOV && d->size == 4 && s->size == 4) || (x->op == X86_MOVSX && d->size == 8 && s->size == 4)) {
            if (s->kind == XO_MEM && s->base >= 0 && s->base < 16 && s->index >= 0 && s->index < 16 && s->disp == 0) {
                int b = st[s->base], i = st[s->index];
                uint64_t t = 0;
                if (b == PV_UNK && i == PV_V64 && s->scale == 4) {
                    /* table address set outside this straight-line code (hoisted out
                     * of a loop): the one lea into that register decoded so far. The
                     * caller proves it is the only write and that it dominates. */
                    uint64_t ht = 0; int cnt = 0;
                    for (int q = 0; q < ndone; q++) {
                        const X86Insn *w = &done[q];
                        if (w->op == X86_LEA && w->ops[0].kind == XO_REG && w->ops[0].reg == s->base && w->ops[0].size == 8 &&
                            w->ops[1].kind == XO_MEM && w->ops[1].base == X86_RIP) { ht = w->ops[1].target; cnt++; }
                    }
                    if (cnt == 1 && ht) { st[s->base] = PV_TB; tb[s->base] = ht; b = PV_TB; hoist = s->base; }
                }
                if (b == PV_TB && i == PV_V64 && s->scale == 4) t = tb[s->base];
                else if (s->scale == 1 && b == PV_TB && i == PV_V4) t = tb[s->base];
                else if (s->scale == 1 && b == PV_V4 && i == PV_TB) t = tb[s->index];
                if (t) { nv = x->op == X86_MOVSX ? PV_E64 : PV_E32; nt = t; }
            } else if (x->op == X86_MOVSX && s->kind == XO_REG && s->reg == d->reg && st[s->reg] == PV_E32) {
                nv = PV_E64; nt = tb[s->reg];     /* cltq */
            }
        } else if (x->op == X86_MOV && d->size == 8 && s->kind == XO_MEM && s->size == 8 && s->base == X86_NOREG &&
                   s->index >= 0 && s->index < 16 && st[s->index] == PV_V64 && s->scale == 8 && s->disp > 0) {
            nv = PV_ABS; nt = (uint64_t)s->disp;     /* non-PIE: 8-byte absolute entries */
        } else if (x->op == X86_ADD && s->kind == XO_REG && d->size == 8 && s->size == 8 && s->reg >= 0 && s->reg < 16) {
            int a = st[d->reg], b = st[s->reg];
            if (a == PV_E64 && b == PV_TB && tb[d->reg] == tb[s->reg]) { nv = PV_TGT; nt = tb[s->reg]; }
            else if (a == PV_TB && b == PV_E64 && tb[d->reg] == tb[s->reg]) { nv = PV_TGT; nt = tb[d->reg]; }
        }
        st[d->reg] = nv; tb[d->reg] = nt;
    }
    if (memform) {
        /* jmp *T(,%rI,8): the old compare-the-index lift, I being the whole bounded value */
        if (st[jo->index] != PV_V64) return 1;
        uint64_t t = (uint64_t)jo->disp;
        const RexShdr *sec = NULL;
        for (int i = 0; i < e->nsh; i++) {
            const RexShdr *sh = &e->sh[i];
            if ((sh->flags & 2) && !(sh->flags & 1) && sh->type != 8 && t >= sh->addr && t + 8 * (uint64_t)n <= sh->addr + sh->size) sec = sh;
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
        jt->at = in->addr; jt->reg = jo->index; jt->n = n; jt->byaddr = 0; jt->guard = hist[ka].addr + (uint64_t)hist[ka].size;
        jt->breg = -1; jt->dep = dep;
        return 0;
    }
    int r = in->ops[0].reg;
    if (r >= 0 && r < 16 && st[r] == PV_ABS) {
        uint64_t t = tb[r];
        const RexShdr *sec = NULL;
        for (int i = 0; i < e->nsh; i++) {
            const RexShdr *sh = &e->sh[i];
            if ((sh->flags & 2) && !(sh->flags & 1) && sh->type != 8 && t >= sh->addr && t + 8 * (uint64_t)n <= sh->addr + sh->size) sec = sh;
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
        jt->at = in->addr; jt->reg = r; jt->n = n; jt->byaddr = 1; jt->guard = hist[ka].addr + (uint64_t)hist[ka].size;
        jt->breg = -1; jt->dep = dep;
        return 0;
    }
    if (r < 0 || r > 15 || st[r] != PV_TGT) return 1;
    uint64_t t = tb[r];
    /* the lift compares target - table, so the table address must still be in a register */
    int breg = -1;
    for (int q = 0; q < 16; q++) if (q != r && st[q] == PV_TB && tb[q] == t) { breg = q; break; }
    if (breg < 0) return 1;
    const RexShdr *sec = NULL;
    for (int i = 0; i < e->nsh; i++) {
        const RexShdr *sh = &e->sh[i];
        if ((sh->flags & 2) && !(sh->flags & 1) && sh->type != 8 && t >= sh->addr && t + 4 * (uint64_t)n <= sh->addr + sh->size) sec = sh;
    }
    if (!sec) return 2;
    uint64_t off = sec->offset + (t - sec->addr);
    if (off + 4 * (uint64_t)n > e->size) return 2;
    jt->targets = malloc((size_t)n * sizeof(uint64_t));
    if (!jt->targets) return 3;
    for (int k = 0; k < n; k++) {
        int32_t v;
        memcpy(&v, e->data + off + 4 * (uint64_t)k, 4);
        uint64_t a = t + (uint64_t)(int64_t)v;
        size_t av;
        if (!rex_elf_code_at(e, a, &av) || a > 0x7fffffff) { free(jt->targets); jt->targets = NULL; return 3; }
        jt->targets[k] = a;
    }
    jt->at = in->addr; jt->reg = r; jt->n = n; jt->byaddr = 1; jt->guard = hist[ka].addr + (uint64_t)hist[ka].size;
    jt->breg = breg; jt->base = t; jt->hoisted = breg == hoist; jt->dep = dep;
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
    uint64_t dyn_main = 0;     /* main as a dynamic _start passes it to the C library */
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
        /* A dynamic program's _start hands main to the C library: the address
         * goes in rdi (mov $main / lea main(%rip)) and the call is through the
         * GOT. Remember it: main is code that really runs, so failing to build it
         * must be reported, not dropped like a symbol-only helper below. */
        if (a == e->entry && !p->main_addr && e->dynamic) {
            uint64_t cand = 0;
            for (int i = 0; i < f->ninsns; i++) {
                const X86Insn *x = &f->insns[i];
                const X86Operand *d0 = &x->ops[0], *s1 = &x->ops[1];
                if ((x->op == X86_MOV || x->op == X86_LEA) && d0->kind == XO_REG && d0->reg == 7 && !d0->xmm) {
                    cand = 0;
                    if (x->op == X86_MOV && s1->kind == XO_IMM) cand = (uint64_t)s1->imm;
                    else if (x->op == X86_LEA && s1->kind == XO_MEM && s1->base == X86_RIP) cand = s1->target;
                } else if (x->op == X86_CALL) {
                    size_t av = 0;
                    if (cand && x->ops[0].kind == XO_MEM && rex_elf_code_at(e, cand, &av) && av > 0) dyn_main = cand;
                    break;
                }
            }
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
        if (build_func(e, f, &syms, &ft, tmperr, sizeof(tmperr))) {
            cfg_func_free(f);
            if (a == dyn_main) {
                snprintf(err, errlen, "%s", tmperr);
                free(syms.v); cfg_free(p); free(calls.v); free(ft.v); return -1;
            }
            continue;
        }
        p->nfuncs++;
    }
    free(syms.v);
    /* Stripped: no symbol named main. Build it and what it calls the way phase 1
     * builds everything, as code that runs. */
    if (dyn_main && cfg_find_func(p, dyn_main) < 0) {
        int c0 = calls.n;
        if (al_push(&calls, dyn_main)) { cfg_free(p); free(calls.v); free(ft.v); return fail(err, errlen, "out of memory"); }
        for (int ci = c0; ci < calls.n; ci++) {
            uint64_t ca = calls.v[ci];
            if (cfg_find_func(p, ca) >= 0) continue;
            if (p->nfuncs >= CFG_MAX_FUNCS) { cfg_free(p); free(calls.v); free(ft.v); return fail(err, errlen, "too many functions"); }
            CfgFunc *f = &p->funcs[p->nfuncs];
            memset(f, 0, sizeof(*f));
            f->addr = ca;
            f->reachable = 1;
            snprintf(f->name, sizeof(f->name), "fn_%llx", (unsigned long long)ca);
            if (build_func(e, f, &calls, &ft, err, errlen)) { cfg_func_free(f); cfg_free(p); free(calls.v); free(ft.v); return -1; }
            p->nfuncs++;
        }
    }
    /* (A PIE _start's lea main(%rip) may already have built it in phase 1.) A
     * symbol named main, below, still has the last word. */
    if (dyn_main && !p->main_addr && cfg_find_func(p, dyn_main) >= 0) p->main_addr = dyn_main;
    /* Everything main reaches through direct calls and tail calls runs, so it
     * must have been built. Phase 2 drops a helper it cannot build; if main
     * reaches one, build it again for its error and fail with that. */
    if (dyn_main) {
        AddrList q = {0};
        if (al_push(&q, dyn_main)) { cfg_free(p); free(calls.v); free(ft.v); return fail(err, errlen, "out of memory"); }
        char *done = calloc(CFG_MAX_FUNCS, 1);
        if (!done) { free(q.v); cfg_free(p); free(calls.v); free(ft.v); return fail(err, errlen, "out of memory"); }
        for (int qi = 0; qi < q.n; qi++) {
            uint64_t qa = q.v[qi];
            int fi = cfg_find_func(p, qa);
            if (fi < 0) {
                CfgFunc tf; memset(&tf, 0, sizeof tf);
                tf.addr = q.v[qi]; tf.reachable = 1;
                snprintf(tf.name, sizeof(tf.name), "fn_%llx", (unsigned long long)q.v[qi]);
                AddrList more = {0};
                int brc = build_func(e, &tf, &more, &ft, err, errlen);
                cfg_func_free(&tf); free(more.v);
                if (brc) { free(done); free(q.v); cfg_free(p); free(calls.v); free(ft.v); return -1; }
                /* builds now (it should not): the decompiler still lacks it */
                free(done); free(q.v); cfg_free(p); free(calls.v); free(ft.v);
                return fail(err, errlen, "fn_%llx: called from main but not built", (unsigned long long)qa);
            }
            if (done[fi]) continue;
            done[fi] = 1;
            if (p->funcs[fi].lenient) {
                /* built leniently as a helper, but main reaches it: build it as code that runs */
                CfgFunc tf; memset(&tf, 0, sizeof tf);
                tf.addr = qa; tf.reachable = 1;
                snprintf(tf.name, sizeof(tf.name), "%s", p->funcs[fi].name);
                AddrList more = {0};
                int brc = build_func(e, &tf, &more, &ft, err, errlen);
                cfg_func_free(&tf); free(more.v);
                if (!brc) brc = fail(err, errlen, "%s: an indirect jump is not followed", p->funcs[fi].name);
                free(done); free(q.v); cfg_free(p); free(calls.v); free(ft.v); return -1;
            }
            const CfgFunc *cf = &p->funcs[fi];
            for (int k = 0; k < cf->ninsns; k++) {
                const X86Insn *x = &cf->insns[k];
                if ((x->op == X86_CALL || (x->op == X86_JMP && cfg_is_tail(cf, x->addr))) && x->ops[0].kind == XO_REL &&
                    !rex_elf_import_at(e, x->ops[0].target) && al_push(&q, x->ops[0].target)) {
                    free(done); free(q.v); cfg_free(p); free(calls.v); free(ft.v); return fail(err, errlen, "out of memory");
                }
            }
        }
        free(done); free(q.v);
    }
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
