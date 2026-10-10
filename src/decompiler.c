#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "decompiler.h"
#include "loader.h"
#include "rex_err.h"
#include "cfg.h"
#include "x86_lift.h"
#include "ir.h"

/* Recover REX source from a REX-built ELF.
 *
 * Pipeline: ELF -> CFG -> machine IR -> this file -> .rex
 *
 * Honest limits:
 * - Built for REX's own ELF64 output. Arbitrary binaries may refuse
 *   or produce a stub that does not round-trip.
 * - Names are invented (f1, a, b, t0...). Original names are gone.
 * - Calls through a register print the pointer expression, 2 args.
 * - cmov becomes (cond ? src : old). hlt/ud2 become IR_TRAP and are dropped.
 * - Structuring: natural loops (while / do-while / while(1) with break and
 * continue), if/else at postdominators, REX switch chains. Nested structs
 * and most pointer arithmetic stay opaque.
 * - Runtime helpers (print, putc, alloc, ...) are recognized by
 *   syscalls and are not emitted; calls to them become builtins.
 */

enum { MAX_LOC = 64 };

typedef struct { char *s; } Ex;

static Ex ex(const char *s) { return (Ex){ strdup(s ? s : "?") }; }
static Ex exf(const char *fmt, ...) {
    char *b = NULL;
    va_list ap; va_start(ap, fmt);
    int n = vasprintf(&b, fmt, ap);
    va_end(ap);
    if (n < 0 || !b) return ex("?");
    return (Ex){ b };
}
static void ex_free(Ex e) { free(e.s); }

/* ---- expression simplifier ----
 * Expressions are built as fully parenthesized strings: atoms, "(a op b)"
 * and "(op a)". split_top finds the top-level binary operator. */
static int is_num(const char *s, long long *v) {
    const char *p = s;
    if (*p == '-') p++;
    if (!*p) return 0;
    for (; *p; p++) if (*p < '0' || *p > '9') return 0;
    if (v) *v = atoll(s);
    return 1;
}
static int split_top(const char *s, char **l, char **op, char **r) {
    size_t n = strlen(s);
    if (n < 5 || s[0] != '(' || s[n - 1] != ')') return 0;
    int depth = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] == '(' || s[i] == '[') depth++;
        else if (s[i] == ')' || s[i] == ']') { depth--; if (depth == 0 && i != n - 1) return 0; }
        else if (s[i] == ' ' && depth == 1 && i > 1) {
            size_t j = i + 1;
            while (j < n && s[j] != ' ') j++;
            if (j >= n - 1) return 0;
            *l = strndup(s + 1, i - 1);
            *op = strndup(s + i + 1, j - i - 1);
            *r = strndup(s + j + 1, n - j - 2);
            return 1;
        }
    }
    return 0;
}
static const char *rel_neg(const char *op) {
    static const char *pairs[][2] = { {"==","!="}, {"!=","=="}, {"<",">="}, {">=","<"}, {">","<="}, {"<=",">"} };
    for (size_t i = 0; i < sizeof(pairs) / sizeof(pairs[0]); i++)
        if (!strcmp(op, pairs[i][0])) return pairs[i][1];
    return NULL;
}
/* Identities (x+0, x*1, ...) apply in address arithmetic only, so source-level
 * shapes survive and match --ir keeps working. */
static int g_addr;
static Ex ex_bin(const char *op, Ex a, Ex b) {
    long long x, y;
    int na = is_num(a.s, &x), nb = is_num(b.s, &y);
    if (na && nb) {
        int r = -1;
        if (!strcmp(op, "==")) r = x == y; else if (!strcmp(op, "!=")) r = x != y;
        else if (!strcmp(op, "<")) r = x < y;  else if (!strcmp(op, "<=")) r = x <= y;
        else if (!strcmp(op, ">")) r = x > y;  else if (!strcmp(op, ">=")) r = x >= y;
        if (r >= 0) { ex_free(a); ex_free(b); return exf("%d", r); }
    }
    if (g_addr && nb && y == 0 && (!strcmp(op, "+") || !strcmp(op, "-") || !strcmp(op, "|") ||
                         !strcmp(op, "^") || !strcmp(op, "<<") || !strcmp(op, ">>"))) { ex_free(b); return a; }
    if (g_addr && na && x == 0 && (!strcmp(op, "+") || !strcmp(op, "|"))) { ex_free(a); return b; }
    if (g_addr && nb && y == 1 && (!strcmp(op, "*") || !strcmp(op, "/"))) { ex_free(b); return a; }
    if (g_addr && na && x == 1 && !strcmp(op, "*")) { ex_free(a); return b; }
    /* (a + -k) -> (a - k) */
    if (nb && y < 0 && !strcmp(op, "+")) { ex_free(b); Ex r = exf("(%s - %lld)", a.s, -y); ex_free(a); return r; }
    Ex r = exf("(%s %s %s)", a.s, op, b.s);
    ex_free(a); ex_free(b);
    return r;
}
static Ex ex_un(const char *op, Ex a) {
    size_t n = strlen(a.s);
    /* double negation */
    if ((!strcmp(op, "-") || !strcmp(op, "!") || !strcmp(op, "~")) && n > 3 &&
        a.s[0] == '(' && a.s[1] == op[0] && a.s[n - 1] == ')') {
        /* only when the inner "(op X)" spans the whole string */
        int depth = 0, whole = 1;
        for (size_t i = 0; i < n; i++) {
            if (a.s[i] == '(') depth++;
            else if (a.s[i] == ')') { depth--; if (depth == 0 && i != n - 1) { whole = 0; break; } }
        }
        if (whole && (a.s[2] != '=')) { Ex r = (Ex){ strndup(a.s + 2, n - 3) }; ex_free(a); return r; }
    }
    if (!strcmp(op, "!")) {
        char *l, *o, *r;
        if (split_top(a.s, &l, &o, &r)) {
            const char *neg = rel_neg(o);
            Ex res = neg ? exf("(%s %s %s)", l, neg, r) : (Ex){ NULL };
            free(l); free(o); free(r);
            if (neg) { ex_free(a); return res; }
        }
        long long v;
        if (is_num(a.s, &v)) { ex_free(a); return exf("%d", v == 0); }
    }
    if (!strcmp(op, "-")) { long long v; if (is_num(a.s, &v)) { ex_free(a); return exf("%lld", -v); } }
    Ex r = exf("(%s%s)", op, a.s);
    ex_free(a);
    return r;
}
/* Drop one pair of outer parentheses for statement / argument contexts. */
static const char *bare(const char *s, char *buf, size_t n) {
    size_t L = strlen(s);
    if (L >= 2 && s[0] == '(' && s[L - 1] == ')' && L - 1 < n) {
        int depth = 0;
        for (size_t i = 0; i < L; i++) {
            if (s[i] == '(') depth++;
            else if (s[i] == ')') { depth--; if (depth == 0 && i != L - 1) return s; }
        }
        memcpy(buf, s + 1, L - 2); buf[L - 2] = 0;
        return buf;
    }
    return s;
}

typedef struct {
    int off;
    char name[16];
    int arg;        /* 0..5, or -1 */
    int hint;       /* 0 none, 1 array, 2 pointer — recovery hints only */
    int alen;       /* array length proven by a bounds check, 0 unknown */
    int sid;        /* struct id (1-based) when this slot is a struct base */
    int nfield;     /* struct field count */
    int ptr_sid;    /* struct a pointer slot points at */
    int hidden;     /* cell of an aggregate: not declared on its own */
    char alias[48]; /* scalar spelling for aggregate cells: t1[2], t1.f8 */
} Slot;

typedef struct {
    uint64_t addr;
    char name[32];
    int nargs;
    Slot slots[MAX_LOC];
    int nslots;
    int kind;       /* 0 user, 1 start, 2 main, 3 runtime */
    const char *builtin; /* print/putc/alloc/free/... */
} Fun;

typedef struct {
    FILE *out;
    IrModule *m;
    CfgProgram *cfg;
    Fun *fun;
    int nfun;
    int verbose;
    Ex reg[16];
    int has[16];
    Ex *stk;
    int nstk, cstk;
    Fun *cur;
    const IrInsn *cmp;
    unsigned char declared[MAX_LOC];
    unsigned char written[MAX_LOC];
    int flat;
    int bound;          /* array length proven for the block being emitted */
    int nstruct;           /* no control flow emitted yet at function level */
} D;

static const int ARG[6] = { 7, 6, 2, 1, 8, 9 };

static Fun *fby(D *d, uint64_t a) {
    for (int i = 0; i < d->nfun; i++) if (d->fun[i].addr == a) return &d->fun[i];
    return NULL;
}

static void setr(D *d, int r, Ex v) {
    if (r < 0 || r > 15) { ex_free(v); return; }
    if (d->has[r]) ex_free(d->reg[r]);
    /* Runaway expressions (register recurrences in optimized code) become
     * an explicit raw register instead of growing without bound. */
    if (strlen(v.s) > 400) { ex_free(v); v = exf("r%d", r); }
    d->reg[r] = v; d->has[r] = 1;
}
static Ex getr(D *d, int r) {
    if (r >= 0 && r < 16 && d->has[r]) return ex(d->reg[r].s);
    return exf("r%d", r);
}
static void push(D *d, Ex v) {
    if (d->nstk == d->cstk) {
        d->cstk = d->cstk ? d->cstk * 2 : 8;
        d->stk = realloc(d->stk, (size_t)d->cstk * sizeof(Ex));
    }
    d->stk[d->nstk++] = v;
}
static Ex pop(D *d) { return d->nstk ? d->stk[--d->nstk] : ex("?"); }

static const char *slot_name(Fun *f, int off) {
    for (int i = 0; i < f->nslots; i++)
        if (f->slots[i].off == off) return f->slots[i].alias[0] ? f->slots[i].alias : f->slots[i].name;
    return NULL;
}
static Slot *slot_at(Fun *f, int off) {
    for (int i = 0; i < f->nslots; i++) if (f->slots[i].off == off) return &f->slots[i];
    return NULL;
}
static void add_slot(Fun *f, int off, int arg) {
    for (int i = 0; i < f->nslots; i++) if (f->slots[i].off == off) return;
    if (f->nslots >= MAX_LOC) return;
    Slot *s = &f->slots[f->nslots++];
    s->off = off; s->arg = arg; s->hint = 0;
    if (arg >= 0) snprintf(s->name, sizeof(s->name), "%c", 'a' + arg);
    else snprintf(s->name, sizeof(s->name), "t%d", f->nslots);
}

static void slot_hint(Fun *f, int off, int hint) {
    for (int i = 0; i < f->nslots; i++)
        if (f->slots[i].off == off && f->slots[i].hint == 0) f->slots[i].hint = hint;
}

/* REX local arrays: element i lives at fp + disp - 8*i, addressed as
 * [rbp + rax*1 + disp] with rax = -(i*8). Return i, or NULL. */
static char *neg8_index(const char *ix) {
    long long v;
    if (is_num(ix, &v)) return NULL; /* numeric handled by caller */
    size_t n = strlen(ix);
    if (n >= 10 && !strncmp(ix, "(-(", 3) && !strcmp(ix + n - 6, " * 8))")) return strndup(ix + 3, n - 9);
    return NULL;
}
static Ex mem_ex_(D *d, const IrOperand *o) {
    if (o->base == 5 && o->index == IR_NOREG) {
        const char *n = slot_name(d->cur, (int)o->disp);
        if (n) return ex(n);
        return exf("m%d", (int)o->disp);
    }
    if (o->base == 4 && o->index == IR_NOREG && o->disp >= 0 && o->disp % 8 == 0) {
        int k = (int)(o->disp / 8);
        if (k < d->nstk) return ex(d->stk[d->nstk - 1 - k].s);
    }
    if (o->base == 5 && o->index != IR_NOREG) {
        Slot *bs = slot_at(d->cur, (int)o->disp);
        const char *base = bs ? bs->name : NULL;
        if (bs && d->bound > bs->alen) bs->alen = d->bound;
        Ex ix = getr(d, o->index);
        long long v;
        char *i = NULL;
        if (o->scale == 1) {
            if (is_num(ix.s, &v) && v <= 0 && v % 8 == 0) { i = malloc(24); if (i) snprintf(i, 24, "%lld", -v / 8); }
            else i = neg8_index(ix.s);
        }
        if (base && i) {
            slot_hint(d->cur, (int)o->disp, 1);
            Ex r = exf("%s[%s]", base, i);
            free(i); ex_free(ix);
            return r;
        }
        free(i);
        ex_free(ix);
        if (base) slot_hint(d->cur, (int)o->disp, 1);
    }
    if (o->base != 5 && o->base != IR_NOREG && o->index == IR_NOREG && o->disp <= 0 && o->disp % 8 == 0 && d->has[o->base]) {
        for (int i = 0; i < d->cur->nslots; i++) {
            Slot *ps = &d->cur->slots[i];
            if (!ps->ptr_sid || strcmp(ps->name, d->reg[o->base].s)) continue;
            for (int j = 0; j < d->cur->nslots; j++)
                if (d->cur->slots[j].sid == ps->ptr_sid && -o->disp / 8 < d->cur->slots[j].nfield)
                    return exf("%s->f%lld", ps->name, (long long)-o->disp);
        }
    }
    if (o->base != 5 && o->base != IR_NOREG && d->has[o->base])
        for (int i = 0; i < d->cur->nslots; i++)
            if (!strcmp(d->cur->slots[i].name, d->reg[o->base].s) && !d->cur->slots[i].alias[0])
                slot_hint(d->cur, d->cur->slots[i].off, 2);
    Ex b = o->base == 5 ? ex("fp") : (o->base != IR_NOREG ? getr(d, o->base) : ex("0"));
    if (o->index != IR_NOREG) {
        Ex ix = getr(d, o->index);
        if (o->scale != 1) ix = ex_bin("*", ix, exf("%d", o->scale));
        b = ex_bin("+", b, ix);
    }
    if (o->disp) b = ex_bin("+", b, exf("%lld", (long long)o->disp));
    /* Heap/pointer cell: *(B + X*8) -> B[X], *(B + 8k) -> B[k] (REX scales by 8). */
    char *l, *op, *r;
    if (split_top(b.s, &l, &op, &r)) {
        Ex out = (Ex){ NULL };
        long long k;
        size_t rn = strlen(r);
        if (!strcmp(op, "+") && is_num(r, &k) && k > 0 && k % 8 == 0 && l[0] != '(')
            out = exf("%s[%lld]", l, k / 8);
        else if (!strcmp(op, "+") && rn > 6 && r[0] == '(' && !strcmp(r + rn - 5, " * 8)") && l[0] != '(')
            out = exf("%s[%.*s]", l, (int)(rn - 6), r + 1);
        free(l); free(op); free(r);
        if (out.s) { ex_free(b); return out; }
    }
    Ex res = exf("*(%s)", b.s);
    ex_free(b);
    return res;
}

static Ex mem_ex(D *d, const IrOperand *o) {
    int save = g_addr; g_addr = 1;
    Ex r = mem_ex_(d, o);
    g_addr = save;
    return r;
}

static Ex op_ex(D *d, const IrOperand *o) {
    switch (o->kind) {
    case IR_O_REG: return getr(d, o->reg);
    case IR_O_IMM:
        if (o->imm == (int64_t)0x8000000000000000ULL)
            return ex("(0 - 9223372036854775807 - 1)");
        return exf("%lld", (long long)o->imm);
    case IR_O_MEM: return mem_ex(d, o);
    case IR_O_ADDR: {
        Fun *t = fby(d, o->addr);
        return ex(t ? t->name : "fn");
    }
    default: return ex("?");
    }
}

static const char *bop(IrOp op) {
    switch (op) {
    case IR_ADD: return "+"; case IR_SUB: return "-"; case IR_MUL: return "*";
    case IR_DIVS: return "/"; case IR_REMS: return "%";
    case IR_AND: return "&"; case IR_OR: return "|"; case IR_XOR: return "^";
    case IR_SHL: return "<<"; case IR_SHR: case IR_SAR: return ">>";
    default: return "?";
    }
}
static const char *cop(IrCond c) {
    switch (c) {
    case IR_CC_EQ: return "=="; case IR_CC_NE: return "!=";
    case IR_CC_LT: case IR_CC_ULT: return "<";
    case IR_CC_LE: case IR_CC_ULE: return "<=";
    case IR_CC_GT: case IR_CC_UGT: return ">";
    case IR_CC_GE: case IR_CC_UGE: return ">=";
    default: return "?";
    }
}


/* Condition from the last cmp/test for condition code cc (taken sense). */
static Ex cond_from(D *d, const IrInsn *cmp, IrCond cc) {
    if (!cmp) return ex("1");
    if (cmp->op == IR_CMP) return ex_bin(cop(cc), op_ex(d, &cmp->a), op_ex(d, &cmp->b));
    Ex v;
    if (cmp->a.kind == cmp->b.kind && cmp->a.kind == IR_O_REG && cmp->a.reg == cmp->b.reg) v = op_ex(d, &cmp->a);
    else v = ex_bin("&", op_ex(d, &cmp->a), op_ex(d, &cmp->b));
    if (cc == IR_CC_EQ) return ex_bin("==", v, ex("0"));
    if (cc == IR_CC_NE) return ex_bin("!=", v, ex("0"));
    if (cc == IR_CC_NEG || cc == IR_CC_LT) return ex_bin("<", v, ex("0"));
    if (cc == IR_CC_POS || cc == IR_CC_GE) return ex_bin(">=", v, ex("0"));
    if (cc == IR_CC_LE) return ex_bin("<=", v, ex("0"));
    if (cc == IR_CC_GT) return ex_bin(">", v, ex("0"));
    return v;
}

static void classify(D *d) {
    for (int i = 0; i < d->nfun; i++) {
        Fun *fi = &d->fun[i];
        const IrFunc *f = &d->m->funcs[i];
        fi->addr = f->addr;
        if (!strcmp(f->name, "start")) { fi->kind = 1; snprintf(fi->name, sizeof(fi->name), "start"); continue; }
        if (f->addr == d->cfg->main_addr) { fi->kind = 2; snprintf(fi->name, sizeof(fi->name), "main"); }
        else snprintf(fi->name, sizeof(fi->name), "f%d", i);

        int has_sys = 0, has_call = 0;
        for (int b = 0; b < f->nblocks; b++)
            for (int k = 0; k < f->blocks[b].ninsns; k++) {
                IrOp op = f->blocks[b].insns[k].op;
                if (op == IR_SYSCALL) has_sys = 1;
                if (op == IR_CALL) has_call = 1;
            }
        if (has_sys) {
            fi->kind = 3;
            /* Guess builtin from shape. */
            int div = 0, imm10 = 0, mmap = 0, munmap = 0, byte_st = 0;
            int sys0 = 0, sys57 = 0, sys59 = 0, dig = 0;
            for (int b = 0; b < f->nblocks; b++)
                for (int k = 0; k < f->blocks[b].ninsns; k++) {
                    const IrInsn *in = &f->blocks[b].insns[k];
                    if (in->op == IR_DIVS) div = 1;
                    if (in->op == IR_MOV && in->a.kind == IR_O_IMM && in->a.imm == 10) imm10 = 1;
                    if (in->op == IR_MOV && in->a.kind == IR_O_IMM && in->a.imm == 9) mmap = 1;
                    if (in->op == IR_MOV && in->a.kind == IR_O_IMM && in->a.imm == 11) munmap = 1;
                    if (in->op == IR_MOV && in->a.kind == IR_O_IMM && in->a.imm == 57) sys57 = 1;
                    if (in->op == IR_MOV && in->a.kind == IR_O_IMM && in->a.imm == 59) sys59 = 1;
                    if (in->op == IR_STORE && in->dst.width == 1) byte_st = 1;
                    if (in->op == IR_CMP && ((in->b.kind == IR_O_IMM && (in->b.imm == 48 || in->b.imm == 57)) ||
                        (in->a.kind == IR_O_IMM && (in->a.imm == 48 || in->a.imm == 57)))) dig = 1;
                    if (in->op == IR_SYSCALL) {
                        for (int j = k - 1; j >= 0 && j >= k - 6; j--) {
                            const IrInsn *p = &f->blocks[b].insns[j];
                            if (p->op == IR_XOR && p->dst.reg == 0 && p->a.kind == IR_O_REG && p->a.reg == 0) sys0 = 1;
                            if (p->op == IR_MOV && p->dst.reg == 0 && p->a.kind == IR_O_IMM && p->a.imm == 0) sys0 = 1;
                        }
                    }
                }
            if (sys57 || sys59) fi->builtin = "exec";
            else if (sys0 && dig) fi->builtin = "read";
            else if (div && imm10) fi->builtin = "print";
            else if (mmap) fi->builtin = "alloc";
            else if (munmap) fi->builtin = "free";
            else if (byte_st) fi->builtin = "putc";
            else fi->builtin = "print";
            snprintf(fi->name, sizeof(fi->name), "%s", fi->builtin);
            if (!strcmp(fi->builtin, "read")) fi->nargs = 0;
            if (!strcmp(fi->builtin, "exec")) fi->nargs = 1;
        }

        /* Args: early stores of arg regs, or first uses. */
        if (f->nblocks) {
            const IrBlock *b0 = &f->blocks[0];
            for (int k = 0; k < b0->ninsns && k < 24; k++) {
                const IrInsn *in = &b0->insns[k];
                if (in->op == IR_STORE && in->dst.kind == IR_O_MEM && in->dst.base == 5 &&
                    in->a.kind == IR_O_REG) {
                    for (int a = 0; a < 6; a++) if (in->a.reg == ARG[a]) {
                        if (a + 1 > fi->nargs) fi->nargs = a + 1;
                        add_slot(fi, (int)in->dst.disp, a);
                    }
                }
                /* print_int style: mov rdi -> rax early */
                if (in->op == IR_MOV && in->dst.kind == IR_O_REG && in->a.kind == IR_O_REG &&
                    in->a.reg == 7 && fi->nargs < 1) fi->nargs = 1;
            }
        }
        for (int b = 0; b < f->nblocks; b++)
            for (int k = 0; k < f->blocks[b].ninsns; k++) {
                const IrOperand *ops[3] = { &f->blocks[b].insns[k].dst, &f->blocks[b].insns[k].a, &f->blocks[b].insns[k].b };
                for (int o = 0; o < 3; o++)
                    if (ops[o]->kind == IR_O_MEM && ops[o]->base == 5 && ops[o]->index == IR_NOREG && ops[o]->disp < 0)
                        add_slot(fi, (int)ops[o]->disp, -1);
            }
        if (fi->kind == 0 && !has_sys) {
            int byte_ld = 0, cmp0 = 0, add1 = 0, n_byte = 0, has_mul = 0, ncall = 0;
            for (int b = 0; b < f->nblocks; b++)
                for (int k = 0; k < f->blocks[b].ninsns; k++) {
                    const IrInsn *in = &f->blocks[b].insns[k];
                    if (in->op == IR_LOAD && in->a.kind == IR_O_MEM && in->a.width == 1) byte_ld = 1;
                    if (in->op == IR_ZEXT && in->a.kind == IR_O_MEM && in->a.width == 1) { byte_ld = 1; n_byte++; }
                    if (in->op == IR_CMP && in->a.kind == IR_O_MEM && in->a.width == 1) byte_ld = 1;
                    if (in->op == IR_CMP && ((in->b.kind == IR_O_IMM && in->b.imm == 0) ||
                        (in->a.kind == IR_O_IMM && in->a.imm == 0))) cmp0 = 1;
                    if (in->op == IR_ADD && in->b.kind == IR_O_IMM && in->b.imm == 1) add1 = 1;
                    if (in->op == IR_MUL) has_mul = 1;
                    if (in->op == IR_CALL) ncall++;
                }
            if (n_byte >= 2 && !has_mul && ncall == 0 && f->nblocks >= 3) {
                fi->kind = 3; fi->builtin = "strcmp"; fi->nargs = 2;
                snprintf(fi->name, sizeof(fi->name), "strcmp");
            } else if (byte_ld && cmp0 && add1 && !has_mul && ncall == 0 && fi->nargs <= 1) {
                fi->kind = 3; fi->builtin = "len"; fi->nargs = 1;
                snprintf(fi->name, sizeof(fi->name), "len");
            }
        }
        (void)has_call;
    }
}

static void emit(D *d, int depth, const char *fmt, ...) {
    for (int i = 0; i < depth; i++) fputs("    ", d->out);
    va_list ap; va_start(ap, fmt); vfprintf(d->out, fmt, ap); va_end(ap);
    fputc('\n', d->out);
}

static int is_prolog(const IrInsn *in) {
    if (in->op == IR_PUSH && in->a.kind == IR_O_REG && in->a.reg == 5) return 1;
    if (in->op == IR_MOV && in->dst.kind == IR_O_REG && in->dst.reg == 5 &&
        in->a.kind == IR_O_REG && in->a.reg == 4) return 1;
    if (in->op == IR_SUB && in->dst.kind == IR_O_REG && in->dst.reg == 4 &&
        in->a.kind == IR_O_REG && in->a.reg == 4 && in->b.kind == IR_O_IMM) return 1;
    return 0;
}
static int is_epilog(const IrInsn *in) {
    if (in->op == IR_MOV && in->dst.kind == IR_O_REG && in->dst.reg == 4 &&
        in->a.kind == IR_O_REG && in->a.reg == 5) return 1;
    if (in->op == IR_POP && in->dst.kind == IR_O_REG && in->dst.reg == 5) return 1;
    return 0;
}

/* Aggregate (array / struct) base slot index covering slot si, or -1. */
static int agg_base(Fun *f, int si) {
    Slot *s = &f->slots[si];
    for (int i = 0; i < f->nslots; i++) {
        Slot *b = &f->slots[i];
        int n = b->alen > 0 && b->hint == 1 ? b->alen : b->sid ? b->nfield : 0;
        if (n && s->off <= b->off && s->off > b->off - 8 * n && (b->off - s->off) % 8 == 0) return i;
    }
    return -1;
}
static void decl_agg(D *d, int bi, int depth) {
    Slot *b = &d->cur->slots[bi];
    if (b->sid) emit(d, depth, "let %s = S%d; // hint: struct, fields named by byte offset", b->name, b->sid);
    else emit(d, depth, "let %s[%d]; // hint: array, length from the bounds check", b->name, b->alen);
}

static void step(D *d, const IrInsn *in, int depth, int *emit_call) {
    if (is_prolog(in) || is_epilog(in)) return;
    switch (in->op) {
    case IR_NOP: case IR_TRAP: case IR_SYSCALL: break;
    case IR_PUSH: push(d, op_ex(d, &in->a)); break;
    case IR_POP:
        if (in->dst.kind == IR_O_REG) setr(d, in->dst.reg, pop(d));
        else ex_free(pop(d));
        break;
    case IR_MOV: case IR_ZEXT: case IR_SEXT:
        if (in->dst.kind == IR_O_REG) setr(d, in->dst.reg, op_ex(d, &in->a));
        break;
    case IR_LOAD:
        if (in->dst.kind == IR_O_REG) setr(d, in->dst.reg, op_ex(d, &in->a));
        break;
    case IR_STORE: {
        Ex dst = op_ex(d, &in->dst), src = op_ex(d, &in->a);
        char bb[1024];
        int si = -1;
        if (in->dst.kind == IR_O_MEM && in->dst.base == 5 && in->dst.index == IR_NOREG)
            for (int i = 0; i < d->cur->nslots; i++)
                if (d->cur->slots[i].off == (int)in->dst.disp && d->cur->slots[i].arg < 0) si = i;
        int agg = si >= 0 ? agg_base(d->cur, si) : -1;
        if (agg >= 0 && !d->written[si] && !strcmp(src.s, "0") && in->a.kind == IR_O_IMM) {
            /* zero-init of an aggregate cell: part of its declaration */
            d->written[si] = 1;
            if (!d->declared[agg]) { d->declared[agg] = 1; decl_agg(d, agg, depth); }
        } else if (agg >= 0) {
            d->written[si] = 1;
            if (!d->declared[agg]) { d->declared[agg] = 1; decl_agg(d, agg, depth); }
            emit(d, depth, "%s = %s;", dst.s, bare(src.s, bb, sizeof bb));
        } else if (si >= 0 && !d->declared[si] && d->flat && depth == 1) {
            d->declared[si] = 1;
            Slot *sl = &d->cur->slots[si];
            if (!sl->ptr_sid && !strncmp(src.s, "&", 1)) {
                Slot *tg = NULL;
                for (int i = 0; i < d->cur->nslots; i++) if (!strcmp(d->cur->slots[i].name, src.s + 1)) tg = &d->cur->slots[i];
                if (tg && tg->sid) sl->ptr_sid = tg->sid;
            }
            emit(d, depth, "let %s = %s;%s", dst.s, bare(src.s, bb, sizeof bb),
                 sl->ptr_sid ? " // hint: pointer to struct" : sl->hint == 2 ? " // hint: pointer" : "");
        } else if (strcmp(dst.s, src.s))
            emit(d, depth, "%s = %s;", dst.s, bare(src.s, bb, sizeof bb));
        ex_free(dst); ex_free(src);
        break;
    }
    case IR_ADDR:
        if (in->dst.kind == IR_O_REG) {
            if (in->a.kind == IR_O_MEM && in->a.base == IR_NOREG && in->a.index == IR_NOREG)
                setr(d, in->dst.reg, exf("%lld", (long long)in->a.disp));  /* absolute address as number */
            else if (in->a.kind == IR_O_MEM && in->a.base == 5 && in->a.index == IR_NOREG &&
                     slot_at(d->cur, (int)in->a.disp) && slot_at(d->cur, (int)in->a.disp)->alias[0]) {
                setr(d, in->dst.reg, exf("&%s", slot_at(d->cur, (int)in->a.disp)->name));
            } else {
                Ex m = mem_ex(d, &in->a);
                if (m.s[0] == '*') {
                    Ex r = exf("&%s", m.s[1] == '(' ? m.s + 2 : m.s + 1);
                    size_t L = strlen(r.s);
                    if (L && r.s[L - 1] == ')') r.s[L - 1] = 0;
                    ex_free(m);
                    setr(d, in->dst.reg, r);
                } else {
                    setr(d, in->dst.reg, exf("&%s", m.s));
                    ex_free(m);
                }
            }
        }
        break;
    case IR_ADD: case IR_SUB: case IR_MUL: case IR_DIVS: case IR_REMS:
    case IR_AND: case IR_OR: case IR_XOR: case IR_SHL: case IR_SHR: case IR_SAR:
        if (in->dst.kind == IR_O_REG)
            setr(d, in->dst.reg, ex_bin(bop(in->op), op_ex(d, &in->a), op_ex(d, &in->b)));
        break;
    case IR_NEG: case IR_NOT:
        if (in->dst.kind == IR_O_REG)
            setr(d, in->dst.reg, ex_un(in->op == IR_NEG ? "-" : "~", op_ex(d, &in->a)));
        break;
    case IR_CMP: case IR_TEST:
        d->cmp = in;
        break;
    case IR_SETCC: {
        Ex v = d->cmp ? cond_from(d, d->cmp, in->cc) : ex("0");
        if (in->dst.kind == IR_O_REG) setr(d, in->dst.reg, v);
        else ex_free(v);
        break;
    }
    case IR_CMOV: {
        /* REX supports cond ? t : f (parsed as N_IF with num=1). */
        Ex src = op_ex(d, &in->a);
        Ex oldv = in->dst.kind == IR_O_REG ? getr(d, in->dst.reg) : ex("0");
        Ex cond = cond_from(d, d->cmp, in->cc);
        Ex tern = exf("(%s ? %s : %s)", cond.s, src.s, oldv.s);
        ex_free(cond); ex_free(src); ex_free(oldv);
        if (in->dst.kind == IR_O_REG) setr(d, in->dst.reg, tern);
        else ex_free(tern);
        break;
    }
    case IR_CALL: {
        Fun *t = in->a.kind == IR_O_ADDR ? fby(d, in->a.addr) : NULL;
        const char *nm = "fn";
        int na = 0;
        if (t) {
            if (t->kind == 3 && t->builtin) {
                nm = t->builtin;
                if (!strcmp(nm, "read")) na = 0;
                else if (!strcmp(nm, "strcmp")) na = 2;
                else if (!strcmp(nm, "print") || !strcmp(nm, "putc") || !strcmp(nm, "alloc") ||
                         !strcmp(nm, "free") || !strcmp(nm, "len") || !strcmp(nm, "exec")) na = 1;
                else na = t->nargs;
            }
            else { nm = t->name; na = t->nargs; }
        } else if (in->a.kind == IR_O_REG) {
            Ex tg = getr(d, in->a.reg);
            nm = tg.s; /* will leak into call string */
            na = 2;
            /* build call with function pointer expression */
            char args[512] = "";
            for (int a = 0; a < na; a++) {
                Ex e = getr(d, ARG[a]);
                char bb[512];
                if (a) strncat(args, ", ", sizeof(args) - strlen(args) - 1);
                strncat(args, bare(e.s, bb, sizeof bb), sizeof(args) - strlen(args) - 1);
                ex_free(e);
            }
            Ex call = exf("%s(%s)", nm, args);
            ex_free(tg);
            setr(d, 0, call);
            if (emit_call) *emit_call = 1;
            break;
        }
        char args[512] = "";
        for (int a = 0; a < na; a++) {
            Ex e = getr(d, ARG[a]);
            char bb[512];
            if (a) strncat(args, ", ", sizeof(args) - strlen(args) - 1);
            strncat(args, bare(e.s, bb, sizeof bb), sizeof(args) - strlen(args) - 1);
            ex_free(e);
        }
        Ex call = exf("%s(%s)", nm, args);
        if (t && t->kind == 3 && t->builtin && !strcmp(t->builtin, "strcmp")) {
            Ex a0 = getr(d, ARG[0]), a1 = getr(d, ARG[1]);
            ex_free(call);
            setr(d, 0, ex_bin("==", a0, a1));
            if (emit_call) *emit_call = 0;
            break;
        }
        if ((!t && in->a.kind == IR_O_ADDR) || (t && t->kind == 3 && t->builtin &&
            strcmp(t->builtin, "print") && strcmp(t->builtin, "putc") &&
            strcmp(t->builtin, "alloc") && strcmp(t->builtin, "free") &&
            strcmp(t->builtin, "len") && strcmp(t->builtin, "exec") &&
            strcmp(t->builtin, "read") && strcmp(t->builtin, "strcmp"))) {
            ex_free(call);
            break;
        }
        if (t && t->kind == 3 && (!strcmp(nm, "print") || !strcmp(nm, "putc") || !strcmp(nm, "exec"))) {
            /* Skip print of absolute addresses left by elided fail paths. */
            if (na == 1 && d->has[ARG[0]] && d->reg[ARG[0]].s[0] >= '0' && d->reg[ARG[0]].s[0] <= '9') {
                long long v = atoll(d->reg[ARG[0]].s);
                if (v > 0x400000 && v < 0x500000) { ex_free(call); break; }
            }
            emit(d, depth, "%s;", call.s);
            ex_free(call);
        } else {
            setr(d, 0, call);
            if (emit_call) *emit_call = 1;
        }
        break;
    }
    default: break;
    }
}

static Ex br_cond(D *d, const IrInsn *br, const IrBlock *b) {
    /* Prefer setcc result compared to 0:  setcc; zext; cmp x,0; br.eq -> if (!setcc) */
    const IrInsn *cmp = NULL, *set = NULL;
    for (int j = b->ninsns - 2; j >= 0; j--) {
        if (!cmp && (b->insns[j].op == IR_CMP || b->insns[j].op == IR_TEST)) cmp = &b->insns[j];
        if (!set && b->insns[j].op == IR_SETCC) set = &b->insns[j];
        if (cmp && set) break;
    }
    if (cmp && cmp->op == IR_CMP && cmp->b.kind == IR_O_IMM && cmp->b.imm == 0 && set &&
        cmp->a.kind == IR_O_REG && d->has[cmp->a.reg]) {
        Ex v = getr(d, cmp->a.reg);
        if (br->cc == IR_CC_EQ) return ex_un("!", v);  /* branch if zero => if (!v) taken */
        return v;
    }
    return cond_from(d, cmp, br->cc);
}


/* ---- Dominators / postdominators (reducible structuring) ---- */

static void ir_succs(const IrFunc *f, int b, int *succs, int *ns) {
    *ns = 0;
    if (b < 0 || b >= f->nblocks) return;
    const IrBlock *bl = &f->blocks[b];
    if (bl->nsucc > 0) {
        for (int i = 0; i < bl->nsucc && i < 2; i++) succs[(*ns)++] = bl->succ[i];
        return;
    }
    const IrInsn *t = bl->ninsns ? &bl->insns[bl->ninsns - 1] : NULL;
    if (!t) return;
    if (t->op == IR_JMP && t->a.kind == IR_O_BLOCK) succs[(*ns)++] = t->a.block;
    else if (t->op == IR_BR) { succs[(*ns)++] = t->a.block; succs[(*ns)++] = t->b.block; }
}

static int dom_intersect(int *idom, int b1, int b2) {
    while (b1 != b2) {
        while (b1 > b2) b1 = idom[b1];
        while (b2 > b1) b2 = idom[b2];
    }
    return b1;
}

static int *compute_idom(const IrFunc *f) {
    int n = f->nblocks;
    if (n <= 0) return NULL;
    int *idom = malloc((size_t)n * sizeof(int));
    int *pred_n = calloc((size_t)n, sizeof(int));
    int **pred = calloc((size_t)n, sizeof(int *));
    int *fill = calloc((size_t)n, sizeof(int));
    if (!idom || !pred_n || !pred || !fill) { free(idom); free(pred_n); free(pred); free(fill); return NULL; }
    for (int b = 0; b < n; b++) {
        int succs[2], ns = 0; ir_succs(f, b, succs, &ns);
        for (int i = 0; i < ns; i++) if (succs[i] >= 0 && succs[i] < n) pred_n[succs[i]]++;
    }
    for (int b = 0; b < n; b++) if (pred_n[b]) pred[b] = calloc((size_t)pred_n[b], sizeof(int));
    for (int b = 0; b < n; b++) {
        int succs[2], ns = 0; ir_succs(f, b, succs, &ns);
        for (int i = 0; i < ns; i++) {
            int s = succs[i];
            if (s >= 0 && s < n && pred[s]) pred[s][fill[s]++] = b;
        }
    }
    for (int b = 0; b < n; b++) idom[b] = -1;
    idom[0] = 0;
    int changed = 1, guard = 0;
    while (changed && guard++ < n * n) {
        changed = 0;
        for (int b = 1; b < n; b++) {
            int new_idom = -1;
            for (int i = 0; i < pred_n[b]; i++) {
                int p = pred[b][i];
                if (idom[p] < 0) continue;
                new_idom = (new_idom < 0) ? p : dom_intersect(idom, p, new_idom);
            }
            if (new_idom >= 0 && idom[b] != new_idom) { idom[b] = new_idom; changed = 1; }
        }
    }
    for (int b = 0; b < n; b++) free(pred[b]);
    free(pred); free(pred_n); free(fill);
    return idom;
}

static int dominates(const int *idom, int a, int b) {
    if (!idom || a < 0 || b < 0) return 0;
    int guard = 0;
    while (guard++ < 10000) {
        if (b == a) return 1;
        if (b == idom[b]) return a == b;
        b = idom[b];
        if (b < 0) return 0;
    }
    return 0;
}

/* True when some edge u->v has v not dominating u while v is a DFS ancestor of u
 * (a retreating non-back edge). Only meaningful for the function's reachable CFG. */
static int cfg_irreducible(const IrFunc *f, const int *idom) {
    int n = f->nblocks;
    if (!idom || n <= 1) return 0;
    int *parent = malloc((size_t)n * sizeof(int));
    int *seen = calloc((size_t)n, sizeof(int));
    int *stack = malloc((size_t)n * sizeof(int));
    if (!parent || !seen || !stack) { free(parent); free(seen); free(stack); return 0; }
    for (int i = 0; i < n; i++) parent[i] = -1;
    int sp = 0; stack[sp++] = 0; seen[0] = 1;
    while (sp) {
        int b = stack[--sp];
        int succs[2], ns = 0; ir_succs(f, b, succs, &ns);
        for (int i = 0; i < ns; i++) {
            int s = succs[i];
            if (s < 0 || s >= n) continue;
            if (!seen[s]) { seen[s] = 1; parent[s] = b; stack[sp++] = s; }
        }
    }
    int bad = 0;
    for (int b = 0; b < n && !bad; b++) {
        if (!seen[b]) continue;
        int succs[2], ns = 0; ir_succs(f, b, succs, &ns);
        for (int i = 0; i < ns; i++) {
            int s = succs[i];
            if (s < 0 || s >= n || !seen[s]) continue;
            /* Is s an ancestor of b in the DFS tree? */
            int anc = 0, x = b, g = 0;
            while (x >= 0 && g++ < n) { if (x == s) { anc = 1; break; } x = parent[x]; }
            if (anc && !dominates(idom, s, b)) { bad = 1; break; }
        }
    }
    free(parent); free(seen); free(stack);
    return bad;
}

/* ---- Structuring ----
 * Effective CFG: edges into runtime fail blocks (bounds / div-zero checks
 * that call a runtime helper with a constant message) are dropped, so a
 * check becomes straight-line code. Loops come from back edges u->h where
 * h dominates u (natural loops). if/else joins are immediate
 * postdominators. Irreducible main is refused earlier with E402.
 */
typedef struct {
    int n;
    int (*succ)[2];
    int *nsucc;
    int *idom, *ipdom;      /* ipdom: n means "function exit" */
    unsigned char *fail;
    int *loop_exit;         /* per header: exit block, -1 none; -2 not a header */
    unsigned char *inloop;  /* n*n: inloop[h*n+b] */
    int *bound;             /* per block: array length proven by a dropped check, 0 none */
} G;

static int is_fail_block(D *d, const IrFunc *f, int bi) {
    const IrBlock *tb = &f->blocks[bi];
    int saw_fail = 0;
    for (int k = 0; k < tb->ninsns; k++) {
        const IrInsn *in = &tb->insns[k];
        if (is_prolog(in) || is_epilog(in) || in->op == IR_NOP || in->op == IR_TRAP) continue;
        if (in->op == IR_JMP || in->op == IR_RET) continue;
        if (in->op == IR_ADDR || in->op == IR_ZEXT || in->op == IR_SEXT) continue;
        if (in->op == IR_ADD || in->op == IR_SUB) {
            if (in->dst.kind == IR_O_REG && in->dst.reg == 4) continue; /* stack alignment */
            return 0;
        }
        if (in->op == IR_MOV && in->a.kind != IR_O_IMM) return 0;
        if (in->op == IR_MOV) continue;
        if (in->op == IR_CALL && in->a.kind == IR_O_ADDR) {
            Fun *t = fby(d, in->a.addr);
            if (!t || t->kind == 3) { saw_fail = 1; continue; }
        }
        return 0;
    }
    /* Constant message argument: addr rdi,[abs] */
    int msg = 0;
    for (int k = 0; k < tb->ninsns; k++)
        if (tb->insns[k].op == IR_ADDR && tb->insns[k].dst.kind == IR_O_REG && tb->insns[k].dst.reg == 7 &&
            tb->insns[k].a.base == IR_NOREG) msg = 1;
    return saw_fail && msg;
}

static int *dom_tree(int n, int entry, int (*succ)[2], const int *nsucc) {
    int *rpo = malloc((size_t)n * sizeof(int)), *order = malloc((size_t)n * sizeof(int));
    int *st = malloc((size_t)n * 2 * sizeof(int)), *seen = calloc((size_t)n, sizeof(int));
    int *idom = malloc((size_t)n * sizeof(int));
    int *npred = calloc((size_t)n, sizeof(int)), *pred = malloc((size_t)n * (size_t)n * sizeof(int) + sizeof(int));
    if (!rpo || !order || !st || !seen || !idom || !npred || !pred) {
        free(rpo); free(order); free(st); free(seen); free(idom); free(npred); free(pred); return NULL;
    }
    for (int b = 0; b < n; b++) for (int s = 0; s < nsucc[b]; s++) { int v = succ[b][s]; pred[v * n + npred[v]++] = b; }
    /* iterative postorder */
    int cnt = 0, sp = 0;
    int *it = calloc((size_t)n, sizeof(int));
    st[sp++] = entry; seen[entry] = 1;
    while (sp) {
        int b = st[sp - 1];
        if (it[b] < nsucc[b]) {
            int v = succ[b][it[b]++];
            if (!seen[v]) { seen[v] = 1; st[sp++] = v; }
        } else { order[cnt++] = b; sp--; }
    }
    free(it);
    for (int i = 0; i < n; i++) rpo[i] = -1;
    for (int i = 0; i < cnt; i++) rpo[order[i]] = cnt - 1 - i;  /* rpo number */
    for (int i = 0; i < n; i++) idom[i] = -1;
    idom[entry] = entry;
    int changed = 1;
    while (changed) {
        changed = 0;
        for (int i = cnt - 1; i >= 0; i--) {
            int b = order[i];
            if (b == entry) continue;
            int ni = -1;
            for (int k = 0; k < npred[b]; k++) {
                int p = pred[b * n + k];
                if (idom[p] < 0) continue;
                if (ni < 0) { ni = p; continue; }
                int x = p, y = ni;
                while (x != y) {
                    while (rpo[x] > rpo[y]) x = idom[x];
                    while (rpo[y] > rpo[x]) y = idom[y];
                }
                ni = x;
            }
            if (ni >= 0 && idom[b] != ni) { idom[b] = ni; changed = 1; }
        }
    }
    free(rpo); free(order); free(st); free(seen); free(npred); free(pred);
    return idom;
}

static int g_dominates(const G *g, int a, int b) {
    for (int guard = 0; guard <= g->n; guard++) {
        if (b == a) return 1;
        if (b < 0 || g->idom[b] == b || g->idom[b] < 0) return 0;
        b = g->idom[b];
    }
    return 0;
}

static void g_free(G *g) {
    free(g->succ); free(g->nsucc); free(g->idom); free(g->ipdom); free(g->fail);
    free(g->loop_exit); free(g->inloop); free(g->bound);
}

static const IrInsn *last_cmp(const IrBlock *b) {
    for (int j = b->ninsns - 2; j >= 0; j--)
        if (b->insns[j].op == IR_CMP || b->insns[j].op == IR_TEST) return &b->insns[j];
    return NULL;
}

/* Follow blocks that hold nothing but an unconditional jump. */
static int thread(const IrFunc *f, int b) {
    for (int guard = 0; guard < f->nblocks && b >= 0 && b < f->nblocks; guard++) {
        const IrBlock *bl = &f->blocks[b];
        if (bl->ninsns != 1 || bl->insns[0].op != IR_JMP || bl->insns[0].a.kind != IR_O_BLOCK) break;
        if (bl->insns[0].a.block == b) break;
        b = bl->insns[0].a.block;
    }
    return b;
}

static int g_build(D *d, const IrFunc *f, G *g) {
    int n = f->nblocks;
    memset(g, 0, sizeof(*g));
    g->n = n;
    g->succ = calloc((size_t)n + 1, sizeof(*g->succ));
    g->nsucc = calloc((size_t)n + 1, sizeof(int));
    g->fail = calloc((size_t)n, 1);
    g->loop_exit = malloc((size_t)n * sizeof(int));
    g->inloop = calloc((size_t)n * (size_t)n, 1);
    g->bound = calloc((size_t)n, sizeof(int));
    if (!g->succ || !g->nsucc || !g->fail || !g->loop_exit || !g->inloop || !g->bound) return -1;
    for (int b = 0; b < n; b++) g->fail[b] = (unsigned char)is_fail_block(d, f, b);
    for (int b = 0; b < n; b++) {
        const IrBlock *bl = &f->blocks[b];
        const IrInsn *t = bl->ninsns ? &bl->insns[bl->ninsns - 1] : NULL;
        int s[2], ns = 0;
        if (g->fail[b]) { g->nsucc[b] = 0; continue; }
        if (t && t->op == IR_RET) ns = 0;
        else if (t && t->op == IR_TRAP) ns = 0;
        else if (t && t->op == IR_JMP) { if (t->a.kind == IR_O_BLOCK) s[ns++] = t->a.block; }
        else if (t && t->op == IR_BR) {
            int a = t->a.block, c = t->b.block;
            if (!g->fail[a]) s[ns++] = a;
            if (!g->fail[c] && c != a) s[ns++] = c;
            if (ns == 1 && (g->fail[a] || g->fail[c])) {
                const IrInsn *cmp = last_cmp(bl);
                if (cmp && cmp->op == IR_CMP && cmp->b.kind == IR_O_IMM && cmp->b.imm > 0) g->bound[s[0]] = (int)cmp->b.imm;
            }
        } else for (int k = 0; k < bl->nsucc && k < 2; k++) s[ns++] = bl->succ[k];
        for (int k = 0; k < ns; k++) s[k] = thread(f, s[k]);
        if (ns == 2 && s[0] == s[1]) ns = 1;
        for (int k = 0; k < ns; k++) g->succ[b][k] = s[k];
        g->nsucc[b] = ns;
    }
    g->idom = dom_tree(n, 0, g->succ, g->nsucc);
    /* Postdominators: reverse graph with virtual exit n. */
    int (*rs)[2] = calloc((size_t)n + 1, sizeof(*rs));
    int *rns = calloc((size_t)n + 1, sizeof(int));
    int *rcap = calloc((size_t)n + 1, sizeof(int));
    int ok = rs && rns && rcap;
    /* reverse edges can exceed 2 per node; collapse: use a dense list */
    int *radj = ok ? calloc((size_t)(n + 1) * (size_t)(n + 1), sizeof(int)) : NULL;
    if (ok && radj) {
        for (int b = 0; b < n; b++) {
            if (g->nsucc[b] == 0) radj[n * (n + 1) + rcap[n]++] = b;
            for (int k = 0; k < g->nsucc[b]; k++) { int v = g->succ[b][k]; radj[v * (n + 1) + rcap[v]++] = b; }
        }
        /* Postdominator via simple iterative set intersection on bitsets (small n). */
        int W = n + 1;
        unsigned char *pd = malloc((size_t)W * (size_t)W);
        if (pd) {
            for (int b = 0; b < W; b++) memset(pd + (size_t)b * W, b == n ? 0 : 1, (size_t)W);
            pd[(size_t)n * W + n] = 1;
            int ch = 1;
            while (ch) {
                ch = 0;
                for (int b = n - 1; b >= 0; b--) {
                    unsigned char tmp[W];
                    int any = 0;
                    if (g->nsucc[b] == 0) { memcpy(tmp, pd + (size_t)n * W, (size_t)W); any = 1; }
                    for (int k = 0; k < g->nsucc[b]; k++) {
                        unsigned char *s = pd + (size_t)g->succ[b][k] * W;
                        if (!any) { memcpy(tmp, s, (size_t)W); any = 1; }
                        else for (int i = 0; i < W; i++) tmp[i] &= s[i];
                    }
                    if (!any) memset(tmp, 0, (size_t)W);
                    tmp[b] = 1;
                    if (memcmp(tmp, pd + (size_t)b * W, (size_t)W)) { memcpy(pd + (size_t)b * W, tmp, (size_t)W); ch = 1; }
                }
            }
            g->ipdom = malloc((size_t)W * sizeof(int));
            for (int b = 0; b < n && g->ipdom; b++) {
                /* ipdom = strict postdominator p such that every other strict pdom of b also pdoms p */
                int best = -1;
                for (int p = 0; p < W; p++) {
                    if (p == b || !pd[(size_t)b * W + p]) continue;
                    int okp = 1;
                    for (int q = 0; q < W; q++)
                        if (q != b && q != p && pd[(size_t)b * W + q] && !pd[(size_t)p * W + q]) { okp = 0; break; }
                    if (okp) { best = p; break; }
                }
                g->ipdom[b] = best;
            }
            free(pd);
        }
    }
    free(radj); free(rs); free(rns); free(rcap);
    if (!g->idom || !g->ipdom) return -1;
    /* Natural loops. */
    for (int h = 0; h < n; h++) g->loop_exit[h] = -2;
    for (int u = 0; u < n; u++)
        for (int k = 0; k < g->nsucc[u]; k++) {
            int h = g->succ[u][k];
            if (!g_dominates(g, h, u)) continue;
            g->loop_exit[h] = -1;
            unsigned char *in = g->inloop + (size_t)h * n;
            int *st = malloc((size_t)n * sizeof(int)); int sp = 0;
            if (!st) continue;
            in[h] = 1;
            if (!in[u]) { in[u] = 1; st[sp++] = u; }
            while (sp) {
                int x = st[--sp];
                for (int y = 0; y < n; y++)
                    for (int kk = 0; kk < g->nsucc[y]; kk++)
                        if (g->succ[y][kk] == x && !in[y]) { in[y] = 1; st[sp++] = y; }
            }
            free(st);
        }
    for (int h = 0; h < n; h++) {
        if (g->loop_exit[h] == -2) continue;
        unsigned char *in = g->inloop + (size_t)h * n;
        int ex = -1;
        int ip = g->ipdom[h];
        if (ip >= 0 && ip < n && !in[ip]) ex = ip;
        for (int b = 0; b < n && ex < 0; b++) {
            if (!in[b]) continue;
            for (int k = 0; k < g->nsucc[b]; k++) if (!in[g->succ[b][k]]) { ex = g->succ[b][k]; break; }
        }
        g->loop_exit[h] = ex;
    }
    return 0;
}

typedef struct { int header, exit; } LCtx;

typedef struct { Ex reg[16]; int has[16]; int nstk; } Snap;
static void snap_take(D *d, Snap *s) {
    for (int i = 0; i < 16; i++) { s->has[i] = d->has[i]; if (d->has[i]) s->reg[i] = ex(d->reg[i].s); }
    s->nstk = d->nstk;
}
static void snap_restore(D *d, Snap *s, int keep) {
    for (int i = 0; i < 16; i++) {
        if (d->has[i]) ex_free(d->reg[i]);
        d->has[i] = s->has[i];
        if (s->has[i]) d->reg[i] = keep ? ex(s->reg[i].s) : s->reg[i];
    }
    while (d->nstk > s->nstk) ex_free(d->stk[--d->nstk]);
}

static int block_emits(const IrBlock *b) {
    for (int k = 0; k < b->ninsns; k++) {
        IrOp op = b->insns[k].op;
        if (op == IR_STORE || op == IR_CALL || op == IR_SYSCALL) return 1;
    }
    return 0;
}

static void emit_ret(D *d, int depth) {
    if (d->cur->kind != 2) {
        char bb[1024];
        if (d->has[0]) emit(d, depth, "return %s;", bare(d->reg[0].s, bb, sizeof bb));
        else emit(d, depth, "return 0;");
    }
}

static int g_budget;

static int ret_only(const IrBlock *b) {
    if (!b->ninsns || b->insns[b->ninsns - 1].op != IR_RET) return 0;
    for (int k = 0; k < b->ninsns - 1; k++)
        if (!is_epilog(&b->insns[k]) && b->insns[k].op != IR_NOP) return 0;
    return 1;
}

/* Before the first control-flow statement, declare every local not yet
 * declared by its first straight-line assignment. */
static void flush_decls(D *d) {
    if (!d->flat) return;
    d->flat = 0;
    for (int i = 0; i < d->cur->nslots; i++)
        if (d->cur->slots[i].arg < 0 && !d->declared[i] && !d->cur->slots[i].hidden) {
            d->declared[i] = 1;
            if (d->cur->slots[i].alias[0]) { decl_agg(d, i, 1); continue; }
            emit(d, 1, "let %s = 0;%s", d->cur->slots[i].name,
                 d->cur->slots[i].hint == 2 ? " // hint: pointer" : "");
        }
}
static void structure(D *d, const IrFunc *f, G *g, int bi, int stop, const LCtx *lc, int depth, int enter);

/* Join for branches whose arms leave early: lowest-index block reachable
 * from both arms (REX lays code out in source order). */
static int common_reach(const IrFunc *f, G *g, int from, int a, int b, const LCtx *lc, int stop) {
    (void)f;
    int n = g->n;
    unsigned char *ra = calloc((size_t)n, 1), *rb = calloc((size_t)n, 1);
    int *st = malloc((size_t)n * sizeof(int));
    int best = -1;
    if (ra && rb && st) {
        for (int side = 0; side < 2; side++) {
            unsigned char *r = side ? rb : ra;
            int sp = 0;
            st[sp++] = side ? b : a; r[side ? b : a] = 1;
            while (sp) {
                int x = st[--sp];
                if (x == stop || (lc && (x == lc->header || x == lc->exit))) continue;
                for (int k = 0; k < g->nsucc[x]; k++) {
                    int y = g->succ[x][k];
                    if (y == from || r[y]) continue;
                    r[y] = 1; st[sp++] = y;
                }
            }
        }
        for (int x = 0; x < n; x++)
            if (ra[x] && rb[x] && !(lc && (x == lc->header || x == lc->exit))) { best = x; break; }
    }
    free(ra); free(rb); free(st);
    return best;
}

/* do-while: the only back edge comes from a quiet block ending in
 * br(header, exit). */
static int find_latch(const IrFunc *f, G *g, int h) {
    int latch = -1, nback = 0;
    for (int u = 0; u < g->n; u++)
        for (int k = 0; k < g->nsucc[u]; k++)
            if (g->succ[u][k] == h && g_dominates(g, h, u)) { latch = u; nback++; }
    if (nback != 1 || latch == h) return -1;
    const IrBlock *lb = &f->blocks[latch];
    if (!lb->ninsns || lb->insns[lb->ninsns - 1].op != IR_BR || g->nsucc[latch] != 2 || block_emits(lb)) return -1;
    int other = g->succ[latch][0] == h ? g->succ[latch][1] : g->succ[latch][0];
    if (other != g->loop_exit[h]) return -1;
    return latch;
}

static char *arm_text(D *d, const IrFunc *f, G *g, int bi, int stop, const LCtx *lc, int depth) {
    char *buf = NULL; size_t n = 0;
    FILE *save = d->out, *m = open_memstream(&buf, &n);
    if (!m) { structure(d, f, g, bi, stop, lc, depth, 0); return strdup(""); }
    d->out = m;
    structure(d, f, g, bi, stop, lc, depth, 0);
    fclose(m);
    d->out = save;
    return buf ? buf : strdup("");
}

/* A block that only compares the switch value: load [rsp]; cmp r, K; br. */
static int case_test(const IrBlock *b, long long *k, IrCond *cc, int head) {
    if (b->ninsns < 2) return 0;
    const IrInsn *br = &b->insns[b->ninsns - 1];
    if (br->op != IR_BR || (br->cc != IR_CC_NE && br->cc != IR_CC_EQ)) return 0;
    const IrInsn *cmp = &b->insns[b->ninsns - 2];
    if (cmp->op != IR_CMP || cmp->b.kind != IR_O_IMM || cmp->b.imm < 0) return 0;
    if (head) {
        const IrInsn *ld = b->ninsns >= 3 ? &b->insns[b->ninsns - 3] : NULL;
        if (!ld || ld->op != IR_LOAD || ld->a.kind != IR_O_MEM || ld->a.base != 4 || ld->a.disp != 0) return 0;
        *k = cmp->b.imm; *cc = br->cc;
        return 1;
    }
    for (int i = 0; i < b->ninsns - 2; i++) {
        const IrInsn *in = &b->insns[i];
        if (in->op == IR_LOAD && in->a.kind == IR_O_MEM && in->a.base == 4 && in->a.disp == 0 && in->a.index == IR_NOREG) continue;
        if (in->op == IR_PUSH || in->op == IR_MOV || in->op == IR_LOAD || in->op == IR_POP) continue;
        return 0;
    }
    int top = 0;
    for (int i = 0; i < b->ninsns - 2; i++)
        if (b->insns[i].op == IR_LOAD && b->insns[i].a.base == 4 && b->insns[i].a.disp == 0) top = 1;
    if (!top) return 0;
    *k = cmp->b.imm; *cc = br->cc;
    return 1;
}

/* REX lowers switch to: push value; repeat { load [rsp]; cmp K; br.ne next, case }.
 * All arms join at the block that pops the value. */
static int try_switch(D *d, const IrFunc *f, G *g, int bi, const LCtx *lc, int depth) {
    const IrBlock *b = &f->blocks[bi];
    long long k; IrCond cc;
    if (!case_test(b, &k, &cc, 1)) return 0;
    int join = g->ipdom[bi];
    if (join < 0 || join >= g->n) return 0;
    long long keys[64]; int targets[64], nc = 0;
    int cur = bi, deflt = -1;
    while (nc < 64) {
        const IrBlock *cb = &f->blocks[cur];
        long long kk; IrCond c2;
        if (cur != bi && (block_emits(cb) || !case_test(cb, &kk, &c2, 0))) { deflt = cur; break; }
        if (cur == bi) { kk = k; c2 = cc; }
        const IrInsn *br = &cb->insns[cb->ninsns - 1];
        int eq = thread(f, c2 == IR_CC_EQ ? br->a.block : br->b.block);
        int ne = thread(f, c2 == IR_CC_EQ ? br->b.block : br->a.block);
        keys[nc] = kk; targets[nc] = eq; nc++;
        if (ne == join) { deflt = -1; break; }
        cur = ne;
    }
    /* switch value: top of the symbolic stack */
    if (!d->nstk) return 0;
    char bb[1024];
    emit(d, depth, "switch (%s) {", bare(d->stk[d->nstk - 1].s, bb, sizeof bb));
    for (int i = 0; i < nc; i++) {
        Snap s; snap_take(d, &s);
        char *a = arm_text(d, f, g, targets[i], join, lc, depth + 2);
        snap_restore(d, &s, 0);
        emit(d, depth + 1, "case %lld: {", keys[i]);
        fputs(a, d->out); free(a);
        emit(d, depth + 1, "}");
    }
    if (deflt >= 0 && deflt != join) {
        Snap s; snap_take(d, &s);
        char *a = arm_text(d, f, g, deflt, join, lc, depth + 2);
        snap_restore(d, &s, 0);
        emit(d, depth + 1, "default: {");
        fputs(a, d->out); free(a);
        emit(d, depth + 1, "}");
    }
    emit(d, depth, "}");
    return 1;
}

static void structure(D *d, const IrFunc *f, G *g, int bi, int stop, const LCtx *lc, int depth, int enter) {
    if (depth > 48 || g_budget <= 0) {
        emit(d, depth, "// E402: control flow too tangled to structure here (block %d)", bi);
        g_budget = 0;
        return;
    }
    while (bi >= 0 && bi < g->n && g_budget-- > 0) {
        if (!enter) {
            if (bi == stop) {
                if (ret_only(&f->blocks[bi])) emit_ret(d, depth);
                return;
            }
            if (lc && bi == lc->header) { emit(d, depth, "continue;"); return; }
            if (lc && bi == lc->exit) { emit(d, depth, "break;"); return; }
            if (g->loop_exit[bi] != -2 && !(lc && lc->header == bi)) {
                int latch;
                flush_decls(d);
                LCtx inner = { bi, g->loop_exit[bi] };
                const IrBlock *hb = &f->blocks[bi];
                const IrInsn *ht = hb->ninsns ? &hb->insns[hb->ninsns - 1] : NULL;
                unsigned char *in = g->inloop + (size_t)bi * g->n;
                if (ht && ht->op == IR_BR && g->nsucc[bi] == 2 && !block_emits(hb) &&
                    (!in[ht->a.block] || !in[ht->b.block]) && (in[ht->a.block] || in[ht->b.block])) {
                    for (int k = 0; k < hb->ninsns - 1; k++) step(d, &hb->insns[k], depth, NULL);
                    Ex c = br_cond(d, ht, hb);
                    int body = in[ht->a.block] ? thread(f, ht->a.block) : thread(f, ht->b.block);
                    if (!in[ht->a.block]) c = ex_un("!", c);
                    { char bb[1024]; emit(d, depth, "while (%s) {", bare(c.s, bb, sizeof bb)); }
                    ex_free(c);
                    Snap s; snap_take(d, &s);
                    structure(d, f, g, body, bi, &inner, depth + 1, 0);
                    snap_restore(d, &s, 0);
                    emit(d, depth, "}");
                } else if ((latch = find_latch(f, g, bi)) >= 0) {
                    const IrBlock *lb = &f->blocks[latch];
                    const IrInsn *lt = &lb->insns[lb->ninsns - 1];
                    LCtx dl = { latch, inner.exit };
                    emit(d, depth, "do {");
                    Snap s; snap_take(d, &s);
                    structure(d, f, g, bi, latch, &dl, depth + 1, 1);
                    for (int k = 0; k < lb->ninsns - 1; k++) step(d, &lb->insns[k], depth + 1, NULL);
                    Ex c = br_cond(d, lt, lb);
                    if (thread(f, lt->a.block) != bi) c = ex_un("!", c);
                    { char bb[1024]; emit(d, depth, "} while (%s);", bare(c.s, bb, sizeof bb)); }
                    ex_free(c);
                    snap_restore(d, &s, 0);
                } else {
                    emit(d, depth, "while (1) {");
                    Snap s; snap_take(d, &s);
                    structure(d, f, g, bi, bi, &inner, depth + 1, 1);
                    snap_restore(d, &s, 0);
                    emit(d, depth, "}");
                }
                bi = inner.exit;
                if (bi < 0) return;
                continue;
            }
        }
        enter = 0;
        d->bound = g->bound[bi];
        const IrBlock *b = &f->blocks[bi];
        const IrInsn *term = b->ninsns ? &b->insns[b->ninsns - 1] : NULL;
        int nbody = term && ir_is_terminator(term->op) ? b->ninsns - 1 : b->ninsns;
        for (int k = 0; k < nbody; k++) step(d, &b->insns[k], depth, NULL);
        if (g->nsucc[bi] == 0) {
            if (term && term->op == IR_RET) emit_ret(d, depth);
            return;
        }
        if (g->nsucc[bi] == 1) {
            if (term && term->op == IR_BR) d->cmp = NULL; /* dropped check */
            bi = g->succ[bi][0];
            continue;
        }
        /* two-way branch */
        flush_decls(d);
        Ex c = br_cond(d, term, b);
        int ta = thread(f, term->a.block), fb = thread(f, term->b.block);
        char bb[1024];
        if (try_switch(d, f, g, bi, lc, depth)) { bi = g->ipdom[bi]; ex_free(c); if (bi >= g->n) return; continue; }
        if (lc && ((ta == lc->exit && fb == lc->header) || (fb == lc->exit && ta == lc->header))) {
            if (ta != lc->exit) c = ex_un("!", c);
            emit(d, depth, "if (%s) {", bare(c.s, bb, sizeof bb)); ex_free(c);
            emit(d, depth + 1, "break;");
            emit(d, depth, "}");
            if (stop == lc->header) return;
            emit(d, depth, "continue;");
            return;
        }
        if (lc && (ta == lc->exit || ta == lc->header || fb == lc->exit || fb == lc->header)) {
            int jump = (ta == lc->exit || ta == lc->header) ? ta : fb;
            int other = jump == ta ? fb : ta;
            if (jump != ta) c = ex_un("!", c);
            emit(d, depth, "if (%s) {", bare(c.s, bb, sizeof bb)); ex_free(c);
            emit(d, depth + 1, jump == lc->exit ? "break;" : "continue;");
            emit(d, depth, "}");
            bi = other;
            continue;
        }
        int join = g->ipdom[bi];
        if (join >= g->n) join = -1;
        if (join < 0 || ret_only(&f->blocks[join])) join = (ta == stop || fb == stop) ? stop : common_reach(f, g, bi, ta, fb, lc, stop);
        int ret_join = join >= 0 && ret_only(&f->blocks[join]);
        Snap s; snap_take(d, &s);
        char *armA = ta == join ? strdup("") : arm_text(d, f, g, ta, join, lc, depth + 1);
        snap_restore(d, &s, 1);
        char *armB = fb == join ? strdup("") : arm_text(d, f, g, fb, join, lc, depth + 1);
        if (!*armA && !*armB) { /* both empty: keep side effects only */ }
        else if (!*armA) {
            c = ex_un("!", c);
            emit(d, depth, "if (%s) {", bare(c.s, bb, sizeof bb));
            fputs(armB, d->out); emit(d, depth, "}");
        } else if (!*armB) {
            emit(d, depth, "if (%s) {", bare(c.s, bb, sizeof bb));
            fputs(armA, d->out); emit(d, depth, "}");
        } else {
            emit(d, depth, "if (%s) {", bare(c.s, bb, sizeof bb));
            fputs(armA, d->out);
            emit(d, depth, "} else {");
            fputs(armB, d->out);
            emit(d, depth, "}");
        }
        ex_free(c); free(armA); free(armB);
        snap_restore(d, &s, 0);
        if (join < 0 || ret_join) return;
        bi = join;
    }
}

/* After the discarded pass: arrays (indexed + bounds-checked) and structs
 * (runs of zero-initialized adjacent locals, never indexed) get aliases.
 * Struct declarations print before the function. */
static void finish_hints(D *d, const IrFunc *f, Fun *fi) {
    for (int i = 0; i < fi->nslots; i++) {
        Slot *b = &fi->slots[i];
        if (b->hint != 1 || b->alen < 2) continue;
        snprintf(b->alias, sizeof b->alias, "%s[0]", b->name);
        for (int k = 1; k < b->alen; k++) {
            Slot *c = slot_at(fi, b->off - 8 * k);
            if (!c || c->arg >= 0) continue;
            c->hidden = 1;
            snprintf(c->alias, sizeof c->alias, "%s[%d]", b->name, k);
        }
    }
    if (!f->nblocks) return;
    const IrBlock *b0 = &f->blocks[0];
    for (int k = 0; k < b0->ninsns; k++) {
        int run = 0, off0 = 0;
        while (k + run < b0->ninsns) {
            const IrInsn *in = &b0->insns[k + run];
            if (in->op != IR_STORE || in->a.kind != IR_O_IMM || in->a.imm != 0 || in->dst.kind != IR_O_MEM ||
                in->dst.base != 5 || in->dst.index != IR_NOREG) break;
            if (run == 0) off0 = (int)in->dst.disp;
            else if ((int)in->dst.disp != off0 - 8 * run) break;
            run++;
        }
        if (run >= 2) {
            Slot *base = slot_at(fi, off0);
            int ok = base && base->hint == 0 && base->arg < 0 && !base->hidden;
            for (int j = 1; ok && j < run; j++) { Slot *c = slot_at(fi, off0 - 8 * j); if (!c || c->hint || c->hidden || c->arg >= 0) ok = 0; }
            if (ok) {
                base->sid = ++d->nstruct;
                base->nfield = run;
                fprintf(d->out, "struct S%d {", base->sid);
                for (int j = 0; j < run; j++) fprintf(d->out, " f%d;", 8 * j);
                fprintf(d->out, " } // hint: recovered struct\n\n");
                snprintf(base->alias, sizeof base->alias, "%s.f0", base->name);
                for (int j = 1; j < run; j++) {
                    Slot *c = slot_at(fi, off0 - 8 * j);
                    c->hidden = 1;
                    snprintf(c->alias, sizeof c->alias, "%s.f%d", base->name, 8 * j);
                }
            }
            k += run - 1;
        }
    }
}

static void decompile_fun(D *d, Fun *fi) {
    if (fi->kind == 1 || fi->kind == 3) return;
    const IrFunc *f = NULL;
    for (int i = 0; i < d->m->nfuncs; i++) if (d->m->funcs[i].addr == fi->addr) { f = &d->m->funcs[i]; break; }
    if (!f) return;

    /* reset env */
    for (int i = 0; i < 16; i++) { if (d->has[i]) ex_free(d->reg[i]); d->has[i] = 0; }
    while (d->nstk) ex_free(d->stk[--d->nstk]);
    d->cmp = NULL;
    d->cur = fi;
    G g;
    if (g_build(d, f, &g) == 0) {
        /* Pass 1 (discarded) collects hints; pass 2 prints. */
        for (int pass = 0; pass < 2; pass++) {
            for (int i = 0; i < 16; i++) { if (d->has[i]) ex_free(d->reg[i]); d->has[i] = 0; }
            while (d->nstk) ex_free(d->stk[--d->nstk]);
            for (int a = 0; a < fi->nargs; a++) setr(d, ARG[a], exf("%c", 'a' + a));
            d->cmp = NULL;
            memset(d->declared, 0, sizeof d->declared);
            d->flat = 1;
            g_budget = 20000;
            if (pass == 0) {
                char *buf = NULL; size_t n = 0;
                FILE *save = d->out, *m = open_memstream(&buf, &n);
                if (!m) continue;
                d->out = m;
                structure(d, f, &g, 0, -1, NULL, 1, 0);
                fclose(m); free(buf);
                d->out = save;
                finish_hints(d, f, fi);
                fprintf(d->out, "fn %s(", fi->name);
                for (int a = 0; a < fi->nargs; a++) fprintf(d->out, "%s%c", a ? ", " : "", 'a' + a);
                fprintf(d->out, ") {\n");
            } else {
                memset(d->written, 0, sizeof d->written);
                structure(d, f, &g, 0, -1, NULL, 1, 0);
            }
        }
    } else {
        fprintf(d->out, "fn %s() {\n", fi->name);
        emit(d, 1, "// E600: could not build the control-flow graph for this function");
    }
    g_free(&g);
    fprintf(d->out, "}\n\n");
}

int rex_decompile(const char *inpath, const char *outpath, int verbose) {
    RexElf e;
    CfgProgram p;
    char err[256];
    { int _rc = rex_bin_open(inpath, &e, err, sizeof(err)); if (_rc) { fprintf(stderr, "rex: %s\n", err); return _rc; } }
    { int _c = cfg_build(&e, &p, err, sizeof(err)); if (_c) { fprintf(stderr, "rex: %s\n", err); rex_elf_free(&e); return _c; } }
    IrModule *m = x86_lift(&p, err, sizeof(err));
    if (!m) { fprintf(stderr, "rex: %s\n", err); cfg_free(&p); rex_elf_free(&e); return REX_E300_LIFT; }
    for (int fi = 0; fi < m->nfuncs; fi++) {
        if (strcmp(m->funcs[fi].name, "main") != 0 && m->funcs[fi].addr != p.main_addr) continue;
        int *idom = compute_idom(&m->funcs[fi]);
        if (idom && cfg_irreducible(&m->funcs[fi], idom)) {
            free(idom);
            int _e = rex_errf(err, sizeof(err), REX_E402_IRREDUCIBLE, "%s", m->funcs[fi].name);
            fprintf(stderr, "rex: %s\n", err);
            ir_module_free(m); cfg_free(&p); rex_elf_free(&e);
            return _e;
        }
        free(idom);
    }
    FILE *out = fopen(outpath, "w");
    if (!out) { fprintf(stderr, "rex: decompile: cannot write %s\n", outpath); ir_module_free(m); cfg_free(&p); rex_elf_free(&e); return REX_E600_DECOMPILE; }

    D d = {0};
    d.out = out; d.m = m; d.cfg = &p; d.verbose = verbose;
    d.fun = calloc((size_t)m->nfuncs, sizeof(Fun));
    d.nfun = m->nfuncs;
    classify(&d);

    fprintf(out, "// recovered by rex decompile\n");
    fprintf(out, "// REX-built ELF64 only; names are invented\n\n");

    for (int i = 0; i < d.nfun; i++) if (d.fun[i].kind == 0) decompile_fun(&d, &d.fun[i]);
    for (int i = 0; i < d.nfun; i++) if (d.fun[i].kind == 2) decompile_fun(&d, &d.fun[i]);

    if (verbose) {
        fprintf(stderr, "rex: decompile: %d functions\n", m->nfuncs);
        for (int i = 0; i < d.nfun; i++)
            fprintf(stderr, "  %-12s kind=%d nargs=%d builtin=%s\n",
                    d.fun[i].name, d.fun[i].kind, d.fun[i].nargs,
                    d.fun[i].builtin ? d.fun[i].builtin : "-");
    }
    for (int i = 0; i < 16; i++) if (d.has[i]) ex_free(d.reg[i]);
    while (d.nstk) ex_free(d.stk[--d.nstk]);
    free(d.stk);
    free(d.fun);
    fclose(out);
    ir_module_free(m); cfg_free(&p); rex_elf_free(&e);
    return 0;
}
