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
            if (neg) { Ex res = exf("(%s %s %s)", l, neg, r); free(l); free(o); free(r); ex_free(a); return res; }
            /* De Morgan: push the ! inside && / || so a negated chain reads as
             * one short-circuit condition instead of !(... || ...). */
            if (!strcmp(o, "||") || !strcmp(o, "&&")) {
                const char *dual = o[0] == '|' ? "&&" : "||";
                Ex res = ex_bin(dual, ex_un("!", ex(l)), ex_un("!", ex(r)));
                free(l); free(o); free(r); ex_free(a); return res;
            }
            free(l); free(o); free(r);
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
    unsigned clob;  /* caller-saved registers this function may modify (transitively) */
    int reach;      /* reached from main by a call or a taken address */
    int shape;      /* kind 3 by the shape of a REX string helper, not by a syscall */
    int taken;      /* its address is a value (operand or pointer in data): a callp target */
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
    Ex xreg[32];        /* foreign SSE xmm pseudo-regs: lo 16..31, hi 32..47 */
    int xhas[32];
    Ex *stk;
    int nstk, cstk;
    Fun *cur;
    const IrInsn *cmp;
    unsigned char declared[MAX_LOC];
    unsigned char written[MAX_LOC];
    int flat;
    int bound;          /* array length proven for the block being emitted */
    int nstruct;
    int need_udiv;      /* emit the udiv/urem helpers */
    int need_mulh;      /* emit the umulh/smulh helpers (one-operand 64-bit mul) */
    int need_callp;     /* emit callp: a call through a function pointer */
    int callp_n;        /* arguments callp passes on: the most any target takes, at most 5 */
    char callp_why[160];/* why callp cannot stand for every pointer call (match refuses, E605) */
    int need_gfr;       /* global gfr hands a new frame block to a local */
    int frame;          /* foreign: current function's stack lives in heap block fr (0 = off, else half size) */
    int fp;             /* foreign: rbp is a real frame pointer (mov %rsp,%rbp), not a general callee-saved register */
    int blob;           /* foreign: data sections live in one heap block gmem */
    uint64_t blo, bhi;  /* address range of that block */
    int foreign;        /* not REX-built (has section headers): register variables, exact widths */
    const RexElf *elf;
    struct { uint64_t addr; int width; long long init; } glob[256];
    int nglob;
    unsigned vused;     /* register variables used in the current function */
    int nx, nxmax;      /* spill temporaries x0.. in the current function */
    int fixed_x;        /* >= 0: compare spills use x<fixed_x>, x<fixed_x+1> */
    int depth;          /* indentation of the statement being stepped */
    Ex cmpa, cmpb;      /* foreign: cmp/test operands as of the compare */
    int cmp_snap;           /* no control flow emitted yet at function level */
} D;

static const int ARG[6] = { 7, 6, 2, 1, 8, 9 };

static Fun *fby(D *d, uint64_t a) {
    for (int i = 0; i < d->nfun; i++) if (d->fun[i].addr == a) return &d->fun[i];
    return NULL;
}

/* Caller-saved registers an unknown callee may clobber: rax rcx rdx rsi rdi r8-r11. */
#define CLOB_SAVED ((1u<<0)|(1u<<1)|(1u<<2)|(1u<<6)|(1u<<7)|(1u<<8)|(1u<<9)|(1u<<10)|(1u<<11))

/* For each function, the set of caller-saved registers it may modify, including
 * through the functions it calls (fixpoint over the call graph). A call to a
 * builtin, an external address or a register is treated as a full clobber. A
 * value a caller leaves in a caller-saved register across a call to a function
 * that provably never writes that register survives the call. */
/* The lift borrows a scratch register by saving it to rsp-136 and loading it
 * back in the same block (x86_lift.c scratch_save): a write between the two,
 * with nothing in between that moves rsp, calls or reuses the slot, leaves the
 * register as the caller had it. */
static int is_slot136(const IrOperand *o) {
    return o->kind == IR_O_MEM && o->base == 4 && o->index == IR_NOREG && o->disp == -136 && o->width == 8;
}
static int scratch_bracketed(const IrBlock *B, int k, int r) {
    int lo = -1, hi = -1;
    const IrInsn *self = &B->insns[k];
    int restore = self->op == IR_LOAD && is_slot136(&self->a);   /* the load back itself */
    for (int j = k - 1; j >= 0; j--) {
        const IrInsn *q = &B->insns[j];
        if (q->op == IR_STORE && is_slot136(&q->dst) && q->a.kind == IR_O_REG && q->a.reg == r && q->a.width == 8) { lo = j; break; }
        if (q->op == IR_CALL || q->op == IR_SYSCALL || q->op == IR_PUSH || q->op == IR_POP || (q->dst.kind == IR_O_REG && q->dst.reg == 4) ||
            (q->op == IR_STORE && q->dst.kind == IR_O_MEM && q->dst.base == 4 && q->dst.index == IR_NOREG && q->dst.disp > -144 && q->dst.disp < -128)) return 0;
    }
    if (lo < 0) return 0;
    if (restore) return 1;
    for (int j = k + 1; j < B->ninsns; j++) {
        const IrInsn *q = &B->insns[j];
        if (q->op == IR_LOAD && q->dst.kind == IR_O_REG && q->dst.reg == r && q->dst.width == 8 && is_slot136(&q->a)) { hi = j; break; }
        if (q->op == IR_CALL || q->op == IR_SYSCALL || q->op == IR_PUSH || q->op == IR_POP || (q->dst.kind == IR_O_REG && q->dst.reg == 4) ||
            (q->op == IR_STORE && q->dst.kind == IR_O_MEM && q->dst.base == 4 && q->dst.index == IR_NOREG && q->dst.disp > -144 && q->dst.disp < -128)) return 0;
    }
    return hi >= 0;
}

static void compute_clobbers(D *d) {
    int n = d->nfun;
    for (int i = 0; i < n; i++) {
        const IrFunc *f = &d->m->funcs[i];
        unsigned b = 0;
        for (int bl = 0; bl < f->nblocks; bl++) {
            const IrBlock *B = &f->blocks[bl];
            for (int k = 0; k < B->ninsns; k++) {
                const IrInsn *in = &B->insns[k];
                if (in->op == IR_SYSCALL) b |= CLOB_SAVED;
                if (in->op == IR_CALL) {
                    if (in->a.kind == IR_O_ADDR) {
                        Fun *t = fby(d, in->a.addr);
                        if (!t || t->kind == 3) b |= CLOB_SAVED;  /* builtin/external */
                    } else b |= CLOB_SAVED;                       /* indirect */
                }
                if (in->dst.kind == IR_O_REG && in->dst.reg >= 0 && in->dst.reg < 16 &&
                    !scratch_bracketed(B, k, in->dst.reg))
                    b |= 1u << in->dst.reg;
            }
        }
        d->fun[i].clob = b & CLOB_SAVED;
    }
    for (int it = 0; it <= n; it++) {
        int changed = 0;
        for (int i = 0; i < n; i++) {
            if (d->fun[i].clob == CLOB_SAVED) continue;
            const IrFunc *f = &d->m->funcs[i];
            unsigned m = d->fun[i].clob;
            for (int bl = 0; bl < f->nblocks && m != CLOB_SAVED; bl++) {
                const IrBlock *B = &f->blocks[bl];
                for (int k = 0; k < B->ninsns; k++) {
                    const IrInsn *in = &B->insns[k];
                    if (in->op != IR_CALL || in->a.kind != IR_O_ADDR) continue;
                    Fun *t = fby(d, in->a.addr);
                    if (t && t->kind != 3) m |= t->clob;
                }
            }
            if (m != d->fun[i].clob) { d->fun[i].clob = m; changed = 1; }
        }
        if (!changed) break;
    }
}

static void emit(D *d, int depth, const char *fmt, ...);
/* True when s uses the variable name vn as a whole token. */
static int mentions_v(const char *s, const char *vn) {
    size_t n = strlen(vn);
    for (const char *q = strstr(s, vn); q; q = strstr(q + 1, vn)) {
        char nx = q[n];
        if ((q == s || !(q[-1] == '_' || (q[-1] >= 'a' && q[-1] <= 'z') || (q[-1] >= '0' && q[-1] <= '9'))) && !(nx >= '0' && nx <= '9')) return 1;
    }
    return 0;
}
static void setr(D *d, int r, Ex v) {
    if (r >= 16 && r < 48) {
        /* long packed-lane expressions are spilled to a temporary so chained
         * SSE ops do not grow without bound. */
        if (d->foreign && strlen(v.s) > 400) {
            char bb[2048];
            int k = d->nx++;
            emit(d, d->depth, "x%d = %s;", k, bare(v.s, bb, sizeof bb));
            ex_free(v); v = exf("x%d", k);
        }
        if (d->xhas[r - 16]) ex_free(d->xreg[r - 16]);
        d->xreg[r - 16] = v; d->xhas[r - 16] = 1;
        return;
    }
    if (r < 0 || r > 15) { ex_free(v); return; }
    if (d->has[r]) ex_free(d->reg[r]);
    /* Runaway expressions (register recurrences in optimized code) become
     * an explicit raw register instead of growing without bound. */
    if (strlen(v.s) > 400) {
        if (d->foreign) {
            /* Spill to a fresh temporary so later expressions stay exact. */
            char bb[1024];
            int k = d->nx++;
            emit(d, d->depth, "x%d = %s;", k, bare(v.s, bb, sizeof bb));
            ex_free(v); v = exf("x%d", k);
        } else { ex_free(v); v = exf("r%d", r); }
    }
    d->reg[r] = v; d->has[r] = 1;
}
static Ex getr(D *d, int r) {
    if (r >= 16 && r < 48) return d->xhas[r - 16] ? ex(d->xreg[r - 16].s) : ex("0");
    if (r >= 0 && r < 16 && d->has[r]) return ex(d->reg[r].s);
    if (d->foreign && r >= 0 && r < 16) { d->vused |= 1u << r; return exf("v%d", r); }
    return exf("r%d", r);
}
/* Exact low-width views for foreign code (REX values are 64-bit). */
static Ex ex_mask(Ex e, int width) {
    long long v;
    if (width >= 8) return e;
    /* non-PIE code moves data addresses through 32-bit registers; gmem is a
     * 64-bit heap pointer, so an address-valued expression keeps all bits */
    if (width == 4 && mentions_v(e.s, "gmem") && !strstr(e.s, "*(")) return e;
    unsigned long long m = width == 4 ? 4294967295ULL : width == 2 ? 65535ULL : 255ULL;
    if (is_num(e.s, &v) && v >= 0 && (unsigned long long)v <= m) return e;
    char suf[32]; snprintf(suf, sizeof suf, " & %llu)", m);
    size_t L = strlen(e.s), S = strlen(suf);
    if (L > S && !strcmp(e.s + L - S, suf) && e.s[0] == '(') return e;
    /* already narrower: "(x & k)" at the top level with k = 2^n-1 <= m */
    if (e.s[0] == '(' && L > 3 && e.s[L - 1] == ')') {
        const char *amp = strrchr(e.s, '&');
        long long k;
        char num[32];
        if (amp && amp > e.s + 1 && amp[-1] == ' ' && amp[1] == ' ' && (size_t)(e.s + L - 1 - (amp + 2)) < sizeof num) {
            memcpy(num, amp + 2, (size_t)(e.s + L - 1 - (amp + 2)));
            num[e.s + L - 1 - (amp + 2)] = 0;
            int depth = 0, top = 1;
            for (const char *q = e.s + 1; q < amp; q++) { if (*q == '(') depth++; else if (*q == ')') { if (--depth < 0) top = 0; } }
            if (top && depth == 0 && is_num(num, &k) && k >= 0 && (unsigned long long)k <= m && ((unsigned long long)k & ((unsigned long long)k + 1)) == 0) return e;
        }
    }

    Ex r = exf("(%s & %llu)", e.s, m);
    ex_free(e);
    return r;
}
/* True when e is a non-negative literal or already masked to <= 32 bits. */
static int ex_nonneg(Ex e) {
    long long v;
    if (is_num(e.s, &v)) return v >= 0;
    Ex t = ex_mask(ex(e.s), 4);
    int same = !strcmp(t.s, e.s);
    ex_free(t);
    return same;
}
static Ex ex_sext(Ex e, int width) {
    if (width >= 8) return e;
    long long v;
    if (is_num(e.s, &v)) {
        int sh = 64 - 8 * width;
        long long s = (long long)((unsigned long long)v << sh) >> sh;
        ex_free(e); return exf("%lld", s);
    }
    e = ex_mask(e, width);
    Ex r = exf("((%s << %d) >> %d)", e.s, 64 - 8 * width, 64 - 8 * width);
    ex_free(e);
    return r;
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
static int data_addr(const D *d, uint64_t a, long long *init, int width) {
    if (!d->elf) return 0;
    for (int i = 0; i < d->elf->nsh; i++) {
        const RexShdr *s = &d->elf->sh[i];
        if (!(s->flags & 2) || (s->flags & 4) || a < s->addr || a + (uint64_t)width > s->addr + s->size) continue;
        long long v = 0;
        if (s->type != 8 && s->offset + (a - s->addr) + (uint64_t)width <= d->elf->size)
            memcpy(&v, d->elf->data + s->offset + (a - s->addr), (size_t)width);
        if (width < 8) v &= (long long)((1ULL << (8 * width)) - 1);
        *init = v;
        return 1;
    }
    return 0;
}
/* Foreign code that indexes or takes the address of data gets the data
 * sections copied into one heap block (gmem); addresses become offsets. */
#define BLOB_SLACK 256  /* end pointers (one past the last row) stay inside gmem */
static int in_blob(const D *d, int64_t v) { return d->blob && (uint64_t)v >= d->blo && (uint64_t)v < d->bhi + BLOB_SLACK; }
static int is_ident(const char *s) {
    if (!s || !((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') || *s == '_')) return 0;
    for (; *s; s++) if (!((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') || (*s >= '0' && *s <= '9') || *s == '_')) return 0;
    return 1;
}
static Ex daddr(D *d, int64_t v) {
    if (in_blob(d, v)) return exf("(gmem + %llu)", (unsigned long long)((uint64_t)v - d->blo));
    return exf("%lld", (long long)v);
}
static void blob_range(D *d) {
    d->blo = ~0ULL; d->bhi = 0;
    for (int i = 0; d->elf && i < d->elf->nsh; i++) {
        const RexShdr *s = &d->elf->sh[i];
        if (!(s->flags & 2) || (s->flags & 4) || s->addr < 0x1000 || !s->size) continue;
        if (!(s->flags & 1) && strncmp(s->name, ".rodata", 7)) continue;  /* data, bss, rodata only */
        /* A dynamically linked program's loader tables are not its data. */
        if (d->elf->dynamic && (!strcmp(s->name, ".dynamic") || !strcmp(s->name, ".got") || !strcmp(s->name, ".got.plt") ||
            !strcmp(s->name, ".init_array") || !strcmp(s->name, ".fini_array") ||
            !strcmp(s->name, ".preinit_array") || !strcmp(s->name, ".tm_clone_table"))) continue;
        if (s->addr < d->blo) d->blo = s->addr;
        if (s->addr + s->size > d->bhi) d->bhi = s->addr + s->size;
    }
    if (d->bhi <= d->blo || d->bhi - d->blo > (1u << 20)) d->blo = d->bhi = 0;
}
static int op_points_data(const D *d, const IrOperand *o) {
    if (o->kind == IR_O_IMM) return o->width >= 4 && (uint64_t)o->imm >= d->blo && (uint64_t)o->imm < d->bhi;
    if (o->kind == IR_O_MEM) return (o->base != IR_NOREG || o->index != IR_NOREG) && o->base != 4 && o->base != 5 &&
        (uint64_t)o->disp >= d->blo && (uint64_t)o->disp < d->bhi + BLOB_SLACK;  /* end-pointer idiom: base+disp with disp one past the data */
    return 0;
}
/* Does emitted code point into [lo, hi)? The same operand rules blob_scan uses. */
static int refs_range(D *d, uint64_t lo, uint64_t hi) {
    uint64_t slo = d->blo, shi = d->bhi;
    d->blo = lo; d->bhi = hi;
    int hit = 0;
    for (int fi = 0; fi < d->m->nfuncs && !hit; fi++) {
        const IrFunc *f = &d->m->funcs[fi];
        if (!strcmp(f->name, "start") || !strcmp(f->name, "_start") || d->fun[fi].kind == 1) continue;
        for (int b = 0; b < f->nblocks && !hit; b++)
            for (int k = 0; k < f->blocks[b].ninsns && !hit; k++) {
                const IrInsn *in = &f->blocks[b].insns[k];
                if (in->op == IR_CALL || in->op == IR_JMP || in->op == IR_BR) continue;
                hit = op_points_data(d, &in->a) || op_points_data(d, &in->b) || op_points_data(d, &in->dst) ||
                      (in->op == IR_ADDR && in->a.kind == IR_O_MEM && in->a.base == IR_NOREG && in->a.index == IR_NOREG &&
                       (uint64_t)in->a.disp >= lo && (uint64_t)in->a.disp < hi);
            }
    }
    d->blo = slo; d->bhi = shi;
    return hit;
}
static void blob_scan(D *d) {
    blob_range(d);
    /* In a dynamically linked program, .data and .bss also hold the C
     * runtime's own state, and they sit pages away from .rodata. Span only
     * the sections the emitted code points into, so gmem stays small. */
    if (d->foreign && d->bhi && d->elf && d->elf->dynamic) {
        uint64_t lo = ~0ULL, hi = 0;
        for (int i = 0; i < d->elf->nsh; i++) {
            const RexShdr *sc = &d->elf->sh[i];
            if (!sc->size || sc->addr < d->blo || sc->addr + sc->size > d->bhi) continue;
            if (!(sc->flags & 2) || (sc->flags & 4)) continue;
            if (!refs_range(d, sc->addr, sc->addr + sc->size)) continue;
            if (sc->addr < lo) lo = sc->addr;
            if (sc->addr + sc->size > hi) hi = sc->addr + sc->size;
        }
        if (hi > lo) { d->blo = lo; d->bhi = hi; } else d->blo = d->bhi = 0;
    }
    if (!d->foreign || d->bhi == 0) return;
    for (int fi = 0; fi < d->m->nfuncs && !d->blob; fi++) {
        const IrFunc *f = &d->m->funcs[fi];
        if (!strcmp(f->name, "start") || !strcmp(f->name, "_start")) continue;
        if (d->elf && d->elf->dynamic && d->fun[fi].kind == 1) continue;   /* C runtime helpers: not emitted */
        for (int b = 0; b < f->nblocks && !d->blob; b++)
            for (int k = 0; k < f->blocks[b].ninsns; k++) {
                const IrInsn *in = &f->blocks[b].insns[k];
                if (in->op == IR_CALL || in->op == IR_JMP || in->op == IR_BR) continue;
                if (op_points_data(d, &in->a) || op_points_data(d, &in->b) || op_points_data(d, &in->dst) ||
                    (in->op == IR_ADDR && in->a.kind == IR_O_MEM && in->a.base == IR_NOREG && in->a.index == IR_NOREG &&
                     (uint64_t)in->a.disp >= d->blo && (uint64_t)in->a.disp < d->bhi)) { d->blob = 1; break; }
            }
    }
}
static const char *glob_name(D *d, uint64_t a, int width) {
    static char nm[32];
    long long init;
    if (!data_addr(d, a, &init, width)) return NULL;
    int i;
    for (i = 0; i < d->nglob; i++) if (d->glob[i].addr == a) break;
    if (i == d->nglob) {
        if (d->nglob >= 256) return NULL;
        d->glob[i].addr = a; d->glob[i].width = width; d->glob[i].init = init; d->nglob++;
    }
    snprintf(nm, sizeof nm, "g_%llx", (unsigned long long)a);
    return nm;
}

static Ex mem_ex_(D *d, const IrOperand *o) {
    if (d->foreign && o->base == IR_NOREG && o->index == IR_NOREG && in_blob(d, o->disp)) {
        Ex a = daddr(d, o->disp);
        Ex r = exf("*(%s)", a.s);
        ex_free(a);
        return r;
    }
    if (d->foreign && o->base == IR_NOREG && o->index == IR_NOREG) {
        const char *g = glob_name(d, (uint64_t)o->disp, o->width ? o->width : 8);
        if (g) return ex(g);
    }
    if (d->frame && (o->base == 4 || (o->base == 5 && d->fp))) {
        Ex b = getr(d, o->base);
        if (o->index != IR_NOREG) {
            Ex ix = getr(d, o->index);
            if (o->scale != 1) ix = ex_bin("*", ix, exf("%d", o->scale));
            b = ex_bin("+", b, ix);
        }
        if (o->disp) b = ex_bin(o->disp < 0 ? "-" : "+", b, exf("%lld", o->disp < 0 ? -(long long)o->disp : (long long)o->disp));
        Ex r = exf("*(%s)", b.s);
        ex_free(b);
        return r;
    }
    if (d->foreign && o->base == 4 && o->index == IR_NOREG) {
        const char *n = slot_name(d->cur, 1000000 + (int)o->disp);
        if (n) return ex(n);
    }
    /* In foreign code without a frame pointer, rbp is a register like any other. */
    int rbpf = o->base == 5 && (!d->foreign || d->fp);
    if (rbpf && o->index == IR_NOREG) {
        const char *n = slot_name(d->cur, (int)o->disp);
        if (n) return ex(n);
        return exf("m%d", (int)o->disp);
    }
    if (!d->foreign && o->base == 4 && o->index == IR_NOREG && o->disp >= 0 && o->disp % 8 == 0) {
        int k = (int)(o->disp / 8);
        if (k < d->nstk) return ex(d->stk[d->nstk - 1 - k].s);
    }
    if (rbpf && o->index != IR_NOREG) {
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
    if (!rbpf && o->base != IR_NOREG && o->index == IR_NOREG && o->disp <= 0 && o->disp % 8 == 0 && d->has[o->base]) {
        for (int i = 0; i < d->cur->nslots; i++) {
            Slot *ps = &d->cur->slots[i];
            if (!ps->ptr_sid || strcmp(ps->name, d->reg[o->base].s)) continue;
            for (int j = 0; j < d->cur->nslots; j++)
                if (d->cur->slots[j].sid == ps->ptr_sid && -o->disp / 8 < d->cur->slots[j].nfield)
                    return exf("%s->f%lld", ps->name, (long long)-o->disp);
        }
    }
    if (!rbpf && o->base != IR_NOREG && d->has[o->base])
        for (int i = 0; i < d->cur->nslots; i++)
            if (!strcmp(d->cur->slots[i].name, d->reg[o->base].s) && !d->cur->slots[i].alias[0])
                slot_hint(d->cur, d->cur->slots[i].off, 2);
    Ex b = rbpf ? ex("fp") : (o->base != IR_NOREG ? getr(d, o->base) : ex("0"));
    if (o->index != IR_NOREG) {
        Ex ix = getr(d, o->index);
        if (o->scale != 1) ix = ex_bin("*", ix, exf("%d", o->scale));
        b = ex_bin("+", b, ix);
    }
    if (o->disp) b = ex_bin("+", b, daddr(d, o->disp));
    /* Heap/pointer cell: *(B + X*8) -> B[X], *(B + 8k) -> B[k] (REX scales by 8). */
    char *l, *op, *r;
    if (!d->foreign && split_top(b.s, &l, &op, &r)) {
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
    case IR_O_REG: return d->foreign ? ex_mask(getr(d, o->reg), o->width) : getr(d, o->reg);
    case IR_O_IMM:
        if (o->imm == (int64_t)0x8000000000000000ULL)
            return ex("(0 - 9223372036854775807 - 1)");
        if (o->width >= 4 && in_blob(d, o->imm)) return daddr(d, o->imm);
        return exf("%lld", (long long)o->imm);
    case IR_O_MEM: return d->foreign ? ex_mask(mem_ex(d, o), o->width) : mem_ex(d, o);
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
    case IR_DIVS: case IR_DIVU: return "/"; case IR_REMS: case IR_REMU: return "%";
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
static Ex opnd(D *d, const IrInsn *cmp, int which) {
    if (d->foreign && d->cmp_snap && cmp == d->cmp) return ex(which ? d->cmpb.s : d->cmpa.s);
    return op_ex(d, which ? &cmp->b : &cmp->a);
}
static Ex cond_from(D *d, const IrInsn *cmp, IrCond cc) {
    if (!cmp) return ex("1");
    if (cmp->op == IR_CMP) {
        int w = cmp->a.width ? cmp->a.width : 8;
        int sgn = cc == IR_CC_LT || cc == IR_CC_LE || cc == IR_CC_GT || cc == IR_CC_GE;
        if (cc == IR_CC_NEG || cc == IR_CC_POS) {
            Ex a = opnd(d, cmp, 0), b = opnd(d, cmp, 1);
            if (d->foreign && w < 8) { a = ex_sext(a, w); b = ex_sext(b, w); }
            return ex_bin(cc == IR_CC_NEG ? "<" : ">=", ex_bin("-", a, b), ex("0"));
        }
        if (d->foreign && w < 8 && sgn)
            return ex_bin(cop(cc), ex_sext(opnd(d, cmp, 0), w), ex_sext(opnd(d, cmp, 1), w));
        Ex a = opnd(d, cmp, 0), b = opnd(d, cmp, 1);
        if (d->foreign && w < 8) {
            /* equality and unsigned order compare the low w bytes, and registers
             * print masked to them: an immediate must be masked too (cmp $-1,%esi
             * is esi == 0xffffffff, never == -1) */
            Ex *s2[2] = { &a, &b };
            for (int k = 0; k < 2; k++) {
                long long v;
                if (!is_num(s2[k]->s, &v)) continue;
                unsigned long long m = (1ULL << (8 * w)) - 1, u = (unsigned long long)v & m;
                if (u == (unsigned long long)v) continue;
                ex_free(*s2[k]); *s2[k] = exf("%llu", u);
            }
        }
        return ex_bin(cop(cc), a, b);
    }
    Ex v;
    if (cmp->a.kind == cmp->b.kind && cmp->a.kind == IR_O_REG && cmp->a.reg == cmp->b.reg) v = opnd(d, cmp, 0);
    else v = ex_bin("&", opnd(d, cmp, 0), opnd(d, cmp, 1));
    if (d->foreign && cmp->a.width && cmp->a.width < 8 && cc != IR_CC_EQ && cc != IR_CC_NE) v = ex_sext(v, cmp->a.width);
    if (cc == IR_CC_EQ) return ex_bin("==", v, ex("0"));
    if (cc == IR_CC_NE) return ex_bin("!=", v, ex("0"));
    if (cc == IR_CC_NEG || cc == IR_CC_LT) return ex_bin("<", v, ex("0"));
    if (cc == IR_CC_POS || cc == IR_CC_GE) return ex_bin(">=", v, ex("0"));
    if (cc == IR_CC_LE) return ex_bin("<=", v, ex("0"));
    if (cc == IR_CC_GT) return ex_bin(">", v, ex("0"));
    return v;
}

static int frame_has_fp(const IrFunc *f);
static void classify(D *d) {
    for (int i = 0; i < d->nfun; i++) {
        Fun *fi = &d->fun[i];
        const IrFunc *f = &d->m->funcs[i];
        fi->addr = f->addr;
        if (!strcmp(f->name, "start")) { fi->kind = 1; snprintf(fi->name, sizeof(fi->name), "start"); continue; }
        /* In a dynamically linked program the entry is the C runtime's _start,
         * which only hands main to __libc_start_main: the start stub, not code
         * of the program's own. */
        if (d->elf && d->elf->dynamic && f->addr == d->elf->entry && f->addr != d->cfg->main_addr) {
            fi->kind = 1; snprintf(fi->name, sizeof(fi->name), "start"); continue;
        }
        /* The C runtime's own helpers in such a program: never called by the
         * program's code, so they are not part of its source. Matched by
         * symbol name only, so nothing the program defines is ever hidden. */
        if (d->elf && d->elf->dynamic && f->addr != d->cfg->main_addr) {
            static const char *crt[] = { "_init", "_fini", "deregister_tm_clones", "register_tm_clones",
                "__do_global_dtors_aux", "frame_dummy", "_dl_relocate_static_pie", "__libc_csu_init",
                "__libc_csu_fini" };
            int is_crt = 0;
            for (size_t c = 0; c < sizeof crt / sizeof crt[0]; c++) if (!strcmp(f->name, crt[c])) is_crt = 1;
            if (is_crt) { fi->kind = 1; snprintf(fi->name, sizeof(fi->name), "%.31s", f->name); continue; }
        }
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

        /* rbp is a frame pointer in REX code and in foreign code that sets it from rsp */
        int rbpfr = !d->foreign || frame_has_fp(f);
        /* Args: early stores of arg regs, or first uses. */
        if (f->nblocks) {
            const IrBlock *b0 = &f->blocks[0];
            unsigned bwr = 0;   /* registers written so far: foreign code stores an arg register's own value only before that */
            for (int k = 0; k < b0->ninsns && k < 24; k++) {
                const IrInsn *in = &b0->insns[k];
                if (rbpfr && in->op == IR_STORE && in->dst.kind == IR_O_MEM && in->dst.base == 5 &&
                    in->a.kind == IR_O_REG && !(d->foreign && (bwr >> in->a.reg & 1))) {
                    for (int a = 0; a < 6; a++) if (in->a.reg == ARG[a]) {
                        if (a + 1 > fi->nargs) fi->nargs = a + 1;
                        add_slot(fi, (int)in->dst.disp, a);
                    }
                }
                /* print_int style: mov rdi -> rax early */
                if (in->op == IR_MOV && in->dst.kind == IR_O_REG && in->a.kind == IR_O_REG &&
                    in->a.reg == 7 && fi->nargs < 1) fi->nargs = 1;
                if (in->op == IR_CALL || in->op == IR_SYSCALL) bwr = ~0u;
                else if (in->dst.kind == IR_O_REG && in->dst.reg >= 0 && in->dst.reg < 32) bwr |= 1u << in->dst.reg;
            }
        }
        for (int b = 0; b < f->nblocks; b++)
            for (int k = 0; k < f->blocks[b].ninsns; k++) {
                const IrOperand *ops[3] = { &f->blocks[b].insns[k].dst, &f->blocks[b].insns[k].a, &f->blocks[b].insns[k].b };
                for (int o = 0; o < 3; o++) {
                    if (rbpfr && ops[o]->kind == IR_O_MEM && ops[o]->base == 5 && ops[o]->index == IR_NOREG && ops[o]->disp < 0)
                        add_slot(fi, (int)ops[o]->disp, -1);
                    /* rsp slots; a negative offset is the red zone of a leaf, which
                     * no call can clobber while the compiler keeps a value there */
                    if (d->foreign && ops[o]->kind == IR_O_MEM && ops[o]->base == 4 && ops[o]->index == IR_NOREG && ops[o]->disp > -4096)
                        add_slot(fi, 1000000 + (int)ops[o]->disp, -1);
                }
            }
        if (d->foreign && fi->kind == 0 && f->nblocks) {
            /* Arguments: arg registers read before written in the entry block. */
            unsigned wr = 0; int na = 0;
            const IrBlock *b0 = &f->blocks[0];
            for (int k = 0; k < b0->ninsns; k++) {
                const IrInsn *in = &b0->insns[k];
                const IrOperand *rd[4] = { &in->a, &in->b, in->dst.kind == IR_O_MEM ? &in->dst : NULL, NULL };
                for (int o = 0; o < 3; o++) {
                    const IrOperand *x = rd[o];
                    if (!x) continue;
                    int regs[2] = { x->kind == IR_O_REG ? x->reg : x->kind == IR_O_MEM ? x->base : -1, x->kind == IR_O_MEM ? x->index : -1 };
                    if (in->op == IR_XOR && x->kind == IR_O_REG && in->a.kind == IR_O_REG && in->b.kind == IR_O_REG && in->a.reg == in->b.reg) continue;
                    for (int q = 0; q < 2; q++)
                        for (int a = 0; a < 6; a++)
                            if (regs[q] == ARG[a] && !(wr & (1u << ARG[a])) && a + 1 > na) na = a + 1;
                }
                if (in->op == IR_CALL) break;
                if (in->dst.kind == IR_O_REG) wr |= 1u << in->dst.reg;
            }
            if (na > fi->nargs) fi->nargs = na;
        }
        if (d->foreign && fi->kind == 2) {
            fi->nargs = 0;
            for (int i = 0; i < fi->nslots; i++) if (fi->slots[i].arg >= 0) fi->slots[i].arg = -1;
        }
        /* REX's own string helpers, recognised by shape. In a gcc/clang program
         * the same shape may be the program's own loop (a char switch over a
         * string): see shape_reached below. */
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
                fi->kind = 3; fi->builtin = "strcmp"; fi->nargs = 2; fi->shape = 1;
                snprintf(fi->name, sizeof(fi->name), "strcmp");
            } else if (byte_ld && cmp0 && add1 && !has_mul && ncall == 0 && fi->nargs <= 1) {
                fi->kind = 3; fi->builtin = "len"; fi->nargs = 1; fi->shape = 1;
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

/* Foreign code: register expressions read memory lazily. Before a write
 * that may change what they read, pin them in x temporaries. name: the
 * variable written, or NULL for any memory. */
static void pin_reads(D *d, int depth, const char *name) {
    if (!d->foreign) return;
    char bb[1024];
    for (int r = 0; r < 16; r++) {
        if (!d->has[r] || r == 4 || (r == 5 && d->frame && d->fp)) continue;
        const char *e = d->reg[r].s;
        if (name ? !mentions_v(e, name) : !strstr(e, "*(")) continue;
        int k = d->nx++;
        emit(d, depth, "x%d = %s;", k, bare(e, bb, sizeof bb));
        ex_free(d->reg[r]); d->reg[r] = exf("x%d", k);
    }
    if (d->cmp_snap) {
        Ex *sn[2] = { &d->cmpa, &d->cmpb };
        for (int j = 0; j < 2; j++) {
            const char *e = sn[j]->s;
            if (name ? !mentions_v(e, name) : !strstr(e, "*(")) continue;
            int k = d->nx++;
            emit(d, depth, "x%d = %s;", k, bare(e, bb, sizeof bb));
            ex_free(*sn[j]); *sn[j] = exf("x%d", k);
        }
    }
}

/* Store src to a memory operand (narrow foreign stores keep the upper bytes). */
static void store_ex(D *d, const IrInsn *in, Ex src, int src_imm, int depth) {
    Ex dst = in->dst.kind == IR_O_MEM ? mem_ex(d, &in->dst) : op_ex(d, &in->dst);
    if (d->foreign) pin_reads(d, depth, dst.s[0] == '*' ? NULL : dst.s);
    char bb[1024];
    if (d->foreign && in->dst.kind == IR_O_MEM && in->dst.width && in->dst.width < 8 && dst.s[0] == '*') {
        /* REX stores 8 bytes: keep the bytes above the C store width. */
        unsigned long long m = in->dst.width == 4 ? 4294967295ULL : in->dst.width == 2 ? 65535ULL : 255ULL;
        emit(d, depth, "%s = (%s & %lld) | %s;", dst.s, dst.s, -(long long)m - 1, ex_mask(ex(src.s), in->dst.width).s);
        ex_free(dst); ex_free(src);
        return;
    }
    int si = -1;
    if (in->dst.kind == IR_O_MEM && in->dst.base == 5 && in->dst.index == IR_NOREG && (!d->foreign || d->fp))
        for (int i = 0; i < d->cur->nslots; i++)
            if (d->cur->slots[i].off == (int)in->dst.disp && d->cur->slots[i].arg < 0) si = i;
    if (d->foreign && !d->frame && in->dst.kind == IR_O_MEM && in->dst.base == 4 && in->dst.index == IR_NOREG)
        for (int i = 0; i < d->cur->nslots; i++)
            if (d->cur->slots[i].off == 1000000 + (int)in->dst.disp && d->cur->slots[i].arg < 0) si = i;
    int agg = si >= 0 ? agg_base(d->cur, si) : -1;
    if (agg >= 0 && !d->written[si] && !strcmp(src.s, "0") && src_imm) {
        /* zero-init of an aggregate cell: part of its declaration */
        d->written[si] = 1;
        if (!d->declared[agg]) { d->declared[agg] = 1; decl_agg(d, agg, depth); }
    } else if (agg >= 0) {
        d->written[si] = 1;
        if (!d->declared[agg]) { d->declared[agg] = 1; decl_agg(d, agg, depth); }
        emit(d, depth, "%s = %s;", dst.s, bare(src.s, bb, sizeof bb));
    } else if (si >= 0 && !d->declared[si] && d->flat && depth == 1 && is_ident(dst.s)) {
        /* A slot in an address-taken frame is a memory cell (*(fr + n)), not a
         * name: it is stored to below like any other cell, never declared. */
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
}

/* --- packed SIMD lanes (IR_VEC) ---------------------------------------------
 * An xmm register is a low/high 64-bit pseudo-register pair; each 64-bit half
 * holds 8/w lanes of width w bytes. These helpers build the REX expression for
 * a lane and reassemble a half from lanes, so a packed op becomes exact 64-bit
 * integer arithmetic that round-trips through the REX compiler. */
static Ex v_mask(Ex e, int w) {
    if (w >= 8) return e;
    return ex_bin("&", e, exf("%llu", (1ULL << (8 * w)) - 1));
}
static Ex v_lane(const char *h, int w, int i) {
    int sh = 8 * w * i;
    Ex e = sh ? ex_bin(">>", ex(h), exf("%d", sh)) : ex(h);
    return v_mask(e, w);
}
static Ex v_sext(Ex e, int w) {
    if (w >= 8) return e;
    int s = 64 - 8 * w;
    return ex_bin(">>", ex_bin("<<", e, exf("%d", s)), exf("%d", s));
}
static Ex v_place(Ex v, int w, int i) {
    int sh = 8 * w * i;
    return sh ? ex_bin("<<", v, exf("%d", sh)) : v;
}
static char *v_half(D *d, int rg) { Ex e = getr(d, rg); char *s = strdup(e.s); ex_free(e); return s; }

static void vec_op(D *d, const IrInsn *in) {
    int vop = in->vop, w = in->dst.width, dn = in->dst.reg - 16;

    if (vop == IR_V_AND || vop == IR_V_OR || vop == IR_V_XOR) {
        const char *op = vop == IR_V_AND ? "&" : vop == IR_V_OR ? "|" : "^";
        int an = in->a.reg - 16, bn = in->b.reg - 16;
        Ex lo = ex_bin(op, getr(d, 16 + an), getr(d, 16 + bn));
        Ex hi = ex_bin(op, getr(d, 32 + an), getr(d, 32 + bn));
        setr(d, 16 + dn, lo); setr(d, 32 + dn, hi);
        return;
    }
    if (vop == IR_V_SRLQ || vop == IR_V_SLLQ) {
        int an = in->a.reg - 16, k = (int)(in->b.imm & 0xff);
        for (int half = 0; half < 2; half++) {
            int rg = half ? 32 : 16;
            Ex h = getr(d, rg + an), r;
            if (k >= 64) { ex_free(h); r = exf("0"); }
            else if (vop == IR_V_SRLQ) r = ex_bin("&", ex_bin(">>", h, exf("%d", k)), exf("%llu", (1ULL << (64 - k)) - 1));
            else r = ex_bin("<<", h, exf("%d", k));
            setr(d, rg + dn, r);
        }
        return;
    }
    if (vop == IR_V_SHUFD) {
        int an = in->a.reg - 16, imm = (int)in->b.imm;
        char *lo = v_half(d, 16 + an), *hi = v_half(d, 32 + an);
        const char *src[2] = { lo, hi };
        for (int half = 0; half < 2; half++) {
            Ex acc = {0}; int have = 0;
            for (int k = 0; k < 2; k++) {
                int sel = (imm >> (2 * (half * 2 + k))) & 3;
                Ex dw = v_lane(src[sel >> 1], 4, sel & 1);
                Ex pl = v_place(dw, 4, k);
                acc = have ? ex_bin("|", acc, pl) : pl; have = 1;
            }
            setr(d, (half ? 32 : 16) + dn, acc);
        }
        free(lo); free(hi);
        return;
    }
    if (vop == IR_V_UNPCKL || vop == IR_V_UNPCKH) {
        int an = in->a.reg - 16, bn = in->b.reg - 16, srcrg = vop == IR_V_UNPCKL ? 16 : 32;
        char *ah = v_half(d, srcrg + an), *bh = v_half(d, srcrg + bn);
        int nper = 8 / w;
        for (int half = 0; half < 2; half++) {
            Ex acc = {0}; int have = 0;
            for (int k = 0; k < nper; k++) {
                int j = half * nper + k;
                Ex lane = (j % 2 == 0) ? v_lane(ah, w, j / 2) : v_lane(bh, w, j / 2);
                Ex pl = v_place(lane, w, k);
                acc = have ? ex_bin("|", acc, pl) : pl; have = 1;
            }
            setr(d, (half ? 32 : 16) + dn, acc);
        }
        free(ah); free(bh);
        return;
    }
    /* per-lane two-source arithmetic / compare */
    {
        int an = in->a.reg - 16, bn = in->b.reg - 16, nper = 8 / w;
        unsigned long long m = (1ULL << (8 * w)) - 1;
        for (int half = 0; half < 2; half++) {
            int rg = half ? 32 : 16;
            char *ah = v_half(d, rg + an), *bh = v_half(d, rg + bn);
            Ex acc = {0}; int have = 0;
            for (int i = 0; i < nper; i++) {
                Ex la = v_lane(ah, w, i), lb = v_lane(bh, w, i), f;
                switch (vop) {
                case IR_V_ADD: f = v_mask(ex_bin("+", la, lb), w); break;
                case IR_V_SUB: f = v_mask(ex_bin("-", la, lb), w); break;
                case IR_V_CMPEQ: f = exf("((%s == %s) ? %llu : 0)", la.s, lb.s, m); ex_free(la); ex_free(lb); break;
                case IR_V_CMPGT: { Ex sa = v_sext(la, w), sb = v_sext(lb, w); f = exf("((%s > %s) ? %llu : 0)", sa.s, sb.s, m); ex_free(sa); ex_free(sb); } break;
                default: ex_free(la); ex_free(lb); f = exf("0"); break;
                }
                Ex pl = v_place(f, w, i);
                acc = have ? ex_bin("|", acc, pl) : pl; have = 1;
            }
            setr(d, rg + dn, acc);
            free(ah); free(bh);
        }
    }
}

/* Functions main can reach: direct calls, and any function whose address
 * appears as an operand (a callback). Without a main every function counts. */
static void compute_reach(D *d) {
    int has_main = 0;
    for (int i = 0; i < d->nfun; i++) { d->fun[i].reach = d->fun[i].kind == 2; has_main |= d->fun[i].reach; }
    if (!has_main) { for (int i = 0; i < d->nfun; i++) d->fun[i].reach = 1; return; }
    for (int changed = 1; changed; ) {
        changed = 0;
        for (int i = 0; i < d->nfun; i++) {
            if (!d->fun[i].reach) continue;
            const IrFunc *f = &d->m->funcs[i];
            for (int b = 0; b < f->nblocks; b++)
                for (int k = 0; k < f->blocks[b].ninsns; k++) {
                    const IrInsn *in = &f->blocks[b].insns[k];
                    const IrOperand *op[3] = { &in->dst, &in->a, &in->b };
                    for (int o = 0; o < 3; o++) {
                        uint64_t v;
                        if (op[o]->kind == IR_O_ADDR) v = op[o]->addr;
                        else if (op[o]->kind == IR_O_IMM) v = (uint64_t)op[o]->imm;
                        else continue;
                        Fun *t = fby(d, v);
                        if (t && !t->reach) { t->reach = 1; changed = 1; }
                    }
                }
        }
    }
}

/* A gcc/clang program has none of REX's string helpers: a function shaped
 * like one that main reaches is the program's own (a char loop) and is
 * decompiled as such. One main never reaches stays hidden, as dead code
 * the linker pulled in (clang's SSE memcpy). */
static void foreign_args(D *d);
static void shape_reached(D *d) {
    int any = 0;
    for (int i = 0; i < d->nfun; i++) {
        Fun *fi = &d->fun[i];
        if (fi->kind != 3 || !fi->shape || !fi->reach) continue;
        fi->kind = 0; fi->builtin = NULL; fi->nargs = 0; fi->shape = 0;
        snprintf(fi->name, sizeof(fi->name), "f%d", i);
        any = 1;
    }
    if (any) { foreign_args(d); compute_clobbers(d); }
}

/* Calls through a function pointer become callp(p, ...), which picks the
 * recovered function whose original address p holds. Its targets are the
 * functions whose address is a value: an operand other than a direct call,
 * or a pointer stored in the program's data. REX takes at most 6
 * parameters, the pointer and 5 arguments; a target that needs 6, or a
 * pointer call with no recovered target at all, cannot be written, and
 * match refuses with E605 (the source is still written for reading). */
static int g_fpcall;
static char g_fpwhy[160];
int rex_decompile_fpcalls(char *why, size_t n) {
    if (g_fpcall && why && n) snprintf(why, n, "%s", g_fpwhy);
    return g_fpcall;
}
static void compute_taken(D *d) {
    for (int i = 0; i < d->nfun; i++) {
        if (d->fun[i].kind == 1 || d->fun[i].kind == 3) continue;   /* start code and runtime helpers */
        const IrFunc *f = &d->m->funcs[i];
        for (int b = 0; b < f->nblocks; b++)
            for (int k = 0; k < f->blocks[b].ninsns; k++) {
                const IrInsn *in = &f->blocks[b].insns[k];
                const IrOperand *op[3] = { &in->dst, &in->a, &in->b };
                for (int o = 0; o < 3; o++) {
                    if (o == 1 && (in->op == IR_CALL || in->op == IR_JMP)) continue;   /* a direct call or jump */
                    uint64_t v;
                    if (op[o]->kind == IR_O_ADDR) v = op[o]->addr;
                    else if (op[o]->kind == IR_O_IMM) v = (uint64_t)op[o]->imm;
                    else continue;
                    Fun *t = fby(d, v);
                    if (t) t->taken = 1;
                }
            }
    }
    const RexElf *e = d->elf;
    for (int s2 = 0; e && s2 < e->nsh; s2++) {
        const RexShdr *sh = &e->sh[s2];
        /* the program's data: not code, not the C runtime's tables or the GOT */
        if (sh->type != 1 || !(sh->flags & 2) || (sh->flags & 4) || !strncmp(sh->name, ".got", 4) ||
            !strncmp(sh->name, ".eh_frame", 9) || sh->offset > e->size || sh->size > e->size - sh->offset) continue;
        for (uint64_t o = (8 - (sh->addr & 7)) & 7; o + 8 <= sh->size; o += 8) {
            uint64_t v;
            memcpy(&v, e->data + sh->offset + o, 8);
            Fun *t = fby(d, v);
            if (t) t->taken = 1;
        }
    }
    d->callp_n = 0; d->callp_why[0] = 0;
    int nt = 0;
    for (int i = 0; i < d->nfun; i++) {
        const Fun *fi = &d->fun[i];
        if (fi->kind != 0 || !fi->taken) continue;   /* REX never calls main */
        int na = fi->nargs;
        if (na > 5) { snprintf(d->callp_why, sizeof d->callp_why, "%s takes %d arguments; a REX function takes the pointer and at most 5", fi->name, na); continue; }
        nt++;
        if (na > d->callp_n) d->callp_n = na;
    }
    if (!nt && !d->callp_why[0]) snprintf(d->callp_why, sizeof d->callp_why, "no recovered function has its address taken");
}

/* Library calls (puts, printf) reached through the PLT or a GOT slot. Counted
 * so match can refuse: the rebuilt program has no libc to call into. */
static int g_libcalls;
static char g_libname[48];

int rex_decompile_libcalls(char *name, size_t n) {
    if (g_libcalls && name && n) snprintf(name, n, "%s", g_libname);
    return g_libcalls;
}

/* Arguments of a library call. Known functions take a fixed count; a variadic
 * one (printf) takes its fixed part plus every further argument register set
 * right before the call; an unknown one takes the registers set there. */
static int lib_arity(D *d, const char *nm, int *is_void) {
    static const struct { const char *n; signed char a; char v; } T[] = {
        {"abort",0,1},{"rand",0,0},{"getchar",0,0},{"getpid",0,0},{"__stack_chk_fail",0,1},
        {"puts",1,0},{"strlen",1,0},{"malloc",1,0},{"free",1,1},{"exit",1,1},{"_exit",1,1},
        {"putchar",1,0},{"atoi",1,0},{"atol",1,0},{"abs",1,0},{"labs",1,0},{"strdup",1,0},
        {"close",1,0},{"srand",1,1},{"time",1,0},{"getenv",1,0},{"system",1,0},{"perror",1,1},
        {"fflush",1,0},{"fclose",1,0},{"sleep",1,0},{"usleep",1,0},{"isalpha",1,0},
        {"isdigit",1,0},{"isspace",1,0},{"toupper",1,0},{"tolower",1,0},
        {"strcpy",2,0},{"strcmp",2,0},{"strcat",2,0},{"strchr",2,0},{"strrchr",2,0},
        {"strstr",2,0},{"fopen",2,0},{"fputs",2,0},{"calloc",2,0},{"realloc",2,0},
        {"fputc",2,0},{"putc",2,0},{"strtok",2,0},{"signal",2,0},
        {"memcpy",3,0},{"memmove",3,0},{"memset",3,0},{"memcmp",3,0},{"strncpy",3,0},
        {"strncmp",3,0},{"strncat",3,0},{"read",3,0},{"write",3,0},{"strtol",3,0},
        {"strtoul",3,0},{"fwrite",4,0},{"fread",4,0},{"qsort",4,1},{"setvbuf",4,0},
        /* variadic: negative = fixed part */
        {"printf",-1,0},{"scanf",-1,0},{"fprintf",-2,0},{"sprintf",-2,0},{"dprintf",-2,0},
        {"sscanf",-2,0},{"fscanf",-2,0},{"open",-2,0},{"snprintf",-3,0},
    };
    *is_void = 0;
    int fixed = -1, var = 1;
    for (size_t i = 0; i < sizeof T / sizeof T[0]; i++)
        if (!strcmp(T[i].n, nm)) { *is_void = T[i].v; fixed = T[i].a < 0 ? -T[i].a : T[i].a; var = T[i].a < 0; break; }
    if (!var) return fixed;
    int n = fixed < 0 ? 0 : fixed;
    while (n < 6 && d->has[ARG[n]]) n++;
    return n;
}


static void step(D *d, const IrInsn *in, int depth, int *emit_call) {
    d->depth = depth;
    if (is_prolog(in) || is_epilog(in)) return;
    switch (in->op) {
    case IR_NOP: case IR_TRAP: case IR_SYSCALL: break;
    case IR_VEC: vec_op(d, in); break;
    case IR_PUSH: push(d, op_ex(d, &in->a)); break;
    case IR_POP:
        if (in->dst.kind == IR_O_REG) setr(d, in->dst.reg, pop(d));
        else ex_free(pop(d));
        break;
    case IR_MOV: case IR_ZEXT: case IR_SEXT:
        if (in->dst.kind == IR_O_REG) {
            if (d->foreign && in->op == IR_SEXT) setr(d, in->dst.reg, ex_sext(op_ex(d, &in->a), in->a.width));
            else setr(d, in->dst.reg, op_ex(d, &in->a));
        }
        break;
    case IR_LOAD:
        if (in->dst.kind == IR_O_REG) setr(d, in->dst.reg, op_ex(d, &in->a));
        break;
    case IR_STORE:
        store_ex(d, in, op_ex(d, &in->a), in->a.kind == IR_O_IMM, depth);
        break;
    case IR_ADDR:
        if (in->dst.kind == IR_O_REG && d->foreign && in->a.kind == IR_O_MEM && (d->frame || (in->a.base != 5 && in->a.base != 4)) &&
            !(in->a.base == IR_NOREG && in->a.index == IR_NOREG)) {
            Ex b = in->a.base != IR_NOREG ? getr(d, in->a.base) : ex("0");
            if (in->a.index != IR_NOREG) {
                Ex ix = getr(d, in->a.index);
                if (in->a.scale > 1) ix = ex_bin("*", ix, exf("%d", in->a.scale));
                b = in->a.base != IR_NOREG ? ex_bin("+", b, ix) : (ex_free(b), ix);
            }
            if (in->a.disp) b = ex_bin("+", b, daddr(d, in->a.disp));
            setr(d, in->dst.reg, b);
            break;
        }
        if (in->dst.kind == IR_O_REG) {
            if (in->a.kind == IR_O_MEM && in->a.base == IR_NOREG && in->a.index == IR_NOREG)
                setr(d, in->dst.reg, daddr(d, in->a.disp));  /* absolute address (gmem offset for data) */
            else if (in->a.kind == IR_O_MEM && in->a.base == 5 && in->a.index == IR_NOREG && (!d->foreign || d->fp) &&
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
    case IR_ADD: case IR_SUB: case IR_MUL: case IR_DIVS: case IR_REMS: case IR_DIVU: case IR_REMU:
    case IR_AND: case IR_OR: case IR_XOR: case IR_SHL: case IR_SHR: case IR_SAR:
        if (in->dst.kind == IR_O_REG) {
            if (in->op == IR_DIVU || in->op == IR_REMU) {
                /* REX "/" is signed: plain when both sides are known below 2^63. */
                Ex a = op_ex(d, &in->a), b = op_ex(d, &in->b);
                if (ex_nonneg(a) && ex_nonneg(b)) setr(d, in->dst.reg, ex_bin(bop(in->op), a, b));
                else {
                    d->need_udiv = 1;
                    setr(d, in->dst.reg, exf("%s(%s, %s)", in->op == IR_DIVU ? "udiv" : "urem", a.s, b.s));
                    ex_free(a); ex_free(b);
                }
            } else if (d->foreign && in->op == IR_SAR && in->dst.width < 8)
                setr(d, in->dst.reg, ex_bin(">>", ex_sext(op_ex(d, &in->a), in->dst.width), op_ex(d, &in->b)));
            else if (d->foreign && in->op == IR_SHR && in->dst.width == 8 && in->b.kind == IR_O_IMM && (in->b.imm & 63)) {
                int k = (int)(in->b.imm & 63);
                setr(d, in->dst.reg, ex_bin("&", ex_bin(">>", op_ex(d, &in->a), exf("%d", k)), exf("%llu", (1ULL << (64 - k)) - 1)));
            } else
                setr(d, in->dst.reg, ex_bin(bop(in->op), op_ex(d, &in->a), op_ex(d, &in->b)));
        } else if (in->dst.kind == IR_O_MEM && d->foreign && in->op != IR_DIVU && in->op != IR_REMU) {
            /* read-modify-write on memory (add [rbp-8], 1) */
            Ex a = op_ex(d, &in->a), b = op_ex(d, &in->b);
            if (in->op == IR_SAR && in->dst.width < 8) a = ex_sext(a, in->dst.width);
            store_ex(d, in, ex_bin(bop(in->op), a, b), 0, depth);
        }
        break;
    case IR_MULHU: case IR_MULHS:
        /* high half of rax * b (lifted one-operand mul/imul); dst is a register */
        if (in->dst.kind == IR_O_REG) {
            Ex a = op_ex(d, &in->a), b = op_ex(d, &in->b);
            if (in->dst.width == 8) {
                d->need_mulh = 1;
                setr(d, in->dst.reg, exf("%s(%s, %s)", in->op == IR_MULHU ? "umulh" : "smulh", a.s, b.s));
                ex_free(a); ex_free(b);
            } else {
                /* 32 bits: the full product fits 64 bits (signed: exactly; unsigned: as bits) */
                Ex m = exf("4294967295");
                Ex p = in->op == IR_MULHU ? ex_bin("*", ex_bin("&", a, exf("4294967295")), ex_bin("&", b, exf("4294967295")))
                                          : ex_bin("*", ex_sext(a, 4), ex_sext(b, 4));
                setr(d, in->dst.reg, ex_bin("&", ex_bin(">>", p, exf("32")), m));
            }
        }
        break;
    case IR_NEG: case IR_NOT:
        if (in->dst.kind == IR_O_REG)
            setr(d, in->dst.reg, ex_un(in->op == IR_NEG ? "-" : "~", op_ex(d, &in->a)));
        else if (in->dst.kind == IR_O_MEM && d->foreign)
            store_ex(d, in, ex_un(in->op == IR_NEG ? "-" : "~", op_ex(d, &in->a)), 0, depth);
        break;
    case IR_CMP: case IR_TEST:
        d->cmp = in;
        if (d->foreign) {
            if (d->cmp_snap) { ex_free(d->cmpa); ex_free(d->cmpb); }
            d->cmpa = op_ex(d, &in->a); d->cmpb = op_ex(d, &in->b);
            d->cmp_snap = 1;
        }
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
        char pre[512] = "";   /* callp: the pointer, before the arguments */
        int na = 0, lib_void = 0;
        const char *imp = NULL;
        if (!t && d->elf) {
            if (in->a.kind == IR_O_ADDR) imp = rex_elf_import_at(d->elf, in->a.addr);
            else if (in->a.kind == IR_O_MEM && in->a.base == IR_NOREG && in->a.index == IR_NOREG)
                imp = rex_elf_import_got(d->elf, (uint64_t)in->a.disp);
        }
        if (imp) {
            nm = imp;
            na = lib_arity(d, imp, &lib_void);
            if (!d->cur || d->cur->reach)
                if (!g_libcalls++) snprintf(g_libname, sizeof g_libname, "%s", imp);
        } else if (t) {
            if (t->kind == 3 && t->builtin) {
                nm = t->builtin;
                if (!strcmp(nm, "read")) na = 0;
                else if (!strcmp(nm, "strcmp")) na = 2;
                else if (!strcmp(nm, "print") || !strcmp(nm, "putc") || !strcmp(nm, "alloc") ||
                         !strcmp(nm, "free") || !strcmp(nm, "len") || !strcmp(nm, "exec")) na = 1;
                else na = t->nargs;
            }
            else { nm = t->name; na = t->nargs; }
        } else if (d->foreign && (in->a.kind == IR_O_REG || in->a.kind == IR_O_MEM)) {
            /* A call through a function pointer: REX has no function values, so
             * callp picks the recovered function by its original address (which
             * is what the pointer holds) and passes it the argument registers.
             * It is emitted like any other call below. */
            Ex tg = in->a.kind == IR_O_REG ? getr(d, in->a.reg) : op_ex(d, &in->a);
            char bb[512];
            snprintf(pre, sizeof pre, "%s", bare(tg.s, bb, sizeof bb));
            ex_free(tg);
            nm = "callp"; na = d->callp_n;
            d->need_callp = 1;
            if ((!d->cur || d->cur->reach) && d->callp_why[0] && !g_fpcall++)
                snprintf(g_fpwhy, sizeof g_fpwhy, "%s", d->callp_why);
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
        char args[1024] = "";
        snprintf(args, sizeof args, "%s", pre);
        for (int a = 0; a < na; a++) {
            Ex e = getr(d, ARG[a]);
            char bb[512];
            if (a || pre[0]) strncat(args, ", ", sizeof(args) - strlen(args) - 1);
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
        if ((!t && !imp && in->a.kind == IR_O_ADDR) || (t && t->kind == 3 && t->builtin &&
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
        } else if (d->foreign) {
            d->vused |= 1u;
            pin_reads(d, depth, NULL);  /* the callee may write memory */
            /* Callee-saved registers still holding an expression of v0 keep
             * the value from before this call. */
            for (int r = 1; r < 16; r++) {
                if (r == 4 || !d->has[r] || !mentions_v(d->reg[r].s, "v0")) continue;
                char bb2[1024];
                int k = d->nx++;
                emit(d, depth, "x%d = %s;", k, bare(d->reg[r].s, bb2, sizeof bb2));
                ex_free(d->reg[r]); d->reg[r] = exf("x%d", k);
            }
            if (lib_void) emit(d, depth, "%s;", call.s);
            else emit(d, depth, "v0 = %s;", call.s);
            ex_free(call);
            /* Clobber only what the callee may write; a known function that
             * never touches a caller-saved register leaves the caller's value
             * in it alive across the call. rax always carries the result (v0). */
            unsigned cm = (t && t->kind != 3) ? (t->clob | 1u) : CLOB_SAVED;
            static const int clob[] = { 0, 1, 2, 6, 7, 8, 9, 10, 11 };
            for (size_t c = 0; c < sizeof clob / sizeof clob[0]; c++) {
                int r = clob[c];
                if (!(cm & (1u << r))) continue;
                if (d->has[r]) ex_free(d->reg[r]);
                d->has[r] = 0;
            }
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
    if (!cmp && d->foreign) cmp = d->cmp;  /* flags inherited from the fall-through predecessor (cmp; je; jg) */
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


/* True when some edge u->v has v not dominating u while v is a DFS ancestor of u
 * (a retreating non-back edge). Only meaningful for the function's reachable CFG. */
static int *dom_tree(int n, int entry, int (*succ)[2], const int *nsucc);
/* Irreducible iff a DFS retreating edge (target still on the DFS stack)
 * goes to a block that does not dominate its source. */
static int cfg_irreducible(const IrFunc *f, const int *unused) {
    (void)unused;
    int n = f->nblocks;
    if (n <= 1) return 0;
    int (*succ)[2] = calloc((size_t)n, sizeof(*succ));
    int *ns = calloc((size_t)n, sizeof(int)), *it = calloc((size_t)n, sizeof(int));
    unsigned char *state = calloc((size_t)n, 1);  /* 0 new, 1 on stack, 2 done */
    int *st = malloc((size_t)n * sizeof(int));
    int bad = 0;
    if (!succ || !ns || !it || !state || !st) goto done;
    for (int b = 0; b < n; b++) {
        int s2[2], k = 0; ir_succs(f, b, s2, &k);
        for (int i = 0; i < k; i++) if (s2[i] >= 0 && s2[i] < n) succ[b][ns[b]++] = s2[i];
    }
    int *idom = dom_tree(n, 0, succ, ns);
    if (!idom) goto done;
    int sp = 0; st[sp++] = 0; state[0] = 1;
    while (sp && !bad) {
        int b = st[sp - 1];
        if (it[b] < ns[b]) {
            int v = succ[b][it[b]++];
            if (state[v] == 0) { state[v] = 1; st[sp++] = v; }
            else if (state[v] == 1) {
                int x = b, ok = 0;
                for (int guard = 0; guard <= n && x >= 0; guard++) {
                    if (x == v) { ok = 1; break; }
                    if (idom[x] == x || idom[x] < 0) break;
                    x = idom[x];
                }
                if (!ok) bad = 1;
            }
        } else { state[b] = 2; sp--; }
    }
    free(idom);
done:
    free(succ); free(ns); free(it); free(state); free(st);
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

typedef struct LCtx { int header, exit; const IrBlock *latch; int lx; int hdr; const struct LCtx *up; } LCtx;  /* hdr: the loop's header block; up: the enclosing loop */  /* lx: x temps reserved for the latch compare */  /* latch: do-while tail run before continue */

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
    if (d->cur->kind != 2 || d->foreign) {
        char bb[1024];
        /* A frame function owns a heap block (fr); hand it back before leaving.
         * Stash the return value first so it never names freed memory. */
        if (d->foreign && d->frame) {
            if (d->has[0]) {
                int k = d->nx++;
                emit(d, depth, "x%d = %s;", k, bare(d->reg[0].s, bb, sizeof bb));
                emit(d, depth, "free(fr);");
                emit(d, depth, "return x%d;", k);
            } else {
                d->vused |= 1u;
                emit(d, depth, "free(fr);");
                emit(d, depth, "return v0;");
            }
            return;
        }
        if (d->has[0]) emit(d, depth, "return %s;", bare(d->reg[0].s, bb, sizeof bb));
        else if (d->foreign) { d->vused |= 1u; emit(d, depth, "return v0;"); }
        else emit(d, depth, "return 0;");
    }
}

static int g_budget;
/* Set when a function overruns the structurer budget or nesting depth; the
 * whole decompile then refuses with E402 rather than emitting a
 * half-structured function body full of broken stubs. */
static int g_struct_fail;
static const char *g_struct_fail_fn;

/* Foreign code: registers live across blocks become variables vN. At each
 * block end, pending register expressions are assigned (in two phases when
 * one depends on another) and the registers revert to their names. */
static void materialize(D *d, int depth) {
    if (!d->foreign) return;
    int pend[16], np = 0;
    char nm[8];
    for (int r = 0; r < 16; r++) {
        if (r == 4 || !d->has[r] || (r == 5 && d->frame && d->fp)) continue;
        snprintf(nm, sizeof nm, "v%d", r);
        if (!strcmp(d->reg[r].s, nm)) continue;
        pend[np++] = r;
    }
    /* Compare operands snapshotted earlier must keep the pre-assignment values. */
    if (d->cmp_snap && np) {
        Ex *sn[2] = { &d->cmpa, &d->cmpb };
        for (int s = 0; s < 2; s++) {
            long long v;
            if (is_num(sn[s]->s, &v)) continue;
            int uses = 0;
            for (int j = 0; j < np && !uses; j++) {
                char vn[8]; snprintf(vn, sizeof vn, "v%d", pend[j]);
                for (const char *q = strstr(sn[s]->s, vn); q; q = strstr(q + 1, vn)) {
                    char nx = q[strlen(vn)];
                    if ((q == sn[s]->s || !((q[-1] >= 'a' && q[-1] <= 'z') || (q[-1] >= '0' && q[-1] <= '9') || q[-1] == '_')) && !(nx >= '0' && nx <= '9')) { uses = 1; break; }
                }
            }
            if (!uses) continue;
            char bb2[1024];
            int k = d->fixed_x >= 0 ? d->fixed_x + s : d->nx++;
            emit(d, depth, "x%d = %s;", k, bare(sn[s]->s, bb2, sizeof bb2));
            ex_free(*sn[s]);
            *sn[s] = exf("x%d", k);
        }
    }
    int need_tmp = 0;
    for (int i = 0; i < np && !need_tmp; i++)
        for (int j = 0; j < np; j++) {
            if (i == j) continue;
            char vn[8]; snprintf(vn, sizeof vn, "v%d", pend[j]);
            const char *s = d->reg[pend[i]].s;
            for (const char *q = strstr(s, vn); q; q = strstr(q + 1, vn)) {
                char nx = q[strlen(vn)];
                if ((q == s || !(q[-1] == '_' || (q[-1] >= 'a' && q[-1] <= 'z') || (q[-1] >= '0' && q[-1] <= '9'))) && !(nx >= '0' && nx <= '9')) { need_tmp = 1; break; }
            }
        }
    char bb[1024];
    for (int i = 0; i < np; i++) {
        int r = pend[i];
        d->vused |= 1u << r;
        if (need_tmp) { d->vused |= 1u << (16 + r); emit(d, depth, "w%d = %s;", r, bare(d->reg[r].s, bb, sizeof bb)); }
        else emit(d, depth, "v%d = %s;", r, bare(d->reg[r].s, bb, sizeof bb));
    }
    for (int i = 0; i < np; i++) {
        int r = pend[i];
        if (need_tmp) emit(d, depth, "v%d = w%d;", r, r);
        ex_free(d->reg[r]);
        d->reg[r] = exf("v%d", r);
    }
}

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
    if (d->frame) return;
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
/* Jump-table dispatch lifted as a compare chain on one register:
 * head ends "cmp r, 0; br.eq T0, S1", each Sk is exactly "cmp r, k; br.eq Tk, Sk+1",
 * the last is "jmp Tn". */
static int try_reg_switch(D *d, const IrFunc *f, G *g, int bi, const LCtx *lc, int depth) {
    const IrBlock *b = &f->blocks[bi];
    if (b->ninsns < 2) return 0;
    const IrInsn *cmp = &b->insns[b->ninsns - 2], *br = &b->insns[b->ninsns - 1];
    if (cmp->op != IR_CMP || cmp->a.kind != IR_O_REG || cmp->b.kind != IR_O_IMM || cmp->b.imm != 0 ||
        br->op != IR_BR || br->cc != IR_CC_EQ) return 0;
    int reg = cmp->a.reg;
    int targets[1100], nc = 0, cur = bi;
    for (;;) {
        const IrBlock *cb = &f->blocks[cur];
        const IrInsn *c2 = cb->ninsns >= 2 ? &cb->insns[cb->ninsns - 2] : NULL;
        const IrInsn *b2 = &cb->insns[cb->ninsns - 1];
        if (cur != bi && cb->ninsns == 1 && b2->op == IR_JMP) { targets[nc++] = thread(f, b2->a.block); break; }
        if (cur != bi && cb->ninsns != 2) return 0;
        if (!c2 || c2->op != IR_CMP || c2->a.kind != IR_O_REG || c2->a.reg != reg || c2->b.kind != IR_O_IMM ||
            c2->b.imm != nc || b2->op != IR_BR || b2->cc != IR_CC_EQ || nc >= 1099) return 0;
        targets[nc++] = thread(f, b2->a.block);
        cur = b2->b.block;
    }
    if (nc < 3) return 0;
    int join = g->ipdom[bi];
    if (join >= g->n || (join >= 0 && ret_only(&f->blocks[join]))) join = -1;
    char bb[1024];
    Ex v = getr(d, reg);
    emit(d, depth, "switch (%s) {", bare(v.s, bb, sizeof bb));
    ex_free(v);
    for (int i = 0; i < nc; i++) {
        Snap s; snap_take(d, &s);
        char *a = arm_text(d, f, g, targets[i], join, lc, depth + 2);
        snap_restore(d, &s, 0);
        emit(d, depth + 1, "case %d: {", i);
        fputs(a, d->out); free(a);
        emit(d, depth + 1, "}");
    }
    emit(d, depth, "}");
    return join < 0 ? 2 : 1;
}

static int try_switch(D *d, const IrFunc *f, G *g, int bi, const LCtx *lc, int depth) {
    const IrBlock *b = &f->blocks[bi];
    long long k; IrCond cc;
    int rs = try_reg_switch(d, f, g, bi, lc, depth);
    if (rs) return rs;
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

/* continue; in a do-while jumps to the condition, so the tail block's
 * statements run first (foreign code). */
static void emit_continue(D *d, const LCtx *lc, int depth) {
    if (lc->latch && d->foreign) {
        /* continue in do-while jumps to the condition: run the tail block's statements first */
        Snap s; snap_take(d, &s);
        const IrInsn *cmp0 = d->cmp;
        int snap0 = d->cmp_snap;
        Ex ca = snap0 ? ex(d->cmpa.s) : ex(""), cb = snap0 ? ex(d->cmpb.s) : ex("");
        for (int k = 0; k < lc->latch->ninsns - 1; k++) step(d, &lc->latch->insns[k], depth, NULL);
        d->fixed_x = lc->lx;
        materialize(d, depth);
        d->fixed_x = -1;
        snap_restore(d, &s, 0);
        if (d->cmp_snap) { ex_free(d->cmpa); ex_free(d->cmpb); }
        d->cmp = cmp0; d->cmp_snap = snap0;
        if (snap0) { d->cmpa = ca; d->cmpb = cb; } else { ex_free(ca); ex_free(cb); }
    }
    emit(d, depth, "continue;");
}

/* "while (1) { B; if (X) { break; } }" with no continue is "do { B } while (!X);". */
static int emit_tail_exit(D *d, int depth, const char *body) {
    char i1[200] = "", i2[204];
    for (int i = 0; i <= depth && strlen(i1) + 5 < sizeof i1; i++) strcat(i1, "    ");
    snprintf(i2, sizeof i2, "%s    ", i1);
    if (strstr(body, "continue;")) return 0;
    size_t bl = strlen(body);
    char tail[420];
    snprintf(tail, sizeof tail, "%s    break;\n%s}\n", i1, i1);
    size_t tl = strlen(tail);
    if (bl < tl || strcmp(body + bl - tl, tail)) return 0;
    /* start of the "if (X) {" line */
    const char *end = body + bl - tl, *ln = end - 1;
    while (ln > body && ln[-1] != '\n') ln--;
    size_t il = strlen(i1);
    if (strncmp(ln, i1, il) || strncmp(ln + il, "if (", 4) || end - ln < (long)(il + 7) || strncmp(end - 4, ") {\n", 4)) return 0;
    char x[1100];
    size_t xl = (size_t)((end - 4) - (ln + il + 4));
    if (xl + 1 > sizeof x) return 0;
    memcpy(x, ln + il + 4, xl); x[xl] = 0;
    Ex c = ex_un("!", exf("(%s)", x));
    char bb[1024];
    emit(d, depth, "do {");
    fwrite(body, 1, (size_t)(ln - body), d->out);
    emit(d, depth, "} while (%s);", bare(c.s, bb, sizeof bb));
    ex_free(c);
    return 1;
}

/* Rotated loop: "if (C) { do { B } while (C); }" is "while (C) { B }".
 * Same text means the same variables, so the rewrite is exact. */
static int emit_rotated(D *d, int depth, const char *cond, const char *arm) {
    char ind[200] = "";
    for (int i = 0; i <= depth && strlen(ind) + 5 < sizeof ind; i++) strcat(ind, "    ");
    size_t il = strlen(ind), al = strlen(arm);
    char head[256], tail[1100];
    snprintf(head, sizeof head, "%sdo {\n", ind);
    snprintf(tail, sizeof tail, "%s} while (%s);\n", ind, cond);
    size_t hl = strlen(head), tl = strlen(tail);
    if (al < hl + tl || strncmp(arm, head, hl) || strcmp(arm + al - tl, tail)) return 0;
    /* the do-while must be the whole arm: no other line at this depth */
    for (const char *q = arm + hl; q < arm + al - tl; ) {
        if (!strncmp(q, ind, il) && q[il] != ' ') return 0;
        const char *nl = strchr(q, '\n');
        if (!nl) return 0;
        q = nl + 1;
    }
    emit(d, depth, "while (%s) {", cond);
    for (const char *q = arm + hl; q < arm + al - tl; ) {
        const char *nl = strchr(q, '\n');
        fwrite(q + 4, 1, (size_t)(nl - q - 3), d->out);  /* one level shallower */
        q = nl + 1;
    }
    emit(d, depth, "}");
    return 1;
}

/* A quiet block (just cmp/test + br) reached only from one branch, sharing
 * a target with it, folds into one condition: c && cy or c || cy. */
static unsigned op_regs(const IrOperand *o) {
    unsigned m = 0;
    if (o->kind == IR_O_REG && o->reg >= 0 && o->reg < 16) m |= 1u << o->reg;
    if (o->kind == IR_O_MEM) {
        if (o->base >= 0 && o->base < 16) m |= 1u << o->base;
        if (o->index >= 0 && o->index < 16) m |= 1u << o->index;
    }
    return m;
}
/* every register in m is written before it is read in block b */
static int regs_dead(const IrBlock *b, unsigned m) {
    for (int k = 0; k < b->ninsns && m; k++) {
        const IrInsn *in = &b->insns[k];
        unsigned rd = op_regs(&in->a) | op_regs(&in->b);
        if (in->dst.kind == IR_O_MEM || in->op == IR_CMOV || (in->dst.kind == IR_O_REG && in->dst.width < 4)) rd |= op_regs(&in->dst);
        if (in->op == IR_CALL || in->op == IR_RET || in->op == IR_SYSCALL) return 0;  /* may read anything */
        if (rd & m) return 0;
        if (in->dst.kind == IR_O_REG && in->dst.width >= 4 && in->op != IR_CMOV) m &= ~(1u << in->dst.reg);
    }
    return m == 0;
}
static int quiet_cond(const IrFunc *f, G *g, int y, const LCtx *lc, int stop) {
    if (y < 0 || y >= g->n || y == stop || g->loop_exit[y] != -2) return 0;
    if (lc && (y == lc->header || y == lc->exit)) return 0;
    const IrBlock *b = &f->blocks[y];
    if (b->ninsns < 2 || b->ninsns > 12 || b->insns[b->ninsns - 1].op != IR_BR) return 0;
    unsigned wr = 0;
    for (int k = 0; k < b->ninsns - 1; k++) {
        IrOp op = b->insns[k].op;
        if (op == IR_STORE || op == IR_CALL || op == IR_SYSCALL || op == IR_PUSH || op == IR_POP || op == IR_TRAP ||
            op == IR_DIVS || op == IR_REMS || op == IR_DIVU || op == IR_REMU || op == IR_MULHU || op == IR_MULHS) return 0;
        if (b->insns[k].dst.kind == IR_O_MEM) return 0;
        if (b->insns[k].dst.kind == IR_O_REG) wr |= 1u << b->insns[k].dst.reg;
    }
    if (wr & ((1u << 4) | (1u << 5))) return 0;
    /* registers written here must be dead (rewritten before read) in both targets */
    for (int t = 0; t < 2 && wr; t++) {
        int tb = thread(f, t ? b->insns[b->ninsns - 1].b.block : b->insns[b->ninsns - 1].a.block);
        if (tb < 0 || tb >= f->nblocks) return 0;
        if (!regs_dead(&f->blocks[tb], wr)) return 0;
    }
    int np = 0;
    for (int x = 0; x < g->n; x++) for (int k = 0; k < g->nsucc[x]; k++) if (g->succ[x][k] == y) np++;
    return np == 1;
}
static void merge_chain(D *d, const IrFunc *f, G *g, const LCtx *lc, int stop, Ex *c, int *ta, int *fb) {
    for (int guard = 0; guard < 16; guard++) {
        int y, isand;
        if (quiet_cond(f, g, *ta, lc, stop)) { y = *ta; isand = 1; }
        else if (quiet_cond(f, g, *fb, lc, stop)) { y = *fb; isand = 0; }
        else return;
        const IrBlock *b = &f->blocks[y];
        int ya = thread(f, b->insns[b->ninsns - 1].a.block), yb = thread(f, b->insns[b->ninsns - 1].b.block);
        int other = isand ? *fb : *ta;
        if (ya != other && yb != other) {
            if (isand && quiet_cond(f, g, *fb, lc, stop)) { y = *fb; isand = 0; b = &f->blocks[y];
                ya = thread(f, b->insns[b->ninsns - 1].a.block); yb = thread(f, b->insns[b->ninsns - 1].b.block); other = *ta;
                if (ya != other && yb != other) return; }
            else return;
        }
        Snap sn; snap_take(d, &sn);
        for (int k = 0; k < b->ninsns - 1; k++) step(d, &b->insns[k], d->depth, NULL);
        Ex cy = br_cond(d, &b->insns[b->ninsns - 1], b);
        snap_restore(d, &sn, 0);  /* the block's register writes are dead */
        if (isand) {       /* ta = y: taken when c && (y goes on) */
            if (yb == other) { *ta = ya; } else { cy = ex_un("!", cy); *ta = yb; }
            *c = ex_bin("&&", *c, cy);
        } else {           /* fb = y: taken when c || (y jumps to ta) */
            if (ya == other) { *fb = yb; } else { cy = ex_un("!", cy); *fb = ya; }
            *c = ex_bin("||", *c, cy);
        }
    }
}

static void structure(D *d, const IrFunc *f, G *g, int bi, int stop, const LCtx *lc, int depth, int enter) {
    if (depth > 48 || g_budget <= 0) {
        g_struct_fail = 1;
        g_struct_fail_fn = f->name;
        g_budget = 0;
        return;
    }
    while (bi >= 0 && bi < g->n && g_budget-- > 0) {
        if (!enter) {
            if (bi == stop) {
                if (ret_only(&f->blocks[bi])) emit_ret(d, depth);
                return;
            }
            if (lc && bi == lc->header) {
                emit_continue(d, lc, depth);
                return;
            }
            if (lc && bi == lc->exit) { emit(d, depth, "break;"); return; }
            /* Back at the header of a loop that is already open around us, but not
             * by its own continue: that is a continue of an outer loop, which REX
             * cannot spell. Opening the loop again here would nest a copy of it in
             * itself, over and over, and the innermost copy would be wrong. */
            for (const LCtx *p = lc; p; p = p->up)
                if (bi == p->hdr) {
                    if (!g_struct_fail) { g_struct_fail = 1; g_struct_fail_fn = f->name; }
                    return;
                }
            if (g->loop_exit[bi] != -2 && !(lc && lc->header == bi)) {
                int latch;
                flush_decls(d);
                LCtx inner = { bi, g->loop_exit[bi], NULL, -1, bi, lc };
                const IrBlock *hb = &f->blocks[bi];
                const IrInsn *ht = hb->ninsns ? &hb->insns[hb->ninsns - 1] : NULL;
                unsigned char *in = g->inloop + (size_t)bi * g->n;
                if (ht && ht->op == IR_BR && g->nsucc[bi] == 2 && !block_emits(hb) &&
                    (!d->foreign || (hb->ninsns == 2 && (hb->insns[0].op == IR_CMP || hb->insns[0].op == IR_TEST))) &&
                    (!in[ht->a.block] || !in[ht->b.block]) && (in[ht->a.block] || in[ht->b.block])) {
                    for (int k = 0; k < hb->ninsns - 1; k++) step(d, &hb->insns[k], depth, NULL);
                    materialize(d, depth);
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
                    LCtx dl = { latch, inner.exit, lb, d->foreign ? d->nx : -1, bi, lc };
                    if (d->foreign) d->nx += 2;
                    emit(d, depth, "do {");
                    Snap s; snap_take(d, &s);
                    structure(d, f, g, bi, latch, &dl, depth + 1, 1);
                    for (int k = 0; k < lb->ninsns - 1; k++) step(d, &lb->insns[k], depth + 1, NULL);
                    d->fixed_x = dl.lx;
                    materialize(d, depth + 1);
                    d->fixed_x = -1;
                    Ex c = br_cond(d, lt, lb);
                    if (thread(f, lt->a.block) != bi) c = ex_un("!", c);
                    { char bb[1024]; emit(d, depth, "} while (%s);", bare(c.s, bb, sizeof bb)); }
                    ex_free(c);
                    snap_restore(d, &s, 0);
                } else {
                    char *lb = NULL; size_t ln = 0;
                    FILE *save = d->out, *mf = d->foreign ? open_memstream(&lb, &ln) : NULL;
                    if (mf) d->out = mf;
                    Snap s; snap_take(d, &s);
                    structure(d, f, g, bi, bi, &inner, depth + 1, 1);
                    snap_restore(d, &s, 0);
                    if (mf) { fclose(mf); d->out = save; }
                    if (!mf || !emit_tail_exit(d, depth, lb ? lb : "")) {
                        emit(d, depth, "while (1) {");
                        if (lb) fputs(lb, d->out);
                        emit(d, depth, "}");
                    }
                    free(lb);
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
        if (!(term && term->op == IR_RET)) materialize(d, depth);
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
        { int sw = try_switch(d, f, g, bi, lc, depth);
          if (sw) { ex_free(c); if (sw == 2) return; bi = g->ipdom[bi]; if (bi < 0 || bi >= g->n) return; continue; } }
        if (d->foreign) merge_chain(d, f, g, lc, stop, &c, &ta, &fb);
        if (lc && ((ta == lc->exit && fb == lc->header) || (fb == lc->exit && ta == lc->header))) {
            if (ta != lc->exit) c = ex_un("!", c);
            emit(d, depth, "if (%s) {", bare(c.s, bb, sizeof bb)); ex_free(c);
            emit(d, depth + 1, "break;");
            emit(d, depth, "}");
            if (stop == lc->header) return;
            emit_continue(d, lc, depth);
            return;
        }
        if (lc && (ta == lc->exit || ta == lc->header || fb == lc->exit || fb == lc->header)) {
            int jump = (ta == lc->exit || ta == lc->header) ? ta : fb;
            int other = jump == ta ? fb : ta;
            if (jump != ta) c = ex_un("!", c);
            emit(d, depth, "if (%s) {", bare(c.s, bb, sizeof bb)); ex_free(c);
            if (jump == lc->exit) emit(d, depth + 1, "break;");
            else emit_continue(d, lc, depth + 1);
            emit(d, depth, "}");
            bi = other;
            continue;
        }
        int join = g->ipdom[bi];
        if (join >= g->n) join = -1;
        if (join < 0 || ret_only(&f->blocks[join])) join = (ta == stop || fb == stop) ? stop : common_reach(f, g, bi, ta, fb, lc, stop);
        int ret_join = join >= 0 && ret_only(&f->blocks[join]);
        Snap s; snap_take(d, &s);
        /* both arms start from this block's flags (a successor may inherit
         * them): a compare in the first arm must not leak into the second */
        const IrInsn *cmp0 = d->cmp;
        int snap0 = d->cmp_snap;
        Ex ca = snap0 ? ex(d->cmpa.s) : ex(""), cb = snap0 ? ex(d->cmpb.s) : ex("");
        char *armA = ta == join && !ret_join ? strdup("") : arm_text(d, f, g, ta, join, lc, depth + 1);
        snap_restore(d, &s, 1);
        if (d->cmp_snap) { ex_free(d->cmpa); ex_free(d->cmpb); }
        d->cmp = cmp0; d->cmp_snap = snap0;
        if (snap0) { d->cmpa = ca; d->cmpb = cb; } else { ex_free(ca); ex_free(cb); }
        char *armB = fb == join && !ret_join ? strdup("") : arm_text(d, f, g, fb, join, lc, depth + 1);
        if (!*armA && !*armB) { /* both empty: keep side effects only */ }
        else if (!*armA) {
            c = ex_un("!", c);
            const char *cs = bare(c.s, bb, sizeof bb);
            if (!(d->foreign && emit_rotated(d, depth, cs, armB))) {
                emit(d, depth, "if (%s) {", cs);
                fputs(armB, d->out); emit(d, depth, "}");
            }
        } else if (!*armB) {
            const char *cs = bare(c.s, bb, sizeof bb);
            if (!(d->foreign && emit_rotated(d, depth, cs, armA))) {
                emit(d, depth, "if (%s) {", cs);
                fputs(armA, d->out); emit(d, depth, "}");
            }
        } else {
            /* REX lowers if/else with the then-arm on the fall-through edge. */
            c = ex_un("!", c);
            emit(d, depth, "if (%s) {", bare(c.s, bb, sizeof bb));
            fputs(armB, d->out);
            emit(d, depth, "} else {");
            fputs(armA, d->out);
            emit(d, depth, "}");
        }
        ex_free(c); free(armA); free(armB);
        snap_restore(d, &s, 0);
        if (join < 0 || ret_join) return;
        bi = join;
    }
    /* The walk ran out of budget in the middle of a region, so what it emitted
     * is cut short: fail like the depth limit does, never return quietly. */
    if (g_budget < 0 && !g_struct_fail) { g_struct_fail = 1; g_struct_fail_fn = f->name; }
}

/* After the discarded pass: arrays (indexed + bounds-checked) and structs
 * (runs of zero-initialized adjacent locals, never indexed) get aliases.
 * Struct declarations print before the function. */
static void finish_hints(D *d, const IrFunc *f, Fun *fi) {
    if (d->frame) return;  /* frame block: no slot locals, arrays or structs */
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

/* Foreign function whose stack is indexed, address-taken or copied: its
 * frame moves to a heap block fr (rsp and rbp both start at fr). Returns
 * the half size of that block, 0 when plain locals suffice. */
static int frame_has_fp(const IrFunc *f) {
    for (int b = 0; b < f->nblocks; b++)
        for (int k = 0; k < f->blocks[b].ninsns; k++) {
            const IrInsn *in = &f->blocks[b].insns[k];
            if (in->op == IR_MOV && in->dst.kind == IR_O_REG && in->dst.reg == 5 &&
                in->a.kind == IR_O_REG && in->a.reg == 4) return 1;
        }
    return 0;
}
static int frame_size(const IrFunc *f) {
    int need = 0;
    long long far = 0;
    for (int b = 0; b < f->nblocks; b++)
        for (int k = 0; k < f->blocks[b].ninsns; k++) {
            const IrInsn *in = &f->blocks[b].insns[k];
            const IrOperand *ops[3] = { &in->dst, &in->a, &in->b };
            if (in->op == IR_SUB && in->dst.kind == IR_O_REG && in->dst.reg == 4 && in->b.kind == IR_O_IMM && in->b.imm > far) far = in->b.imm;
            for (int j = 0; j < 3; j++) {
                const IrOperand *o = ops[j];
                if (o->kind == IR_O_MEM && (o->base == 4 || o->base == 5)) {
                    long long a = o->disp < 0 ? -o->disp : o->disp;
                    if (a > far) far = a;
                    if (o->index != IR_NOREG) need = 1;
                    if (in->op == IR_ADDR && j == 1) need = 1;
                }
            }
            if (is_prolog(in) || is_epilog(in) || in->op == IR_PUSH || in->op == IR_POP || in->op == IR_CALL || in->op == IR_RET) continue;
            if (in->dst.kind == IR_O_REG && (in->dst.reg == 4 || in->dst.reg == 5)) continue;
            if ((in->a.kind == IR_O_REG && (in->a.reg == 4 || in->a.reg == 5)) ||
                (in->b.kind == IR_O_REG && (in->b.reg == 4 || in->b.reg == 5))) need = 1;
        }
    if (!need || far > (1 << 20)) return 0;
    return (int)((far + 256 + 15) & ~15LL);
}

/* Foreign code: arguments are the argument registers live at entry
 * (read before written on some path). Calls read nothing here. */
static void foreign_args(D *d) {
    for (int i = 0; i < d->nfun; i++) {
        Fun *fi = &d->fun[i];
        if (fi->kind != 0) continue;
        const IrFunc *f = &d->m->funcs[i];
        int n = f->nblocks;
        if (!n) continue;
        unsigned *use = calloc((size_t)n, sizeof(unsigned)), *def = calloc((size_t)n, sizeof(unsigned)), *in = calloc((size_t)n, sizeof(unsigned));
        if (!use || !def || !in) { free(use); free(def); free(in); continue; }
        for (int b = 0; b < n; b++)
            for (int k = 0; k < f->blocks[b].ninsns; k++) {
                const IrInsn *x = &f->blocks[b].insns[k];
                unsigned rd = 0, wr = 0;
                if (x->op == IR_CALL) wr = (1u<<0)|(1u<<1)|(1u<<2)|(1u<<6)|(1u<<7)|(1u<<8)|(1u<<9)|(1u<<10)|(1u<<11);
                else if (x->op != IR_SYSCALL && x->op != IR_PUSH && x->op != IR_POP) {
                    rd = op_regs(&x->a) | op_regs(&x->b);
                    if (x->dst.kind == IR_O_MEM || x->op == IR_CMOV || (x->dst.kind == IR_O_REG && x->dst.width < 4)) rd |= op_regs(&x->dst);
                    if (x->op == IR_XOR && x->a.kind == IR_O_REG && x->b.kind == IR_O_REG && x->a.reg == x->b.reg) rd = 0;
                    if (x->dst.kind == IR_O_REG && x->dst.width >= 4 && x->op != IR_CMOV && x->dst.reg >= 0 && x->dst.reg < 16) wr = 1u << x->dst.reg;
                }
                use[b] |= rd & ~def[b];
                def[b] |= wr;
            }
        for (int changed = 1, it = 0; changed && it < 100; it++) {
            changed = 0;
            for (int b = n - 1; b >= 0; b--) {
                unsigned out = 0;
                for (int s = 0; s < f->blocks[b].nsucc; s++) { int t = f->blocks[b].succ[s]; if (t >= 0 && t < n) out |= in[t]; }
                unsigned v = use[b] | (out & ~def[b]);
                if (v != in[b]) { in[b] = v; changed = 1; }
            }
        }
        int na = 0;
        for (int a = 0; a < 6; a++) if (in[0] & (1u << ARG[a])) na = a + 1;
        if (na > fi->nargs) fi->nargs = na;
        free(use); free(def); free(in);
    }
}

/* A spill/pin site may stash a register in an x temporary whose value is then
 * recomputed inline, leaving the temporary assigned but never read. Dropping
 * those dead temporaries keeps recovered functions under REX's local-name cap
 * and removes clutter. Only pure assignments (no call) are removed, so this is
 * behavior-preserving. Operates on the already-emitted function text. */
static int dt_tok(const char *buf, const char *p, int *num) {
    if (*p != 'x') return 0;
    char before = p == buf ? 0 : p[-1];
    if ((before >= 'a' && before <= 'z') || (before >= 'A' && before <= 'Z') ||
        (before >= '0' && before <= '9') || before == '_') return 0;
    const char *q = p + 1;
    if (!(*q >= '0' && *q <= '9')) return 0;
    int n = 0;
    while (*q >= '0' && *q <= '9') { n = n * 10 + (*q - '0'); q++; }
    char after = *q;
    if ((after >= 'a' && after <= 'z') || (after >= 'A' && after <= 'Z') || after == '_') return 0;
    *num = n;
    return (int)(q - p);
}
/* true if the RHS text contains a call (an identifier immediately before '('). */
static int dt_has_call(const char *s, const char *end) {
    for (const char *p = s; p < end; p++)
        if (*p == '(' && p > s) {
            char c = p[-1];
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') return 1;
        }
    return 0;
}
static char *strip_dead_temps(const char *in) {
    size_t len = strlen(in);
    char *buf = malloc(len + 1);
    if (!buf) return NULL;
    memcpy(buf, in, len + 1);
    enum { CAP = 4096 };
    int *reads = malloc(CAP * sizeof(int));
    int *defs = malloc(CAP * sizeof(int));
    int *decl = malloc(CAP * sizeof(int));
    if (!reads || !defs || !decl) { free(reads); free(defs); free(decl); return buf; }
    for (int again = 1; again;) {
        again = 0;
        size_t blen = strlen(buf);
        for (int i = 0; i < CAP; i++) { reads[i] = 0; defs[i] = 0; decl[i] = 0; }
        /* Walk lines, classifying each x token as a definition (assignment LHS
         * or a `let` declaration) or a read. */
        char *line = buf;
        while (line && *line) {
            char *nl = strchr(line, '\n');
            char *lend = nl ? nl : buf + blen;
            char *s = line; while (*s == ' ' || *s == '\t') s++;
            int lhs = -1; char *rhs_start = NULL;
            if (!strncmp(s, "let ", 4)) {
                int num; int w = dt_tok(buf, s + 4, &num);
                if (w && num < CAP) { decl[num]++; }
            } else {
                int num; int w = dt_tok(buf, s, &num);
                if (w && num < CAP) {
                    char *after = s + w; while (*after == ' ') after++;
                    if (after[0] == '=' && after[1] == ' ') { lhs = num; defs[num]++; rhs_start = after + 2; }
                }
            }
            /* count reads: every x token in the value part of the line. For a
             * `let NAME = init;` declaration scan the initializer (so a temp
             * read there counts) but not the declared NAME itself. */
            char *scan = rhs_start ? rhs_start : s;
            if (!strncmp(s, "let ", 4)) {
                char *eq = s + 4;
                while (eq < lend && !(eq[0] == '=' && eq[1] == ' ')) eq++;
                scan = eq < lend ? eq + 2 : lend;
            }
            for (char *p = scan; p < lend;) {
                int num, w;
                if ((w = dt_tok(buf, p, &num)) && num < CAP) { reads[num]++; p += w; }
                else p++;
            }
            (void)lhs;
            line = nl ? nl + 1 : NULL;
        }
        /* Rebuild the buffer, dropping lines that define or declare a temp with
         * zero reads (and a pure RHS). */
        char *out = malloc(blen + 1);
        if (!out) break;
        size_t oi = 0;
        line = buf;
        while (line && *line) {
            char *nl = strchr(line, '\n');
            char *lend = nl ? nl : buf + blen;
            size_t llen = (size_t)(lend - line) + (nl ? 1 : 0);
            char *s = line; while (*s == ' ' || *s == '\t') s++;
            int drop = 0;
            if (!strncmp(s, "let ", 4)) {
                int num; int w = dt_tok(buf, s + 4, &num);
                if (w && num < CAP && reads[num] == 0 && defs[num] > 0) drop = 1;
            } else {
                int num; int w = dt_tok(buf, s, &num);
                if (w && num < CAP) {
                    char *after = s + w; while (*after == ' ') after++;
                    if (after[0] == '=' && after[1] == ' ' && reads[num] == 0) {
                        char *semi = lend; while (semi > after && *semi != ';') semi--;
                        if (!dt_has_call(after + 2, semi)) drop = 1;
                    }
                }
            }
            if (drop) again = 1;
            else { memcpy(out + oi, line, llen); oi += llen; }
            line = nl ? nl + 1 : NULL;
        }
        out[oi] = 0;
        free(buf);
        buf = out;
    }
    free(reads); free(defs); free(decl);
    return buf;
}

/* Stack-height model for the dispatch fallback. Each dispatch arm starts from
 * nothing but the register variables, so the frame view every arm prints must
 * match the machine's. Per block the model tracks the real stack height h
 * (bytes below the entry rsp: push -8, pop +8, sub/add rsp,imm, a call nets 0)
 * and D, the part of it the printer follows: it skips the prologue's sub rsp and
 * keeps pushes on its value stack, so only add rsp,imm moves its rsp. An rsp
 * operand at disp then prints as rsp+D+disp for a machine address h+disp, which
 * is exact when h-D is one constant over the whole function (and equals the
 * height rbp was set at, if rbp addresses the frame too). Joins must agree on
 * (h, D); a return must leave h = 0; no frame access may touch a pushed slot.
 * A pop of a value pushed in another block (an epilogue restoring a callee-saved
 * register) is allowed only when nothing but pops, add rsp and the return
 * follow, so the restored value is never read. Any other rsp write is unknown.
 * Returns 1 when exact; dent (may be NULL) gets each block's entry D. */
#define SM_UNSET (-(1LL << 40))
static int stack_model(const D *d, const IrFunc *f, long long *dent) {
    int n = f->nblocks, ok = 1;
    if (n <= 0) return 1;
    long long *eh = malloc((size_t)n * sizeof *eh), *ed = malloc((size_t)n * sizeof *ed);
    int *work = malloc((size_t)n * sizeof *work);
    long long slots[64]; int nsl = 0;              /* pushed slots, by real height */
    long long acc_lo[256], acc_hi[256]; int nacc = 0;
    if (!eh || !ed || !work) { free(eh); free(ed); free(work); return 0; }
    for (int b = 0; b < n; b++) eh[b] = ed[b] = SM_UNSET;
    eh[0] = ed[0] = 0;
    int nw = 0; work[nw++] = 0;
    long long K = SM_UNSET, hfp = SM_UNSET, rbp_acc = 0;
    while (nw && ok) {
        int bi = work[--nw];
        const IrBlock *b = &f->blocks[bi];
        long long h = eh[bi], dd = ed[bi];
        int vstk = 0;                              /* pushes of this block still on the value stack */
        for (int k = 0; k < b->ninsns && ok; k++) {
            const IrInsn *in = &b->insns[k];
            int pro = is_prolog(in), epi = is_epilog(in);
            /* frame accesses through rsp or rbp, and rsp read as a value */
            const IrOperand *ops[3] = { &in->dst, &in->a, &in->b };
            for (int j = 0; j < 3 && ok; j++) {
                const IrOperand *o = ops[j];
                if (o->kind == IR_O_MEM && o->base == 4) {
                    long long kk = d->frame ? h - dd : h;
                    if (K == SM_UNSET) K = kk; else if (K != kk) ok = 0;
                    if (o->index == IR_NOREG && in->op != IR_ADDR && nacc < 256) {
                        acc_lo[nacc] = h + o->disp; acc_hi[nacc++] = h + o->disp + (o->width ? o->width : 8);
                    }
                } else if (o->kind == IR_O_MEM && o->base == 5 && d->fp) {
                    rbp_acc = 1;
                    if (o->index == IR_NOREG && in->op != IR_ADDR && hfp != SM_UNSET && nacc < 256) {
                        acc_lo[nacc] = hfp + o->disp; acc_hi[nacc++] = hfp + o->disp + (o->width ? o->width : 8);
                    }
                } else if (j > 0 && o->kind == IR_O_REG && o->reg == 4 && !pro && in->op != IR_PUSH && in->op != IR_POP &&
                           !(in->dst.kind == IR_O_REG && in->dst.reg == 4)) {   /* rsp arithmetic: below */
                    if (!d->frame) ok = 0;
                    else if (K == SM_UNSET) K = h - dd; else if (K != h - dd) ok = 0;
                }
            }
            if (!ok) break;
            if (in->op == IR_PUSH) {
                if (nsl < 64) slots[nsl++] = h - 8; else ok = 0;
                h -= 8;
                if (!pro) vstk++;
            } else if (in->op == IR_POP) {
                if (!epi) {
                    if (vstk > 0) vstk--;
                    else {
                        /* restores a value pushed in another block: only an epilogue may */
                        if (in->dst.kind != IR_O_REG || in->dst.reg == 0) ok = 0;
                        for (int q = k + 1; q < b->ninsns && ok; q++) {
                            const IrInsn *x = &b->insns[q];
                            if (x->op == IR_POP || x->op == IR_NOP || x->op == IR_RET || is_epilog(x)) continue;
                            if (x->op == IR_ADD && x->dst.kind == IR_O_REG && x->dst.reg == 4 && x->b.kind == IR_O_IMM) continue;
                            ok = 0;
                        }
                        const IrInsn *t = &b->insns[b->ninsns - 1];
                        if (t->op != IR_RET) ok = 0;
                    }
                }
                h += 8;
            } else if (pro && in->op == IR_MOV) {          /* mov rbp, rsp */
                if (hfp != SM_UNSET && hfp != h) ok = 0;
                hfp = h;
            } else if (pro && in->op == IR_SUB) {          /* sub rsp, imm: the printer skips it */
                h -= in->b.imm;
            } else if (epi && in->op == IR_MOV) {          /* mov rsp, rbp */
                if (hfp == SM_UNSET) ok = 0; else h = hfp;
            } else if (in->dst.kind == IR_O_REG && in->dst.reg == 4) {
                if (in->op == IR_ADD && in->a.kind == IR_O_REG && in->a.reg == 4 && in->b.kind == IR_O_IMM) {
                    h += in->b.imm; dd += in->b.imm;
                } else ok = 0;
            } else if (d->fp && in->dst.kind == IR_O_REG && in->dst.reg == 5) {
                ok = 0;                                     /* rbp addresses the frame; it must not move */
            } else if (in->op == IR_RET) {
                if (h != 0) ok = 0;
            }
        }
        if (!ok) break;
        for (int s = 0; s < b->nsucc; s++) {
            int t = b->succ[s];
            if (t < 0 || t >= n) continue;
            if (eh[t] == SM_UNSET) { eh[t] = h; ed[t] = dd; work[nw++] = t; }
            else if (eh[t] != h || ed[t] != dd) ok = 0;
        }
    }
    if (ok && rbp_acc && K != SM_UNSET && d->frame && hfp != K) ok = 0;   /* rsp and rbp views must agree */
    if (ok && rbp_acc && K != SM_UNSET && !d->frame) ok = 0;              /* separate slot namespaces */
    for (int a = 0; a < nacc && ok; a++)
        for (int p = 0; p < nsl; p++)
            if (acc_lo[a] < slots[p] + 8 && slots[p] < acc_hi[a]) { ok = 0; break; }
    if (ok && dent) for (int b = 0; b < n; b++) dent[b] = ed[b] == SM_UNSET ? 0 : ed[b];
    free(eh); free(ed); free(work);
    return ok;
}

/* Goto-free fallback for control flow the region structurer cannot nest (it
 * would recurse without end). Each block becomes one arm of a dispatch loop
 * keyed on a state variable st: the arm runs the block's statements, flushes its
 * register variables, then sets st to the next block. That simulates the CFG
 * exactly. It is used only where it is provably exact: every conditional branch
 * tests flags set in its own block, no SSE value is live across a block, and the
 * stack model above shows every block sees the frame where the machine has it.
 * Anything else keeps the clean E402 refusal. */
static int dispatch_safe(const D *d, const IrFunc *f) {
    for (int bi = 0; bi < f->nblocks; bi++) {
        const IrBlock *b = &f->blocks[bi];
        int nb = b->ninsns;
        const IrInsn *t = nb ? &b->insns[nb - 1] : NULL;
        int nbody = (t && ir_is_terminator(t->op)) ? nb - 1 : nb;
        if (t && t->op == IR_TRAP) return 0;
        if (t && t->op == IR_BR) {
            int own = 0;
            for (int k = 0; k < nbody; k++)
                if (b->insns[k].op == IR_CMP || b->insns[k].op == IR_TEST) own = 1;
            if (!own) return 0;                       /* flags inherited from another block */
        }
        unsigned xw = 0;                              /* xmm pseudo-regs 16..47 written so far */
        for (int k = 0; k < nb; k++) {
            const IrInsn *in = &b->insns[k];
            const IrOperand *rd[2] = { &in->a, &in->b };
            for (int o = 0; o < 2; o++)
                if (rd[o]->kind == IR_O_REG && rd[o]->reg >= 16 && rd[o]->reg < 48 &&
                    !(xw & (1u << (rd[o]->reg - 16)))) return 0;           /* SSE value crosses a block */
            if (in->dst.kind == IR_O_REG && in->dst.reg >= 16 && in->dst.reg < 48)
                xw |= 1u << (in->dst.reg - 16);
        }
    }
    return stack_model(d, f, NULL);
}

static void emit_dispatch(D *d, const IrFunc *f, int depth) {
    flush_decls(d);
    materialize(d, depth);                            /* parameters become register variables */
    long long *dent = calloc((size_t)(f->nblocks > 0 ? f->nblocks : 1), sizeof *dent);
    if (dent) stack_model(d, f, dent);
    emit(d, depth, "let st = 0;");
    emit(d, depth, "while (1) {");
    for (int bi = 0; bi < f->nblocks; bi++) {
        const IrBlock *b = &f->blocks[bi];
        /* At block entry every register holds its variable; the frame pointer keeps
         * its value; rsp is where the stack model puts it; the value stack is empty. */
        for (int r = 0; r < 16; r++) {
            if (r == 4 || (r == 5 && d->frame && d->fp)) continue;
            if (d->has[r]) ex_free(d->reg[r]);
            d->has[r] = 0;
        }
        while (d->nstk) ex_free(d->stk[--d->nstk]);
        if (d->frame) {
            long long e = dent ? dent[bi] : 0;
            setr(d, 4, e ? exf("(fr + %lld)", d->frame + e) : exf("(fr + %d)", d->frame));
        }
        for (int r = 0; r < 32; r++) { if (d->xhas[r]) ex_free(d->xreg[r]); d->xhas[r] = 0; }
        d->cmp = NULL;
        if (d->cmp_snap) { ex_free(d->cmpa); ex_free(d->cmpb); d->cmp_snap = 0; }
        emit(d, depth + 1, "%s (st == %d) {", bi ? "} else if" : "if", bi);
        int nb = b->ninsns;
        const IrInsn *t = nb ? &b->insns[nb - 1] : NULL;
        int isterm = t && ir_is_terminator(t->op);
        int nbody = isterm ? nb - 1 : nb;
        for (int k = 0; k < nbody; k++) step(d, &b->insns[k], depth + 2, NULL);
        if (t && t->op == IR_RET) {
            emit_ret(d, depth + 2);
        } else if (t && t->op == IR_BR) {
            materialize(d, depth + 2);
            Ex c = br_cond(d, t, b);
            char bb[1024];
            emit(d, depth + 2, "if (%s) {", bare(c.s, bb, sizeof bb));
            emit(d, depth + 3, "st = %d;", t->a.block);
            emit(d, depth + 2, "} else {");
            emit(d, depth + 3, "st = %d;", t->b.block);
            emit(d, depth + 2, "}");
            ex_free(c);
        } else {
            materialize(d, depth + 2);
            int nx = -1;
            if (t && t->op == IR_JMP && t->a.kind == IR_O_BLOCK) nx = t->a.block;
            else if (b->nsucc >= 1) nx = b->succ[0];
            else if (!isterm && bi + 1 < f->nblocks) nx = bi + 1;
            if (nx >= 0) emit(d, depth + 2, "st = %d;", nx);
            else emit_ret(d, depth + 2);
        }
    }
    emit(d, depth + 1, "}");
    emit(d, depth, "}");
    free(dent);
}

static void decompile_fun(D *d, Fun *fi) {
    if (fi->kind == 1 || fi->kind == 3) return;
    const IrFunc *f = NULL;
    for (int i = 0; i < d->m->nfuncs; i++) if (d->m->funcs[i].addr == fi->addr) { f = &d->m->funcs[i]; break; }
    if (!f) return;

    FILE *dt_real = d->out;
    char *dt_buf = NULL; size_t dt_len = 0;
    FILE *dt_m = open_memstream(&dt_buf, &dt_len);
    if (dt_m) d->out = dt_m;

    /* reset env */
    for (int i = 0; i < 16; i++) { if (d->has[i]) ex_free(d->reg[i]); d->has[i] = 0; }
    for (int i = 0; i < 32; i++) { if (d->xhas[i]) ex_free(d->xreg[i]); d->xhas[i] = 0; }
    while (d->nstk) ex_free(d->stk[--d->nstk]);
    d->cmp = NULL;
    d->cur = fi;
    G g;
    d->vused = 0;
    d->frame = d->foreign ? frame_size(f) : 0;
    d->fp = d->foreign ? frame_has_fp(f) : 0;
    d->fixed_x = -1;
    if (g_build(d, f, &g) == 0) {
        /* Trial structuring: when the region structurer cannot nest this
         * function, fall back to the exact dispatch loop if that is safe here.
         * A function that structures normally is never touched. */
        int dispatch = 0;
        if (d->foreign) {
            /* The passes below do not reset the compare snapshot, so save it and
             * put it back: the trial must leave their input exactly as it was. */
            /* A failure an earlier function already recorded must survive the trial. */
            int sv_fail = g_struct_fail;
            const char *sv_fn = g_struct_fail_fn;
            int sv_snap = d->cmp_snap;
            Ex sv_a = { NULL }, sv_b = { NULL };
            if (sv_snap) { sv_a = ex(d->cmpa.s); sv_b = ex(d->cmpb.s); }
            for (int i = 0; i < 16; i++) { if (d->has[i]) ex_free(d->reg[i]); d->has[i] = 0; }
            for (int i = 0; i < 32; i++) { if (d->xhas[i]) ex_free(d->xreg[i]); d->xhas[i] = 0; }
            while (d->nstk) ex_free(d->stk[--d->nstk]);
            for (int a = 0; a < fi->nargs; a++) setr(d, ARG[a], exf("%c", 'a' + a));
            if (d->frame) { setr(d, 4, exf("(fr + %d)", d->frame)); if (d->fp) setr(d, 5, exf("(fr + %d)", d->frame)); }
            d->cmp = NULL; memset(d->declared, 0, sizeof d->declared); d->flat = 1; d->nx = 0;
            g_budget = 20000; g_struct_fail = 0;
            char *tb = NULL; size_t tn = 0;
            FILE *sv = d->out, *tm = open_memstream(&tb, &tn);
            if (tm) { d->out = tm; structure(d, f, &g, 0, -1, NULL, 1, 0); fclose(tm); d->out = sv; }
            free(tb);
            if (g_struct_fail && dispatch_safe(d, f)) dispatch = 1;
            g_struct_fail = sv_fail; g_struct_fail_fn = sv_fn;
            d->vused = 0;
            if (d->cmp_snap) { ex_free(d->cmpa); ex_free(d->cmpb); }
            d->cmp_snap = sv_snap; d->cmpa = sv_a; d->cmpb = sv_b;
        }
        /* Pass 1 (discarded) collects hints; pass 2 prints. */
        int hdr_nx = 0;
        unsigned hdr_vu = 0;
        for (int pass = 0; pass < 2; pass++) {
            for (int i = 0; i < 16; i++) { if (d->has[i]) ex_free(d->reg[i]); d->has[i] = 0; }
            for (int i = 0; i < 32; i++) { if (d->xhas[i]) ex_free(d->xreg[i]); d->xhas[i] = 0; }
            while (d->nstk) ex_free(d->stk[--d->nstk]);
            for (int a = 0; a < fi->nargs; a++) setr(d, ARG[a], exf("%c", 'a' + a));
            if (d->frame) { setr(d, 4, exf("(fr + %d)", d->frame)); if (d->fp) setr(d, 5, exf("(fr + %d)", d->frame)); }
            d->cmp = NULL;
            memset(d->declared, 0, sizeof d->declared);
            d->flat = 1;
            d->nx = 0;
            g_budget = 20000;
            if (pass == 0) {
                char *buf = NULL; size_t n = 0;
                FILE *save = d->out, *m = open_memstream(&buf, &n);
                if (!m) continue;
                d->out = m;
                if (dispatch) emit_dispatch(d, f, 1); else structure(d, f, &g, 0, -1, NULL, 1, 0);
                fclose(m); free(buf);
                d->out = save;
                finish_hints(d, f, fi);
                fprintf(d->out, "fn %s(", fi->name);
                for (int a = 0; a < fi->nargs; a++) fprintf(d->out, "%s%c", a ? ", " : "", 'a' + a);
                fprintf(d->out, ") {\n");
                if (d->frame) { d->need_gfr = 1; fprintf(d->out, "    gfr = alloc(%d);\n    let fr = gfr; // stack frame (arrays / addresses), rsp = fr + %d; freed at each return\n", 2 * d->frame, d->frame); }
                for (int r = 0; r < 16; r++) if (d->vused & (1u << r)) fprintf(d->out, "    let v%d = 0;\n", r);
                for (int r = 0; r < 16; r++) if (d->vused & (1u << (16 + r))) fprintf(d->out, "    let w%d = 0;\n", r);
                for (int k = 0; k < d->nx; k++) fprintf(d->out, "    let x%d = 0;\n", k);
                hdr_nx = d->nx; hdr_vu = d->vused;
            } else {
                /* x temporaries first seen in this pass get declared too */
                int nx0 = hdr_nx;
                unsigned vu0 = hdr_vu;
                char *buf = NULL; size_t n = 0;
                FILE *save = d->out, *m = open_memstream(&buf, &n);
                memset(d->written, 0, sizeof d->written);
                d->nx = 0;
                if (m) d->out = m;
                if (dispatch) emit_dispatch(d, f, 1); else structure(d, f, &g, 0, -1, NULL, 1, 0);
                if (m) {
                    fclose(m);
                    d->out = save;
                    for (int k = nx0; k < d->nx; k++) fprintf(d->out, "    let x%d = 0;\n", k);
                    for (int r = 0; r < 16; r++) if ((d->vused & ~vu0) & (1u << r)) fprintf(d->out, "    let v%d = 0;\n", r);
                    for (int r = 0; r < 16; r++) if ((d->vused & ~vu0) & (1u << (16 + r))) fprintf(d->out, "    let w%d = 0;\n", r);
                    fputs(buf, d->out);
                    free(buf);
                }
            }
        }
    } else {
        fprintf(d->out, "fn %s() {\n", fi->name);
        emit(d, 1, "// E600: could not build the control-flow graph for this function");
    }
    g_free(&g);
    fprintf(d->out, "}\n\n");
    if (dt_m) {
        fclose(dt_m);
        d->out = dt_real;
        char *clean = strip_dead_temps(dt_buf);
        fputs(clean ? clean : dt_buf, d->out);
        free(clean); free(dt_buf);
    }
}

int rex_decompile(const char *inpath, const char *outpath, int verbose) {
    RexElf e;
    CfgProgram p;
    char err[256];
    { int _rc = rex_bin_open(inpath, &e, err, sizeof(err)); if (_rc) { rex_refuse(err); return _rc; } }
    { int _c = cfg_build(&e, &p, err, sizeof(err)); if (_c) { rex_refuse(err); rex_elf_free(&e); return _c; } }
    IrModule *m = x86_lift(&p, err, sizeof(err));
    if (!m) { rex_refuse(err); cfg_free(&p); rex_elf_free(&e); return REX_E300_LIFT; }
    for (int fi = 0; fi < m->nfuncs; fi++) {
        if (strcmp(m->funcs[fi].name, "main") != 0 && m->funcs[fi].addr != p.main_addr) continue;
        int *idom = compute_idom(&m->funcs[fi]);
        if (idom && cfg_irreducible(&m->funcs[fi], idom)) {
            free(idom);
            int _e = rex_errf(err, sizeof(err), REX_E402_IRREDUCIBLE, "%s", m->funcs[fi].name);
            rex_refuse(err);
            ir_module_free(m); cfg_free(&p); rex_elf_free(&e);
            return _e;
        }
        free(idom);
    }
    FILE *out = fopen(outpath, "w");
    if (!out) { fprintf(stderr, "rex: decompile: cannot write %s\n", outpath); ir_module_free(m); cfg_free(&p); rex_elf_free(&e); return REX_E600_DECOMPILE; }

    D d = {0};
    d.m = m; d.cfg = &p; d.verbose = verbose;
    d.foreign = e.nsh > 0;
    d.elf = &e;
    char *body = NULL; size_t bodyn = 0;
    d.out = open_memstream(&body, &bodyn);
    if (!d.out) d.out = out;
    d.fun = calloc((size_t)m->nfuncs, sizeof(Fun));
    d.nfun = m->nfuncs;
    classify(&d);
    compute_clobbers(&d);
    if (d.foreign) foreign_args(&d);
    blob_scan(&d);


    g_struct_fail = 0; g_struct_fail_fn = NULL;
    g_libcalls = 0; g_libname[0] = 0;
    compute_reach(&d);
    if (d.foreign) shape_reached(&d);
    if (d.foreign) compute_taken(&d);
    g_fpcall = 0; g_fpwhy[0] = 0;
    for (int i = 0; i < d.nfun; i++) if (d.fun[i].kind == 0) decompile_fun(&d, &d.fun[i]);
    for (int i = 0; i < d.nfun; i++) if (d.fun[i].kind == 2) decompile_fun(&d, &d.fun[i]);
    if (g_struct_fail) {
        /* A function could not be structured within the budget. Refuse the
         * whole decompile with a clean E402 instead of writing broken stubs. */
        if (d.out != out) fclose(d.out);
        free(body);
        for (int i = 0; i < 16; i++) if (d.has[i]) ex_free(d.reg[i]);
        while (d.nstk) ex_free(d.stk[--d.nstk]);
        free(d.stk);
        free(d.fun);
        fclose(out);
        remove(outpath);
        int _e = rex_errf(err, sizeof(err), REX_E402_IRREDUCIBLE, "%s",
                          g_struct_fail_fn ? g_struct_fail_fn : "a function");
        rex_refuse(err);
        ir_module_free(m); cfg_free(&p); rex_elf_free(&e);
        return _e;
    }
    if (d.out != out) fclose(d.out);
    fprintf(out, "// recovered by rex decompile\n");
    if (d.foreign)
        fprintf(out, "// not REX-built: vN are registers, g_ADDR are globals, C widths are masked; names are invented\n\n");
    else
        fprintf(out, "// REX-built ELF64 only; names are invented\n\n");
    /* REX globals take a plain number; negative initial values are set first thing in main. */
    static char negs[65536];
    negs[0] = 0;
    for (int i = 0; i < d.nglob; i++) {
        long long iv = d.glob[i].init;
        fprintf(out, "let g_%llx = %lld;\n%s", (unsigned long long)d.glob[i].addr, iv < 0 ? 0 : iv, i + 1 == d.nglob ? "\n" : "");
        if (iv < 0 && strlen(negs) + 64 < sizeof negs && (unsigned long long)iv == 1ULL << 63)
            snprintf(negs + strlen(negs), sizeof negs - strlen(negs), "    g_%llx = 0 - 9223372036854775807 - 1;\n",
                     (unsigned long long)d.glob[i].addr);
        else if (iv < 0 && strlen(negs) + 64 < sizeof negs)
            snprintf(negs + strlen(negs), sizeof negs - strlen(negs), "    g_%llx = 0 - %llu;\n",
                     (unsigned long long)d.glob[i].addr, 0ULL - (unsigned long long)iv);
    }
    if (d.need_udiv)
        fprintf(out, "// unsigned 64-bit divide (REX / is signed)\n"
            "fn udiv(a, b) {\n"
            "    let m = -9223372036854775807 - 1;\n"
            "    if (b < 0) { if ((a ^ m) >= (b ^ m)) { return 1; } return 0; }\n"
            "    let q = (((a >> 1) & 9223372036854775807) / b) << 1;\n"
            "    let r = a - q * b;\n"
            "    if ((r ^ m) >= (b ^ m)) { q = q + 1; }\n"
            "    return q;\n"
            "}\n\n"
            "fn urem(a, b) { return a - udiv(a, b) * b; }\n\n");
    if (d.need_mulh)
        fprintf(out, "// high 64 bits of a 128-bit product (one-operand mul/imul)\n"
            "fn umulh(a, b) {\n"
            "    let m = 4294967295;\n"
            "    let al = a & m;\n"
            "    let ah = (a >> 32) & m;\n"
            "    let bl = b & m;\n"
            "    let bh = (b >> 32) & m;\n"
            "    let lh = al * bh;\n"
            "    let hl = ah * bl;\n"
            "    let mid = ((al * bl >> 32) & m) + (lh & m) + (hl & m);\n"
            "    return ah * bh + ((lh >> 32) & m) + ((hl >> 32) & m) + ((mid >> 32) & m);\n"
            "}\n\n"
            "fn smulh(a, b) {\n"
            "    let h = umulh(a, b);\n"
            "    if (a < 0) { h = h - b; }\n"
            "    if (b < 0) { h = h - a; }\n"
            "    return h;\n"
            "}\n\n");
    if (d.need_callp) {
        /* the functions whose address is a value, by that address in the original */
        fprintf(out, "// a call through a function pointer: the pointer holds an original address\n"
                     "fn callp(p");
        static const char *pn[5] = { "a", "b", "c", "d", "e" };
        for (int a = 0; a < d.callp_n; a++) fprintf(out, ", %s", pn[a]);
        fprintf(out, ") {\n");
        for (int i = 0; i < d.nfun; i++) {
            const Fun *fi = &d.fun[i];
            if (fi->kind != 0 || !fi->taken) continue;
            int na = fi->nargs;
            if (na > 5) { fprintf(out, "    // %s takes %d arguments: left out\n", fi->name, na); continue; }
            fprintf(out, "    if (p == %llu) { return %s(", (unsigned long long)m->funcs[i].addr, fi->name);
            for (int a = 0; a < na; a++) fprintf(out, "%s%s", a ? ", " : "", pn[a]);
            fprintf(out, "); }\n");
        }
        fprintf(out, "    let z = 0;\n"
                     "    return 1 / z; // not a function REX recovered: stop, as a jump there would\n"
                     "}\n\n");
    }
    if (d.need_gfr) fprintf(out, "let gfr = 0;%s\n", d.blob ? "" : "\n");
    if (d.blob) {
        fprintf(out, "let gmem = 0; // data sections 0x%llx..0x%llx\n\n", (unsigned long long)d.blo, (unsigned long long)d.bhi);
        size_t n = strlen(negs);
        snprintf(negs + n, sizeof negs - n, "    gmem = alloc(%llu);\n", (unsigned long long)(d.bhi - d.blo + BLOB_SLACK + 8));
        for (int i = 0; i < e.nsh; i++) {
            const RexShdr *sh = &e.sh[i];
            if (!(sh->flags & 2) || (sh->flags & 4) || sh->addr < d.blo || sh->addr >= d.bhi || sh->type == 8 || !sh->size) continue;
            if (!(sh->flags & 1) && strncmp(sh->name, ".rodata", 7)) continue;
            for (uint64_t o = 0; o < sh->size; o += 8) {
                long long v = 0;
                size_t w = sh->size - o < 8 ? (size_t)(sh->size - o) : 8;
                if (sh->offset + o + w > e.size) break;
                memcpy(&v, e.data + sh->offset + o, w);
                if (!v) continue;
                char line[96];
                if ((unsigned long long)v == 1ULL << 63) snprintf(line, sizeof line, "    *(gmem + %llu) = 0 - 9223372036854775807 - 1;\n", (unsigned long long)(sh->addr + o - d.blo));
                else if (v < 0) snprintf(line, sizeof line, "    *(gmem + %llu) = 0 - %lld;\n", (unsigned long long)(sh->addr + o - d.blo), -v);
                else snprintf(line, sizeof line, "    *(gmem + %llu) = %lld;\n", (unsigned long long)(sh->addr + o - d.blo), v);
                n = strlen(negs);
                if (n + strlen(line) + 1 >= sizeof negs) break;
                memcpy(negs + n, line, strlen(line) + 1);
            }
        }
    }
    if (body && negs[0]) {
        char *mp = strstr(body, "fn main() {\n");
        if (mp) {
            mp += strlen("fn main() {\n");
            fwrite(body, 1, (size_t)(mp - body), out);
            fputs(negs, out);
            fputs(mp, out);
            free(body); body = NULL;
        }
    }
    if (body) fputs(body, out);
    free(body);

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
