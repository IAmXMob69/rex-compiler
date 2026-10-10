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
 * - Nested structs, switch, and most pointer arithmetic stay opaque.
 * - Runtime helpers (print, putc, alloc, ...) are recognized by
 *   syscalls and are not emitted; calls to them become builtins.
 */

enum { MAX_LOC = 64 };

typedef struct { char *s; } Ex;

static Ex ex(const char *s) { return (Ex){ strdup(s ? s : "?") }; }
static Ex exf(const char *fmt, ...) {
    char b[256];
    va_list ap; va_start(ap, fmt); vsnprintf(b, sizeof(b), fmt, ap); va_end(ap);
    return ex(b);
}
static void ex_free(Ex e) { free(e.s); }
static Ex ex_bin(const char *op, Ex a, Ex b) {
    Ex r = exf("(%s %s %s)", a.s, op, b.s);
    ex_free(a); ex_free(b);
    return r;
}
static Ex ex_un(const char *op, Ex a) {
    Ex r = exf("(%s%s)", op, a.s);
    ex_free(a);
    return r;
}

typedef struct {
    int off;
    char name[16];
    int arg;        /* 0..5, or -1 */
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
} D;

static const int ARG[6] = { 7, 6, 2, 1, 8, 9 };

static Fun *fby(D *d, uint64_t a) {
    for (int i = 0; i < d->nfun; i++) if (d->fun[i].addr == a) return &d->fun[i];
    return NULL;
}

static void setr(D *d, int r, Ex v) {
    if (r < 0 || r > 15) { ex_free(v); return; }
    if (d->has[r]) ex_free(d->reg[r]);
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
    for (int i = 0; i < f->nslots; i++) if (f->slots[i].off == off) return f->slots[i].name;
    return NULL;
}
static void add_slot(Fun *f, int off, int arg) {
    for (int i = 0; i < f->nslots; i++) if (f->slots[i].off == off) return;
    if (f->nslots >= MAX_LOC) return;
    Slot *s = &f->slots[f->nslots++];
    s->off = off; s->arg = arg;
    if (arg >= 0) snprintf(s->name, sizeof(s->name), "%c", 'a' + arg);
    else snprintf(s->name, sizeof(s->name), "t%d", f->nslots);
}

static Ex mem_ex(D *d, const IrOperand *o) {
    if (o->base == 5 && o->index == IR_NOREG) {
        const char *n = slot_name(d->cur, (int)o->disp);
        if (n) return ex(n);
        return exf("m%d", (int)o->disp);
    }
    if (o->base == 5 && o->index != IR_NOREG && o->scale == 8) {
        /* Local array cell: nearest slot at or below disp. */
        const char *base = NULL;
        int best = 1;
        for (int i = 0; i < d->cur->nslots; i++) {
            int dlt = (int)o->disp - d->cur->slots[i].off;
            if (dlt >= 0 && dlt % 8 == 0 && (!base || dlt < best)) { base = d->cur->slots[i].name; best = dlt; }
        }
        if (base) {
            Ex ix = getr(d, o->index);
            if (best) {
                Ex r = exf("%s[(%s + %d)]", base, ix.s, best / 8);
                ex_free(ix);
                return r;
            }
            Ex r = exf("%s[%s]", base, ix.s);
            ex_free(ix);
            return r;
        }
    }
    if (o->base == 5) o = o; /* keep going */
    Ex b = o->base == 5 ? ex("fp") : (o->base != IR_NOREG ? getr(d, o->base) : ex("0"));
    if (o->index != IR_NOREG) {
        Ex ix = getr(d, o->index);
        if (o->scale != 1) ix = ex_bin("*", ix, exf("%d", o->scale));
        b = ex_bin("+", b, ix);
    }
    if (o->disp) b = ex_bin("+", b, exf("%lld", (long long)o->disp));
    Ex r = exf("*(%s)", b.s);
    ex_free(b);
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
        emit(d, depth, "%s = %s;", dst.s, src.s);
        ex_free(dst); ex_free(src);
        break;
    }
    case IR_ADDR:
        if (in->dst.kind == IR_O_REG) {
            if (in->a.kind == IR_O_MEM && in->a.base == IR_NOREG && in->a.index == IR_NOREG)
                setr(d, in->dst.reg, exf("%lld", (long long)in->a.disp));  /* absolute address as number */
            else {
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
        Ex v;
        if (d->cmp && d->cmp->op == IR_CMP)
            v = ex_bin(cop(in->cc), op_ex(d, &d->cmp->a), op_ex(d, &d->cmp->b));
        else if (d->cmp)
            v = in->cc == IR_CC_EQ ? ex_un("!", op_ex(d, &d->cmp->a)) : op_ex(d, &d->cmp->a);
        else v = ex("0");
        if (in->dst.kind == IR_O_REG) setr(d, in->dst.reg, v);
        else ex_free(v);
        break;
    }
    case IR_CMOV: {
        /* REX has no ternary. Keep the source value; precise if/else recovery is future work. */
        Ex src = op_ex(d, &in->a);
        if (in->dst.kind == IR_O_REG) setr(d, in->dst.reg, src);
        else ex_free(src);
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
                if (a) strcat(args, ", ");
                strcat(args, e.s);
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
            if (a) strcat(args, ", ");
            strcat(args, e.s);
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

/* Returns join block, or -1. */
static int is_ret_block(const IrFunc *f, int bi) {
    if (bi < 0 || bi >= f->nblocks) return 0;
    const IrBlock *b = &f->blocks[bi];
    if (!b->ninsns) return 0;
    for (int k = 0; k < b->ninsns - 1; k++)
        if (!is_epilog(&b->insns[k]) && b->insns[k].op != IR_NOP) return 0;
    return b->insns[b->ninsns - 1].op == IR_RET;
}
static int falls_through(const IrInsn *t) {
    return !t || (t->op != IR_JMP && t->op != IR_BR && t->op != IR_RET && t->op != IR_TRAP);
}
static int find_join(const IrFunc *f, int a, int b) {
    if (a < 0 || b < 0 || a >= f->nblocks || b >= f->nblocks) return -1;
    const IrInsn *ta = f->blocks[a].ninsns ? &f->blocks[a].insns[f->blocks[a].ninsns - 1] : NULL;
    const IrInsn *tb = f->blocks[b].ninsns ? &f->blocks[b].insns[f->blocks[b].ninsns - 1] : NULL;
    if (ta && ta->op == IR_RET && tb && tb->op == IR_RET) return -2;
    if (is_ret_block(f, a) && is_ret_block(f, b)) return -2;
    if (ta && ta->op == IR_JMP && tb && tb->op == IR_JMP && ta->a.block == tb->a.block) {
        if (is_ret_block(f, ta->a.block)) return -2;
        return ta->a.block;
    }
    /* One arm jumps to J, the other falls through into J. */
    if (ta && ta->op == IR_JMP && falls_through(tb) && b + 1 == ta->a.block) {
        if (is_ret_block(f, ta->a.block)) return -2;
        return ta->a.block;
    }
    if (tb && tb->op == IR_JMP && falls_through(ta) && a + 1 == tb->a.block) {
        if (is_ret_block(f, tb->a.block)) return -2;
        return tb->a.block;
    }
    if (tb && tb->op == IR_JMP && tb->a.block == a) return is_ret_block(f, a) ? -2 : a;
    if (ta && ta->op == IR_JMP && ta->a.block == b) return is_ret_block(f, b) ? -2 : b;
    return -1;
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
    if (cmp && cmp->op == IR_CMP) return ex_bin(cop(br->cc), op_ex(d, &cmp->a), op_ex(d, &cmp->b));
    if (cmp) {
        Ex a = op_ex(d, &cmp->a);
        return br->cc == IR_CC_EQ ? ex_un("!", a) : a;
    }
    return ex("1");
}

/* Cleaner while handling: second pass over BR that looks like a loop header. */
static int is_loop_header(const IrFunc *f, int bi) {
    /* A back-edge comes from a later block (or the block itself). Forward
     * branches that land on bi do not make it a loop header. */
    for (int bb = bi; bb < f->nblocks; bb++) {
        const IrInsn *t = f->blocks[bb].ninsns ? &f->blocks[bb].insns[f->blocks[bb].ninsns - 1] : NULL;
        if (!t) continue;
        if (t->op == IR_JMP && t->a.block == bi) return 1;
        if (t->op == IR_BR && bb != bi && (t->a.block == bi || t->b.block == bi)) return 1;
    }
    return 0;
}

static void walk2(D *d, const IrFunc *f, int bi, int until, int depth, int *seen) {
    while (bi >= 0 && bi < f->nblocks && bi != until && !seen[bi]) {
        seen[bi] = 1;
        const IrBlock *b = &f->blocks[bi];
        const IrInsn *term = b->ninsns ? &b->insns[b->ninsns - 1] : NULL;
        int nbody = term && ir_is_terminator(term->op) ? b->ninsns - 1 : b->ninsns;
        for (int k = 0; k < nbody; k++) step(d, &b->insns[k], depth, NULL);

        if (!term) break;

        if (term->op == IR_BR) {
            Ex cond = br_cond(d, term, b);
            int taken = term->a.block, fall = term->b.block;
            int join = find_join(f, taken, fall);

            if (is_loop_header(f, bi)) {
                /* Body is the side that jumps back. Prefer fall if it jmps to bi. */
                int body = fall, exitb = taken;
                int body_backs = 0;
                {
                    const IrInsn *t = f->blocks[fall].ninsns ? &f->blocks[fall].insns[f->blocks[fall].ninsns-1] : NULL;
                    if (t && t->op == IR_JMP && t->a.block == bi) body_backs = 1;
                }
                if (!body_backs) {
                    const IrInsn *t = f->blocks[taken].ninsns ? &f->blocks[taken].insns[f->blocks[taken].ninsns-1] : NULL;
                    if (t && t->op == IR_JMP && t->a.block == bi) { body = taken; exitb = fall; body_backs = 1; }
                }
                if (body_backs) {
                    Ex c;
                    if (exitb == taken) {
                        if (cond.s[0]=='(' && cond.s[1]=='!') {
                            char *s = strdup(cond.s + 2);
                            size_t L = strlen(s);
                            if (L && s[L-1]==')') s[L-1]=0;
                            c = (Ex){ s };
                        } else c = ex_un("!", ex(cond.s));
                        ex_free(cond);
                    } else c = cond;
                    emit(d, depth, "while (%s) {", c.s);
                    ex_free(c);
                    int *seen2 = calloc((size_t)f->nblocks, sizeof(int));
                    /* Allow the header to be "seen" so body doesn't re-enter walk of header. */
                    seen2[bi] = 1;
                    walk2(d, f, body, bi, depth + 1, seen2);
                    free(seen2);
                    emit(d, depth, "}");
                    bi = exitb;
                    continue;
                }
            }

            /* Div-zero / bounds checks: taken arm calls an unrecovered helper and
             * does nothing else interesting. */
            {
                int saw_fail = 0, only_fail = 1;
                const IrBlock *tb = &f->blocks[taken];
                for (int k = 0; k < tb->ninsns; k++) {
                    const IrInsn *in = &tb->insns[k];
                    if (is_prolog(in) || is_epilog(in) || in->op == IR_NOP || in->op == IR_TRAP) continue;
                    if (in->op == IR_JMP || in->op == IR_RET) continue;
                    if (in->op == IR_ADDR || in->op == IR_ZEXT || in->op == IR_SEXT) continue;
                    if (in->op == IR_MOV && in->a.kind != IR_O_IMM) { only_fail = 0; break; }
                    if (in->op == IR_MOV) continue;
                    if (in->op == IR_CALL && in->a.kind == IR_O_ADDR) {
                        Fun *t = fby(d, in->a.addr);
                        if (!t || t->kind == 3) { saw_fail = 1; continue; }
                    }
                    only_fail = 0; break;
                }
                if (only_fail && saw_fail && !is_loop_header(f, bi)) {
                    ex_free(cond);
                    const IrInsn *tl = tb->ninsns ? &tb->insns[tb->ninsns - 1] : NULL;
                    if (falls_through(tl) && taken + 1 < f->nblocks) bi = taken + 1;
                    else if (tl && tl->op == IR_JMP) bi = tl->a.block;
                    else bi = fall;
                    continue;
                }
            }
            emit(d, depth, "if (%s) {", cond.s);
            ex_free(cond);
            if (join == -2) {
                int rb = -1;
                {
                    const IrInsn *t = f->blocks[taken].ninsns ? &f->blocks[taken].insns[f->blocks[taken].ninsns-1] : NULL;
                    if (t && t->op == IR_JMP) rb = t->a.block;
                    else if (is_ret_block(f, taken)) rb = taken;
                }
                walk2(d, f, taken, rb, depth + 1, seen);
                if (d->cur->kind != 2) emit(d, depth + 1, "return %s;", d->has[0] ? d->reg[0].s : "0");
                emit(d, depth, "} else {");
                if (d->has[0]) { ex_free(d->reg[0]); d->has[0] = 0; }
                walk2(d, f, fall, rb, depth + 1, seen);
                if (d->cur->kind != 2) emit(d, depth + 1, "return %s;", d->has[0] ? d->reg[0].s : "0");
                emit(d, depth, "}");
                return;
            }
            walk2(d, f, taken, join >= 0 ? join : until, depth + 1, seen);
            if (fall != join && !seen[fall]) {
                int need_else = join >= 0 || until < 0;
                if (need_else) {
                    emit(d, depth, "} else {");
                    walk2(d, f, fall, join >= 0 ? join : until, depth + 1, seen);
                }
            }
            emit(d, depth, "}");
            bi = join >= 0 ? join : -1;
            continue;
        }
        if (term->op == IR_JMP && term->a.kind == IR_O_BLOCK) { bi = term->a.block; continue; }
        if (term->op == IR_RET) {
            if (d->cur->kind != 2) {
                if (d->has[0]) emit(d, depth, "return %s;", d->reg[0].s);
                else emit(d, depth, "return 0;");
            }
            return;
        }
        if (b->nsucc == 1) bi = b->succ[0];
        else break;
    }
}

static void decompile_fun(D *d, Fun *fi) {
    if (fi->kind == 1 || fi->kind == 3) return;
    const IrFunc *f = NULL;
    for (int i = 0; i < d->m->nfuncs; i++) if (d->m->funcs[i].addr == fi->addr) { f = &d->m->funcs[i]; break; }
    if (!f) return;

    fprintf(d->out, "fn %s(", fi->name);
    for (int a = 0; a < fi->nargs; a++) fprintf(d->out, "%s%c", a ? ", " : "", 'a' + a);
    fprintf(d->out, ") {\n");
    for (int i = 0; i < fi->nslots; i++)
        if (fi->slots[i].arg < 0) fprintf(d->out, "    let %s = 0;\n", fi->slots[i].name);

    /* reset env */
    for (int i = 0; i < 16; i++) { if (d->has[i]) ex_free(d->reg[i]); d->has[i] = 0; }
    while (d->nstk) ex_free(d->stk[--d->nstk]);
    d->cmp = NULL;
    d->cur = fi;
    /* Seed arg regs from parameters for functions that don't spill. */
    for (int a = 0; a < fi->nargs; a++) setr(d, ARG[a], exf("%c", 'a' + a));

    int *seen = calloc((size_t)f->nblocks, sizeof(int));
    walk2(d, f, 0, -1, 1, seen);
    free(seen);
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
