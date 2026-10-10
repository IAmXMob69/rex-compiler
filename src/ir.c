#include <stdlib.h>
#include <string.h>
#include "ir.h"

/* Machine IR: containers, constructors, checks, printer. */

#define IR_MAX_ITEMS (1 << 24)

static int grow(void **p, int *cap, int need, size_t elem) {
    if (need <= *cap) return 0;
    if (need > IR_MAX_ITEMS) return -1;
    int nc = *cap ? *cap : 8;
    while (nc < need) nc *= 2;
    void *np = realloc(*p, (size_t)nc * elem);
    if (!np) return -1;
    *p = np;
    *cap = nc;
    return 0;
}

IrModule *ir_module_new(void) { return calloc(1, sizeof(IrModule)); }

void ir_module_free(IrModule *m) {
    if (!m) return;
    for (int i = 0; i < m->nfuncs; i++) {
        IrFunc *f = &m->funcs[i];
        for (int b = 0; b < f->nblocks; b++) free(f->blocks[b].insns);
        free(f->blocks);
    }
    free(m->funcs);
    free(m);
}

IrFunc *ir_func_add(IrModule *m, const char *name, uint64_t addr) {
    if (grow((void **)&m->funcs, &m->cap, m->nfuncs + 1, sizeof(IrFunc))) return NULL;
    IrFunc *f = &m->funcs[m->nfuncs++];
    memset(f, 0, sizeof(*f));
    snprintf(f->name, sizeof(f->name), "%s", name ? name : "");
    f->addr = addr;
    return f;
}

int ir_block_add(IrFunc *f, uint64_t addr) {
    if (grow((void **)&f->blocks, &f->cap, f->nblocks + 1, sizeof(IrBlock))) return -1;
    IrBlock *b = &f->blocks[f->nblocks];
    memset(b, 0, sizeof(*b));
    b->id = f->nblocks;
    b->addr = addr;
    return f->nblocks++;
}

IrInsn *ir_emit(IrFunc *f, int block, IrOp op) {
    if (block < 0 || block >= f->nblocks || op < 0 || op >= IR_OP_COUNT) return NULL;
    IrBlock *b = &f->blocks[block];
    if (grow((void **)&b->insns, &b->cap, b->ninsns + 1, sizeof(IrInsn))) return NULL;
    IrInsn *in = &b->insns[b->ninsns++];
    memset(in, 0, sizeof(*in));
    in->op = op;
    return in;
}

IrOperand ir_reg(int reg, int width) {
    IrOperand o = {0}; o.kind = IR_O_REG; o.reg = reg; o.width = width; o.base = o.index = IR_NOREG; return o;
}
IrOperand ir_imm(int64_t v, int width) {
    IrOperand o = {0}; o.kind = IR_O_IMM; o.imm = v; o.width = width; o.base = o.index = IR_NOREG; return o;
}
IrOperand ir_mem(int base, int index, int scale, int64_t disp, int width) {
    IrOperand o = {0}; o.kind = IR_O_MEM; o.base = base; o.index = index;
    o.scale = index == IR_NOREG ? 1 : scale; o.disp = disp; o.width = width; return o;
}
IrOperand ir_blk(int block) {
    IrOperand o = {0}; o.kind = IR_O_BLOCK; o.block = block; o.base = o.index = IR_NOREG; return o;
}
IrOperand ir_abs(uint64_t addr) {
    IrOperand o = {0}; o.kind = IR_O_ADDR; o.addr = addr; o.base = o.index = IR_NOREG; return o;
}

int ir_is_terminator(IrOp op) { return op == IR_JMP || op == IR_BR || op == IR_RET; }

static int bad(char *err, size_t n, const IrFunc *f, int b, const char *m) {
    if (err && n) snprintf(err, n, "%s: b%d: %s", f->name, b, m);
    return -1;
}

int ir_link(IrFunc *f, char *err, size_t errlen) {
    for (int i = 0; i < f->nblocks; i++) {
        IrBlock *b = &f->blocks[i];
        b->nsucc = 0;
        for (int k = 0; k + 1 < b->ninsns; k++)
            if (ir_is_terminator(b->insns[k].op)) return bad(err, errlen, f, i, "terminator in middle of block");
        if (b->ninsns == 0) {
            if (i + 1 < f->nblocks) { b->succ[b->nsucc++] = i + 1; continue; }
            return bad(err, errlen, f, i, "empty last block");
        }
        IrInsn *t = &b->insns[b->ninsns - 1];
        if (t->op == IR_BR) {
            if (t->cc == IR_CC_NONE || t->cc >= IR_CC_COUNT) return bad(err, errlen, f, i, "branch without condition");
            if (t->a.kind != IR_O_BLOCK || t->b.kind != IR_O_BLOCK) return bad(err, errlen, f, i, "branch needs two blocks");
            if (t->a.block < 0 || t->a.block >= f->nblocks || t->b.block < 0 || t->b.block >= f->nblocks)
                return bad(err, errlen, f, i, "branch to missing block");
            b->succ[b->nsucc++] = t->a.block;
            if (t->b.block != t->a.block) b->succ[b->nsucc++] = t->b.block;
        } else if (t->op == IR_JMP) {
            if (t->a.kind == IR_O_BLOCK) {
                if (t->a.block < 0 || t->a.block >= f->nblocks) return bad(err, errlen, f, i, "jump to missing block");
                b->succ[b->nsucc++] = t->a.block;
            }
        } else if (t->op != IR_RET) {
            if (i + 1 >= f->nblocks) return bad(err, errlen, f, i, "falls off end of function");
            b->succ[b->nsucc++] = i + 1;
        }
    }
    return 0;
}

static const char *opnames[IR_OP_COUNT] = {
    "nop", "mov", "load", "store", "addr",
    "add", "sub", "mul", "divs", "rems",
    "and", "or", "xor", "shl", "shr", "sar",
    "neg", "not", "zext", "sext",
    "cmp", "test", "setcc",
    "jmp", "br", "call", "ret",
    "push", "pop", "syscall",
};
static const char *ccnames[IR_CC_COUNT] = {
    "", "eq", "ne", "lt", "le", "gt", "ge", "ult", "ule", "ugt", "uge", "neg", "pos",
};

const char *ir_op_name(IrOp op) { return op >= 0 && op < IR_OP_COUNT ? opnames[op] : "?"; }
const char *ir_cc_name(IrCond cc) { return cc >= 0 && cc < IR_CC_COUNT ? ccnames[cc] : "?"; }

static void preg(FILE *out, const IrModule *m, int r) {
    if (r == IR_PC) { fputs("pc", out); return; }
    const char *n = m && m->reg_name ? m->reg_name(r) : NULL;
    if (n) fputs(n, out); else fprintf(out, "r%d", r);
}

void ir_print_operand(FILE *out, const IrModule *m, const IrOperand *o) {
    switch (o->kind) {
    case IR_O_NONE: break;
    case IR_O_REG: preg(out, m, o->reg); fprintf(out, ":%d", o->width); break;
    case IR_O_IMM: fprintf(out, "%lld", (long long)o->imm); break;
    case IR_O_BLOCK: fprintf(out, "b%d", o->block); break;
    case IR_O_ADDR: fprintf(out, "0x%llx", (unsigned long long)o->addr); break;
    case IR_O_MEM: {
        int any = 0;
        fputc('[', out);
        if (o->base != IR_NOREG) { preg(out, m, o->base); any = 1; }
        if (o->index != IR_NOREG) { if (any) fputs(" + ", out); preg(out, m, o->index); fprintf(out, "*%d", o->scale); any = 1; }
        if (o->disp || !any) {
            if (!any) fprintf(out, "0x%llx", (unsigned long long)o->disp);
            else if (o->disp < 0) fprintf(out, " - %llu", (unsigned long long)(-(uint64_t)o->disp));
            else fprintf(out, " + %lld", (long long)o->disp);
        }
        fprintf(out, "]:%d", o->width);
        break;
    }
    }
}

void ir_print_func(FILE *out, const IrModule *m, const IrFunc *f) {
    fprintf(out, "func %s @0x%llx\n", f->name, (unsigned long long)f->addr);
    for (int i = 0; i < f->nblocks; i++) {
        const IrBlock *b = &f->blocks[i];
        fprintf(out, "b%d:", i);
        if (b->addr) fprintf(out, "  ; 0x%llx", (unsigned long long)b->addr);
        fputc('\n', out);
        for (int k = 0; k < b->ninsns; k++) {
            const IrInsn *in = &b->insns[k];
            fprintf(out, "    %s", ir_op_name(in->op));
            if (in->cc != IR_CC_NONE) fprintf(out, ".%s", ir_cc_name(in->cc));
            const IrOperand *ops[3] = { &in->dst, &in->a, &in->b };
            int first = 1;
            for (int j = 0; j < 3; j++) {
                if (ops[j]->kind == IR_O_NONE) continue;
                fputs(first ? " " : ", ", out);
                ir_print_operand(out, m, ops[j]);
                first = 0;
            }
            fputc('\n', out);
        }
    }
}
