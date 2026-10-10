#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "x86_lift.h"
#include "rex_err.h"

enum { FL_NONE, FL_CMP, FL_RESULT };

typedef struct {
    IrFunc *f;
    int block;
    const CfgFunc *cf;
    const X86Insn *in;
    int flags;
    IrOperand res;
    char *err;
    size_t errlen;
    int bad;
    int bfirst;
} L;

static void lfail(L *l, const char *fmt, ...) {
    if (l->bad) return;
    l->bad = 1;
    int code = REX_E300_LIFT;
    if (l->in && (l->in->op == X86_IDIV || l->in->op == X86_DIV)) code = REX_E302_IDIV;
    char detail[160];
    int k = snprintf(detail, sizeof(detail), "%s at 0x%llx: ", l->cf->name, (unsigned long long)l->in->addr);
    if (k < 0) k = 0;
    if ((size_t)k < sizeof(detail)) {
        va_list ap; va_start(ap, fmt);
        vsnprintf(detail + k, sizeof(detail) - (size_t)k, fmt, ap);
        va_end(ap);
    }
    rex_errf(l->err, l->errlen, code, "%s", detail);
}

static IrInsn *emit(L *l, IrOp op) {
    IrInsn *i = ir_emit(l->f, l->block, op);
    if (!i) { lfail(l, "out of memory"); static IrInsn sink; memset(&sink, 0, sizeof(sink)); return &sink; }
    i->origin = l->in->addr;
    return i;
}

static IrOperand conv(L *l, const X86Operand *o) {
    switch (o->kind) {
    case XO_REG:
        if (o->high8) lfail(l, "ah/bh/ch/dh are not supported");
        return ir_reg(o->reg, o->size);
    case XO_IMM: return ir_imm(o->imm, o->size);
    case XO_MEM:
        if (o->base == X86_RIP) return ir_mem(IR_NOREG, IR_NOREG, 1, (int64_t)o->target, o->size);
        return ir_mem(o->base, o->index, o->scale, o->disp, o->size);
    case XO_REL: return ir_abs(o->target);
    default: lfail(l, "missing operand"); return ir_imm(0, 8);
    }
}

/* Something was written: a pending flag result may no longer be valid. */
static void wrote(L *l, IrOperand d) {
    if (l->flags != FL_RESULT) return;
    if (l->res.kind == IR_O_MEM) { l->flags = FL_NONE; return; }
    if (d.kind == IR_O_REG && d.reg == l->res.reg) l->flags = FL_NONE;
    if (d.kind == IR_O_MEM) return;
}

static void zext32(L *l, IrOperand d) {
    if (d.kind == IR_O_REG && d.width == 4) {
        IrInsn *z = emit(l, IR_ZEXT);
        z->dst = ir_reg(d.reg, 8);
        z->a = d;
    }
}

static IrOp alu_op(X86Opcode op) {
    switch (op) {
    case X86_ADD: return IR_ADD; case X86_SUB: return IR_SUB; case X86_AND: return IR_AND;
    case X86_OR: return IR_OR; case X86_XOR: return IR_XOR; case X86_SHL: return IR_SHL;
    case X86_SHR: return IR_SHR; case X86_SAR: return IR_SAR;
    default: return IR_NOP;
    }
}

static IrCond cond(L *l, int cc) {
    switch (cc) {
    case 2: return IR_CC_ULT; case 3: return IR_CC_UGE; case 4: return IR_CC_EQ; case 5: return IR_CC_NE;
    case 6: return IR_CC_ULE; case 7: return IR_CC_UGT; case 8: return IR_CC_NEG; case 9: return IR_CC_POS;
    case 12: return IR_CC_LT; case 13: return IR_CC_GE; case 14: return IR_CC_LE; case 15: return IR_CC_GT;
    default: lfail(l, "condition j%s is not supported", x86_cc_name(cc)); return IR_CC_EQ;
    }
}

/* Make sure IR flags hold what x86 flags hold for this condition. */
static void need_flags(L *l, IrCond c) {
    if (l->flags == FL_CMP) return;
    if (l->flags == FL_RESULT) {
        if (c != IR_CC_EQ && c != IR_CC_NE && c != IR_CC_NEG && c != IR_CC_POS) {
            lfail(l, "condition needs carry/overflow from an arithmetic result");
            return;
        }
        IrInsn *t = emit(l, IR_TEST);
        t->a = l->res; t->b = l->res;
        l->flags = FL_CMP;
        return;
    }
    lfail(l, "flags are set outside this block or by an unmodeled instruction");
}

static void lift_insn(L *l, const X86Insn *prev, int last_in_block, int bindex) {
    const X86Insn *in = l->in;
    IrOperand d = in->nops > 0 ? conv(l, &in->ops[0]) : ir_imm(0, 8);
    IrOperand s = in->nops > 1 ? conv(l, &in->ops[1]) : ir_imm(0, 8);
    IrInsn *i;
    switch (in->op) {
    case X86_NOP: case X86_ENDBR:
        break;
    case X86_HLT: case X86_UD2:
        emit(l, IR_TRAP);
        break;
    case X86_CMOVCC: {
        IrCond c = cond(l, in->cc);
        need_flags(l, c);
        wrote(l, d);
        i = emit(l, IR_CMOV); i->cc = c; i->dst = d; i->a = s;
        zext32(l, d);
        break;
    }
    case X86_XCHG: {
        if (d.kind == IR_O_REG && s.kind == IR_O_REG) {
            int scratch = 11;
            if (d.reg == 11 || s.reg == 11) scratch = 10;
            if (d.reg == scratch || s.reg == scratch) { lfail(l, "xchg needs a free scratch"); break; }
            wrote(l, d); wrote(l, s);
            i = emit(l, IR_MOV); i->dst = ir_reg(scratch, d.width); i->a = d;
            i = emit(l, IR_MOV); i->dst = d; i->a = s; if (d.width == 4) zext32(l, d);
            i = emit(l, IR_MOV); i->dst = s; i->a = ir_reg(scratch, s.width); if (s.width == 4) zext32(l, s);
        } else if (d.kind == IR_O_MEM && s.kind == IR_O_REG) {
            wrote(l, s);
            i = emit(l, IR_MOV); i->dst = ir_reg(11, s.width); i->a = s;
            i = emit(l, IR_LOAD); i->dst = s; i->a = d; if (s.width == 4) zext32(l, s);
            i = emit(l, IR_STORE); i->dst = d; i->a = ir_reg(11, s.width);
        } else if (d.kind == IR_O_REG && s.kind == IR_O_MEM) {
            wrote(l, d);
            i = emit(l, IR_MOV); i->dst = ir_reg(11, d.width); i->a = d;
            i = emit(l, IR_LOAD); i->dst = d; i->a = s; if (d.width == 4) zext32(l, d);
            i = emit(l, IR_STORE); i->dst = s; i->a = ir_reg(11, d.width);
        } else { lfail(l, "xchg form not supported"); }
        break;
    }
    case X86_LEAVE:
        wrote(l, ir_reg(4, 8)); wrote(l, ir_reg(5, 8));
        i = emit(l, IR_MOV); i->dst = ir_reg(4, 8); i->a = ir_reg(5, 8);
        i = emit(l, IR_POP); i->dst = ir_reg(5, 8);
        break;
    case X86_MOV:
        wrote(l, d);
        i = emit(l, d.kind == IR_O_MEM ? IR_STORE : s.kind == IR_O_MEM ? IR_LOAD : IR_MOV);
        i->dst = d; i->a = s;
        zext32(l, d);
        break;
    case X86_MOVZX: case X86_MOVSX:
        wrote(l, d);
        i = emit(l, in->op == X86_MOVZX ? IR_ZEXT : IR_SEXT);
        i->dst = d; i->a = s;
        zext32(l, d);
        break;
    case X86_LEA:
        wrote(l, d);
        i = emit(l, IR_ADDR);
        i->dst = d; i->a = s; i->a.width = d.width;
        zext32(l, d);
        break;
    case X86_ADD: case X86_SUB: case X86_AND: case X86_OR: case X86_XOR:
    case X86_SHL: case X86_SHR: case X86_SAR:
        /* If a flag-user follows in this block, materialize cmp before add/sub
         * (same flags as the alu) so ja/jg after sub $imm,reg works. */
        if ((in->op == X86_ADD || in->op == X86_SUB) && !last_in_block) {
            const X86Insn *nx = l->in + 1;
            if (nx->op == X86_JCC || nx->op == X86_SETCC || nx->op == X86_CMOVCC) {
                i = emit(l, IR_CMP); i->a = d; i->b = s;
                l->flags = FL_CMP;
            }
        }
        wrote(l, d);
        i = emit(l, alu_op(in->op));
        i->dst = d; i->a = d; i->b = s;
        if (in->op >= X86_SHL && in->op <= X86_SAR && !(s.kind == IR_O_IMM && (s.imm & 63) != 0)) l->flags = FL_NONE;
        else if (l->flags != FL_CMP) { l->flags = FL_RESULT; l->res = d; }
        zext32(l, d);
        break;
    case X86_INC: case X86_DEC:
        wrote(l, d);
        i = emit(l, in->op == X86_INC ? IR_ADD : IR_SUB);
        i->dst = d; i->a = d; i->b = ir_imm(1, d.width);
        l->flags = FL_RESULT; l->res = d;
        zext32(l, d);
        break;
    case X86_NEG: case X86_NOT:
        wrote(l, d);
        i = emit(l, in->op == X86_NEG ? IR_NEG : IR_NOT);
        i->dst = d; i->a = d;
        if (in->op == X86_NEG) { l->flags = FL_RESULT; l->res = d; }
        zext32(l, d);
        break;
    case X86_IMUL:
        wrote(l, d);
        i = emit(l, IR_MUL);
        i->dst = d;
        if (in->nops == 3) { i->a = s; i->b = conv(l, &in->ops[2]); }
        else { i->a = d; i->b = s; }
        l->flags = FL_NONE;
        zext32(l, d);
        break;
    case X86_IDIV: {
        /* The dividend is rdx:rax. Accept in this block:
         *   cqo;  xor edx,edx (+ optional mov edx,edx zext);
         *   or mov rdx,rax ; sar rdx,63  (what CQO lowers to in IR/codegen). */
        int ok = 0, rax_changed = 0;
        const X86Insn *bi = l->cf->insns;
        for (int k = (int)(in - bi) - 1; k >= l->bfirst; k--) {
            const X86Insn *q = &bi[k];
            if (q->op == X86_CQO && q->ops[0].size == 8) { ok = rax_changed ? 0 : 1; break; }
            if (q->op == X86_XOR && q->ops[0].kind == XO_REG && q->ops[1].kind == XO_REG && q->ops[0].reg == 2 && q->ops[1].reg == 2) { ok = 2; break; }
            /* mov edx,edx (any width) is a no-op / zext; keep scanning. */
            if (q->op == X86_MOV && q->nops >= 2 && q->ops[0].kind == XO_REG && q->ops[1].kind == XO_REG
                && q->ops[0].reg == 2 && q->ops[1].reg == 2) continue;
            /* sar rdx, 63 then look for a prior mov rdx, rax (skipping no-ops). */
            if (q->op == X86_SAR && q->nops >= 2 && q->ops[0].kind == XO_REG && q->ops[0].reg == 2
                && q->ops[1].kind == XO_IMM && (q->ops[1].imm & 63) == 63) {
                for (int j = k - 1; j >= l->bfirst; j--) {
                    const X86Insn *m = &bi[j];
                    if (m->op == X86_MOV && m->nops >= 2 && m->ops[0].kind == XO_REG && m->ops[0].reg == 2
                        && m->ops[1].kind == XO_REG && m->ops[1].reg == 0) { ok = rax_changed ? 0 : 1; break; }
                    int wr = m->nops > 0 && m->ops[0].kind == XO_REG ? m->ops[0].reg : -1;
                    if (wr == 2 || wr == 0 || m->op == X86_CALL || m->op == X86_SYSCALL) break;
                }
                break;
            }
            int wr = q->nops > 0 && q->ops[0].kind == XO_REG ? q->ops[0].reg : -1;
            if (wr == 2 || q->op == X86_CALL || q->op == X86_SYSCALL || q->op == X86_IDIV || q->op == X86_DIV || q->op == X86_POP) break;
            if (wr == 0) rax_changed = 1;  /* fine for the xor edx form only */
        }
        if (!ok) { lfail(l, "idiv dividend high half (rdx) not from cqo or xor edx"); break; }
        if (d.width != 8 || (d.kind == IR_O_REG && (d.reg == 0 || d.reg == 2))) { lfail(l, "idiv form not supported"); break; }
        wrote(l, ir_reg(0, 8)); wrote(l, ir_reg(2, 8));
        i = emit(l, IR_REMS); i->dst = ir_reg(2, 8); i->a = ir_reg(0, 8); i->b = d;
        i = emit(l, IR_DIVS); i->dst = ir_reg(0, 8); i->a = ir_reg(0, 8); i->b = d;
        l->flags = FL_NONE;
        break;
    }
    case X86_DIV:
        lfail(l, "unsigned div is not supported");
        break;
    case X86_CQO:
        if (in->ops[0].size != 8) { lfail(l, "cltd/cwtd not supported"); break; }
        wrote(l, ir_reg(2, 8));
        i = emit(l, IR_MOV); i->dst = ir_reg(2, 8); i->a = ir_reg(0, 8);
        i = emit(l, IR_SAR); i->dst = ir_reg(2, 8); i->a = ir_reg(2, 8); i->b = ir_imm(63, 1);
        break;
    case X86_CMP: case X86_TEST:
        i = emit(l, in->op == X86_CMP ? IR_CMP : IR_TEST);
        i->a = d; i->b = s;
        l->flags = FL_CMP;
        break;
    case X86_PUSH:
        if (d.kind == IR_O_IMM) d.width = 8;
        if (d.width != 8) { lfail(l, "16-bit push"); break; }
        wrote(l, ir_reg(4, 8));
        i = emit(l, IR_PUSH); i->a = d;
        break;
    case X86_POP:
        if (d.width != 8) { lfail(l, "16-bit pop"); break; }
        wrote(l, d); wrote(l, ir_reg(4, 8));
        i = emit(l, IR_POP); i->dst = d;
        break;
    case X86_CALL:
        i = emit(l, IR_CALL);
        i->a = d; i->b = ir_imm((int64_t)(in->addr + (uint64_t)in->size), 8);
        l->flags = FL_NONE;
        break;
    case X86_JMP: {
        if (in->ops[0].kind != XO_REL) { emit(l, IR_TRAP); break; }
        int t = cfg_find_block(l->cf, in->ops[0].target);
        if (t < 0) { lfail(l, "jump target not in function"); break; }
        i = emit(l, IR_JMP); i->a = ir_blk(t);
        break;
    }
    case X86_JCC: {
        IrCond c = cond(l, in->cc);
        need_flags(l, c);
        int t = cfg_find_block(l->cf, in->ops[0].target);
        if (t < 0 || !last_in_block || bindex + 1 >= l->cf->nblocks) { lfail(l, "branch shape not supported"); break; }
        i = emit(l, IR_BR); i->cc = c; i->a = ir_blk(t); i->b = ir_blk(bindex + 1);
        break;
    }
    case X86_SETCC: {
        IrCond c = cond(l, in->cc);
        need_flags(l, c);
        i = emit(l, IR_SETCC); i->cc = c; i->dst = d;
        wrote(l, d);
        break;
    }
    case X86_RET:
        i = emit(l, IR_RET);
        if (in->nops) i->a = d;
        break;
    case X86_SYSCALL:
        i = emit(l, IR_SYSCALL);
        l->flags = FL_NONE;
        if (cfg_is_exit(prev, in)) emit(l, IR_TRAP);
        break;
    default:
        lfail(l, "instruction %s is not lifted", x86_op_name(in->op));
    }
}

const char *x86_ir_reg_name(int reg) { return reg >= 0 && reg < 16 ? x86_reg_name(reg, 8, 0) : NULL; }

IrModule *x86_lift(const CfgProgram *p, char *err, size_t errlen) {
    IrModule *m = ir_module_new();
    if (!m) { snprintf(err, errlen, "out of memory"); return NULL; }
    m->reg_name = x86_ir_reg_name;
    for (int fi = 0; fi < p->nfuncs; fi++) {
        const CfgFunc *cf = &p->funcs[fi];
        IrFunc *f = ir_func_add(m, cf->name, cf->addr);
        if (!f) { snprintf(err, errlen, "out of memory"); ir_module_free(m); return NULL; }
        for (int b = 0; b < cf->nblocks; b++)
            if (ir_block_add(f, cf->blocks[b].start) != b) { snprintf(err, errlen, "out of memory"); ir_module_free(m); return NULL; }
        int *out_fl = calloc((size_t)cf->nblocks, sizeof(int));
        if (!out_fl) { snprintf(err, errlen, "out of memory"); ir_module_free(m); return NULL; }
        L l = { f, 0, cf, NULL, FL_NONE, {0}, err, errlen, 0, 0 };
        for (int b = 0; b < cf->nblocks; b++) {
            const CfgBlock *bl = &cf->blocks[b];
            l.block = b;
            l.bfirst = bl->first;
            l.flags = FL_NONE;
            /* Inherit cmp flags from a unique fall-through predecessor that ended in jcc.
             * (cmp; je T; jg U  — the jg block still sees the cmp flags.) */
            int pred = -1, npred = 0;
            for (int p = 0; p < cf->nblocks; p++) {
                const CfgBlock *pb = &cf->blocks[p];
                for (int s = 0; s < pb->nsucc; s++)
                    if (pb->succ[s] == b) { pred = p; npred++; }
            }
            if (npred == 1 && out_fl[pred] == FL_CMP) {
                const CfgBlock *pb = &cf->blocks[pred];
                if (pb->n > 0) {
                    const X86Insn *last = &cf->insns[pb->first + pb->n - 1];
                    if (last->op == X86_JCC && pb->nsucc == 2 && pb->succ[1] == b)
                        l.flags = FL_CMP;
                }
            }
            for (int k = 0; k < bl->n; k++) {
                int idx = bl->first + k;
                l.in = &cf->insns[idx];
                const X86Insn *prev = idx > 0 && cf->insns[idx - 1].addr + (uint64_t)cf->insns[idx - 1].size == l.in->addr ? &cf->insns[idx - 1] : NULL;
                lift_insn(&l, prev, k == bl->n - 1, b);
                if (l.bad) { free(out_fl); ir_module_free(m); return NULL; }
            }
            out_fl[b] = l.flags;
        }
        free(out_fl);
        if (ir_link(f, err, errlen)) { ir_module_free(m); return NULL; }
    }
    return m;
}
