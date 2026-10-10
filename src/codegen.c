#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "codegen.h"

typedef struct {
    CgResult *r;
    int *block_off;     /* offset of each block in the current function */
    int nblock;
    char *err;
    size_t errlen;
    int bad;
} Cg;

static void cgfail(Cg *g, const char *fmt, ...) {
    if (g->bad) return;
    g->bad = 1;
    va_list ap; va_start(ap, fmt); vsnprintf(g->err, g->errlen, fmt, ap); va_end(ap);
}

static void eb(Cg *g, unsigned b) {
    CgResult *r = g->r;
    if (r->len == r->cap) {
        size_t nc = r->cap ? r->cap * 2 : 4096;
        unsigned char *nb = realloc(r->code, nc);
        if (!nb) { cgfail(g, "out of memory"); return; }
        r->code = nb; r->cap = nc;
    }
    r->code[r->len++] = (unsigned char)b;
}
static void e32(Cg *g, uint32_t v) { for (int i = 0; i < 4; i++) eb(g, (v >> (8 * i)) & 255); }
static void e64(Cg *g, uint64_t v) { for (int i = 0; i < 8; i++) eb(g, (v >> (8 * i)) & 255); }

static void reloc(Cg *g, uint64_t target) {
    CgResult *r = g->r;
    if (r->nrelocs == r->rcap) {
        int nc = r->rcap ? r->rcap * 2 : 64;
        CgReloc *nr = realloc(r->relocs, (size_t)nc * sizeof(CgReloc));
        if (!nr) { cgfail(g, "out of memory"); return; }
        r->relocs = nr; r->rcap = nc;
    }
    r->relocs[r->nrelocs].at = (int)r->len;
    r->relocs[r->nrelocs].target = target;
    r->relocs[r->nrelocs].kind = 0;
    r->nrelocs++;
    e32(g, 0);
}

static void rex(Cg *g, int w, int r, int x, int b) {
    unsigned v = 0x40 | (w << 3) | (r << 2) | (x << 1) | b;
    if (v != 0x40) eb(g, v);
}
/* REX that must appear (for spl/bpl/sil/dil byte regs). */
static void rex_force(Cg *g, int w, int r, int x, int b) { eb(g, 0x40 | (w << 3) | (r << 2) | (x << 1) | b); }

static int width_w(int width) { return width == 8; }

/* ModRM for reg-reg: reg field = rreg, rm = mreg. */
static void modrm_rr(Cg *g, int rreg, int mreg) { eb(g, 0xc0 | ((rreg & 7) << 3) | (mreg & 7)); }

/* ModRM+SIB+disp for a memory operand, reg field = rreg. */
static void modrm_mem(Cg *g, int rreg, const IrOperand *mem) {
    int base = mem->base, index = mem->index;
    int64_t disp = mem->disp;
    if (base == IR_NOREG && index == IR_NOREG) {
        /* absolute: [disp32] via SIB with no base, mod 00 */
        eb(g, ((rreg & 7) << 3) | 4);
        eb(g, 0x25);
        e32(g, (uint32_t)disp);
        return;
    }
    int need_sib = (index != IR_NOREG) || ((base & 7) == 4);
    int mod;
    int base_is_bp = base != IR_NOREG && (base & 7) == 5;
    if (disp == 0 && !base_is_bp) mod = 0;
    else if (disp >= -128 && disp <= 127) mod = 1;
    else mod = 2;
    if (base == IR_NOREG) mod = 0;  /* [index*scale + disp32] */
    int rm = need_sib ? 4 : (base & 7);
    eb(g, (mod << 6) | ((rreg & 7) << 3) | rm);
    if (need_sib) {
        int ss = mem->scale == 8 ? 3 : mem->scale == 4 ? 2 : mem->scale == 2 ? 1 : 0;
        int idx = index == IR_NOREG ? 4 : (index & 7);
        int bse = base == IR_NOREG ? 5 : (base & 7);
        eb(g, (ss << 6) | (idx << 3) | bse);
    }
    if (mod == 1) eb(g, (unsigned)(int8_t)disp);
    else if (mod == 2 || base == IR_NOREG) e32(g, (uint32_t)disp);
}

static int hi(int reg) { return (reg >= 8) ? 1 : 0; }

/* Prefix + opcode for an instruction with a reg field (rreg) and an
 * r/m that is either a register or memory. */
static void mem_rex(Cg *g, int width, int rreg, const IrOperand *mem, int force_byte) {
    int x = (mem->index != IR_NOREG) ? hi(mem->index) : 0;
    int b = (mem->base != IR_NOREG) ? hi(mem->base) : 0;
    if (force_byte) rex_force(g, width_w(width), hi(rreg), x, b);
    else rex(g, width_w(width), hi(rreg), x, b);
}

static int byte_needs_rex(int reg) { return reg == 4 || reg == 5 || reg == 6 || reg == 7; }

/* dst = src where both are registers, or a is immediate. Generic mov. */
static void mov_ri(Cg *g, int reg, int width, int64_t imm) {
    if (width == 8) {
        if (imm >= -2147483648LL && imm <= 2147483647LL) {
            rex(g, 1, 0, 0, hi(reg));
            eb(g, 0xc7); modrm_rr(g, 0, reg); e32(g, (uint32_t)imm);
        } else {
            rex(g, 1, 0, 0, hi(reg));
            eb(g, 0xb8 + (reg & 7)); e64(g, (uint64_t)imm);
        }
    } else if (width == 1) {
        if (byte_needs_rex(reg) && reg < 8) rex_force(g, 0, 0, 0, 0);
        else rex(g, 0, 0, 0, hi(reg));
        eb(g, 0xb0 + (reg & 7)); eb(g, (unsigned)(imm & 0xff));
    } else {
        if (width == 2) eb(g, 0x66);
        rex(g, 0, 0, 0, hi(reg));
        eb(g, 0xb8 + (reg & 7)); e32(g, (uint32_t)imm);
    }
}

static void alu_imm(Cg *g, int ext, int reg, int width, int64_t imm);

static void gen_mov(Cg *g, const IrOperand *d, const IrOperand *a) {
    if (d->kind == IR_O_REG && a->kind == IR_O_IMM) { mov_ri(g, d->reg, d->width, a->imm); return; }
    if (d->kind == IR_O_REG && a->kind == IR_O_REG) {
        int w = d->width;
        if (w == 2) eb(g, 0x66);
        if (w == 1 && (byte_needs_rex(d->reg) || byte_needs_rex(a->reg)) && d->reg < 8 && a->reg < 8) rex_force(g, 0, hi(a->reg), 0, hi(d->reg));
        else rex(g, width_w(w), hi(a->reg), 0, hi(d->reg));
        eb(g, w == 1 ? 0x88 : 0x89); modrm_rr(g, a->reg, d->reg);
        return;
    }
    cgfail(g, "unsupported mov form");
}

static void gen_load(Cg *g, const IrOperand *d, const IrOperand *mem) {
    int w = d->width;
    if (w == 2) eb(g, 0x66);
    mem_rex(g, w, d->reg, mem, w == 1 && byte_needs_rex(d->reg) && d->reg < 8);
    eb(g, w == 1 ? 0x8a : 0x8b);
    modrm_mem(g, d->reg, mem);
}
static void gen_store(Cg *g, const IrOperand *mem, const IrOperand *a) {
    int w = mem->width;
    if (a->kind == IR_O_IMM) {
        if (w == 2) eb(g, 0x66);
        mem_rex(g, w, 0, mem, 0);
        eb(g, w == 1 ? 0xc6 : 0xc7);
        modrm_mem(g, 0, mem);
        if (w == 1) eb(g, (unsigned)(a->imm & 0xff));
        else if (w == 2) { eb(g, a->imm & 255); eb(g, (a->imm >> 8) & 255); }
        else e32(g, (uint32_t)a->imm);
        return;
    }
    if (a->kind != IR_O_REG) { cgfail(g, "store source must be reg or imm"); return; }
    if (w == 2) eb(g, 0x66);
    mem_rex(g, w, a->reg, mem, w == 1 && byte_needs_rex(a->reg) && a->reg < 8);
    eb(g, w == 1 ? 0x88 : 0x89);
    modrm_mem(g, a->reg, mem);
}

static void gen_lea(Cg *g, const IrOperand *d, const IrOperand *mem) {
    rex(g, width_w(d->width == 8 ? 8 : 8), hi(d->reg), mem->index != IR_NOREG ? hi(mem->index) : 0, mem->base != IR_NOREG && mem->base != IR_PC ? hi(mem->base) : 0);
    eb(g, 0x8d);
    IrOperand mm = *mem;
    if (mm.base == IR_PC) { cgfail(g, "pc-relative lea not supported in recompile"); return; }
    modrm_mem(g, d->reg, &mm);
}

/* ALU reg,reg with opcode base (op 0x01 add etc). */
static void gen_alu_rr(Cg *g, int op, const IrOperand *d, const IrOperand *s) {
    int w = d->width;
    if (w == 2) eb(g, 0x66);
    if (w == 1 && (byte_needs_rex(d->reg) || byte_needs_rex(s->reg)) && d->reg < 8 && s->reg < 8) rex_force(g, 0, hi(s->reg), 0, hi(d->reg));
    else rex(g, width_w(w), hi(s->reg), 0, hi(d->reg));
    eb(g, w == 1 ? op : op | 1);
    modrm_rr(g, s->reg, d->reg);
}

/* /ext group-1 immediate on a register. */
static void alu_imm(Cg *g, int ext, int reg, int width, int64_t imm) {
    if (width == 2) eb(g, 0x66);
    rex(g, width_w(width), 0, 0, hi(reg));
    if (width != 1 && imm >= -128 && imm <= 127) { eb(g, 0x83); modrm_rr(g, ext, reg); eb(g, (unsigned)(int8_t)imm); }
    else if (width == 1) { eb(g, 0x80); modrm_rr(g, ext, reg); eb(g, (unsigned)(imm & 0xff)); }
    else { eb(g, 0x81); modrm_rr(g, ext, reg); e32(g, (uint32_t)imm); }
}

static int alu_ext(IrOp op) {
    switch (op) { case IR_ADD: return 0; case IR_OR: return 1; case IR_AND: return 4; case IR_SUB: return 5; case IR_XOR: return 6; default: return -1; }
}
static int alu_base(IrOp op) {
    switch (op) { case IR_ADD: return 0x00; case IR_OR: return 0x08; case IR_AND: return 0x20; case IR_SUB: return 0x28; case IR_XOR: return 0x30; default: return -1; }
}

static void gen_arith(Cg *g, const IrInsn *in) {
    const IrOperand *d = &in->dst, *a = &in->a, *b = &in->b;
    if (!(d->kind == IR_O_REG && a->kind == IR_O_REG && d->reg == a->reg)) { cgfail(g, "arith expects dst==a register"); return; }
    if (b->kind == IR_O_REG) gen_alu_rr(g, alu_base(in->op), d, b);
    else if (b->kind == IR_O_IMM) alu_imm(g, alu_ext(in->op), d->reg, d->width, b->imm);
    else cgfail(g, "arith operand");
}

static void gen_shift(Cg *g, const IrInsn *in) {
    const IrOperand *d = &in->dst, *b = &in->b;
    int ext = in->op == IR_SHL ? 4 : in->op == IR_SHR ? 5 : 7;
    int w = d->width;
    if (w < 4) { cgfail(g, "8/16-bit shifts not supported"); return; }
    if (b->kind == IR_O_IMM) {
        rex(g, width_w(w), 0, 0, hi(d->reg));
        if (b->imm == 1) { eb(g, 0xd1); modrm_rr(g, ext, d->reg); }
        else { eb(g, 0xc1); modrm_rr(g, ext, d->reg); eb(g, (unsigned)(b->imm & 63)); }
    } else if (b->kind == IR_O_REG && b->reg == 1) {
        rex(g, width_w(w), 0, 0, hi(d->reg));
        eb(g, 0xd3); modrm_rr(g, ext, d->reg);
    } else cgfail(g, "shift count must be imm or cl");
}

static int cc_x86(IrCond c) {
    switch (c) {
    case IR_CC_EQ: return 4; case IR_CC_NE: return 5; case IR_CC_LT: return 12; case IR_CC_GE: return 13;
    case IR_CC_LE: return 14; case IR_CC_GT: return 15; case IR_CC_ULT: return 2; case IR_CC_UGE: return 3;
    case IR_CC_ULE: return 6; case IR_CC_UGT: return 7; case IR_CC_NEG: return 8; case IR_CC_POS: return 9;
    default: return -1;
    }
}

static void gen_block(Cg *g, IrFunc *f, int bi) {
    IrBlock *bl = &f->blocks[bi];
    for (int k = 0; k < bl->ninsns; k++) {
        if (g->bad) return;
        const IrInsn *in = &bl->insns[k];
        switch (in->op) {
        case IR_NOP: break;
        case IR_MOV: gen_mov(g, &in->dst, &in->a); break;
        case IR_LOAD: gen_load(g, &in->dst, &in->a); break;
        case IR_STORE: gen_store(g, &in->dst, &in->a); break;
        case IR_ADDR: gen_lea(g, &in->dst, &in->a); break;
        case IR_ADD: case IR_SUB: case IR_AND: case IR_OR: case IR_XOR: gen_arith(g, in); break;
        case IR_SHL: case IR_SHR: case IR_SAR: gen_shift(g, in); break;
        case IR_MUL: {
            const IrOperand *d = &in->dst;
            if (in->b.kind == IR_O_IMM) {
                rex(g, width_w(d->width), hi(d->reg), 0, hi(in->a.kind == IR_O_REG ? in->a.reg : d->reg));
                int sr = in->a.kind == IR_O_REG ? in->a.reg : d->reg;
                if (in->b.imm >= -128 && in->b.imm <= 127) { eb(g, 0x6b); modrm_rr(g, d->reg, sr); eb(g, (unsigned)(int8_t)in->b.imm); }
                else { eb(g, 0x69); modrm_rr(g, d->reg, sr); e32(g, (uint32_t)in->b.imm); }
            } else if (in->b.kind == IR_O_REG) {
                rex(g, width_w(d->width), hi(d->reg), 0, hi(in->b.reg));
                eb(g, 0x0f); eb(g, 0xaf); modrm_rr(g, d->reg, in->b.reg);
            } else cgfail(g, "imul operand");
            break;
        }
        case IR_DIVS: case IR_REMS: {
            /* lifter already emitted cqo via MOV/SAR; just idiv b */
            const IrOperand *b = &in->b;
            if (b->kind != IR_O_REG) { cgfail(g, "divisor must be a register"); break; }
            if (in->op == IR_DIVS && !(k > 0 && bl->insns[k - 1].op == IR_REMS)) { cgfail(g, "divs without paired rems"); break; }
            if (in->op == IR_REMS) { /* rem then div share one idiv; emit idiv only on REMS, DIVS is a no-op copy */
                rex(g, 1, 0, 0, hi(b->reg)); eb(g, 0xf7); modrm_rr(g, 7, b->reg);
            }
            break;
        }
        case IR_NEG: rex(g, width_w(in->dst.width), 0, 0, hi(in->dst.reg)); eb(g, 0xf7); modrm_rr(g, 3, in->dst.reg); break;
        case IR_NOT: rex(g, width_w(in->dst.width), 0, 0, hi(in->dst.reg)); eb(g, 0xf7); modrm_rr(g, 2, in->dst.reg); break;
        case IR_ZEXT:
            if (in->a.kind == IR_O_REG && in->a.width == 4) { rex(g, 0, hi(in->dst.reg), 0, hi(in->a.reg)); eb(g, 0x89); modrm_rr(g, in->a.reg, in->dst.reg); }
            else if (in->a.kind == IR_O_REG && in->a.width == 1) { rex(g, width_w(in->dst.width), hi(in->dst.reg), 0, hi(in->a.reg)); eb(g, 0x0f); eb(g, 0xb6); modrm_rr(g, in->dst.reg, in->a.reg); }
            else if (in->a.kind == IR_O_REG && in->a.width == 2) { rex(g, width_w(in->dst.width), hi(in->dst.reg), 0, hi(in->a.reg)); eb(g, 0x0f); eb(g, 0xb7); modrm_rr(g, in->dst.reg, in->a.reg); }
            else if (in->a.kind == IR_O_MEM) { int w=in->a.width; mem_rex(g,8,in->dst.reg,&in->a,0); eb(g,0x0f); eb(g, w==1?0xb6:0xb7); modrm_mem(g,in->dst.reg,&in->a); }
            else cgfail(g, "zext form");
            break;
        case IR_SEXT:
            if (in->a.kind == IR_O_REG) { int w=in->a.width; rex(g, width_w(in->dst.width), hi(in->dst.reg), 0, hi(in->a.reg)); eb(g,0x0f); eb(g, w==1?0xbe:0xbf); modrm_rr(g, in->dst.reg, in->a.reg); }
            else if (in->a.kind == IR_O_MEM) { int w=in->a.width; mem_rex(g,8,in->dst.reg,&in->a,0); eb(g,0x0f); eb(g, w==1?0xbe:0xbf); modrm_mem(g,in->dst.reg,&in->a); }
            else cgfail(g, "sext form");
            break;
        case IR_CMP: case IR_TEST: {
            const IrOperand *a = &in->a, *b = &in->b;
            int op = in->op == IR_CMP ? 0x38 : 0x84;
            if (a->kind == IR_O_REG && b->kind == IR_O_REG) {
                int w = a->width;
                if (w == 2) eb(g, 0x66);
                if (w==1 && (byte_needs_rex(a->reg)||byte_needs_rex(b->reg)) && a->reg<8 && b->reg<8) rex_force(g,0,hi(b->reg),0,hi(a->reg));
                else rex(g, width_w(w), hi(b->reg), 0, hi(a->reg));
                eb(g, w == 1 ? op : op | 1); modrm_rr(g, b->reg, a->reg);
            } else if (in->op == IR_CMP && a->kind == IR_O_REG && b->kind == IR_O_IMM) {
                alu_imm(g, 7, a->reg, a->width, b->imm);
            } else if (in->op == IR_TEST && a->kind == IR_O_REG && b->kind == IR_O_IMM) {
                int w = a->width; if (w==2) eb(g,0x66); rex(g, width_w(w), 0, 0, hi(a->reg));
                eb(g, w==1?0xf6:0xf7); modrm_rr(g, 0, a->reg);
                if (w==1) eb(g, b->imm & 255); else if (w==2){eb(g,b->imm&255);eb(g,(b->imm>>8)&255);} else e32(g,(uint32_t)b->imm);
            } else if (a->kind == IR_O_MEM) {
                int w = a->width;
                if (in->op==IR_CMP && b->kind==IR_O_IMM){ if(w==2)eb(g,0x66); mem_rex(g,w,0,a,0); eb(g, w==1?0x80:0x81); modrm_mem(g,7,a); if(w==1)eb(g,b->imm&255); else if(w==2){eb(g,b->imm&255);eb(g,(b->imm>>8)&255);} else e32(g,(uint32_t)b->imm); }
                else cgfail(g, "cmp/test mem form");
            } else cgfail(g, "cmp/test form");
            break;
        }
        case IR_SETCC: {
            int cc = cc_x86(in->cc);
            if (byte_needs_rex(in->dst.reg) && in->dst.reg < 8) rex_force(g, 0, 0, 0, 0);
            else if (hi(in->dst.reg)) rex(g, 0, 0, 0, 1);
            eb(g, 0x0f); eb(g, 0x90 | cc); modrm_rr(g, 0, in->dst.reg);
            break;
        }
        case IR_CMOV: {
            int cc = cc_x86(in->cc);
            if (in->dst.kind != IR_O_REG || in->a.kind != IR_O_REG) { cgfail(g, "cmov form"); break; }
            int w = in->dst.width;
            if (w != 4 && w != 8) { cgfail(g, "cmov width"); break; }
            rex(g, w == 8, hi(in->dst.reg), 0, hi(in->a.reg));
            eb(g, 0x0f); eb(g, 0x40 | cc);
            modrm_rr(g, in->dst.reg, in->a.reg);
            break;
        }
        case IR_PUSH:
            if (in->a.kind == IR_O_REG) { if (hi(in->a.reg)) eb(g, 0x41); eb(g, 0x50 + (in->a.reg & 7)); }
            else if (in->a.kind == IR_O_IMM) {
                if (in->a.imm >= -128 && in->a.imm <= 127) { eb(g, 0x6a); eb(g, (unsigned)(int8_t)in->a.imm); }
                else { eb(g, 0x68); e32(g, (uint32_t)in->a.imm); }
            } else cgfail(g, "push form");
            break;
        case IR_POP:
            if (in->dst.kind == IR_O_REG) { if (hi(in->dst.reg)) eb(g, 0x41); eb(g, 0x58 + (in->dst.reg & 7)); }
            else cgfail(g, "pop form");
            break;
        case IR_CALL:
            if (in->a.kind == IR_O_ADDR) { eb(g, 0xe8); reloc(g, in->a.addr); }
            else if (in->a.kind == IR_O_REG) { if (hi(in->a.reg)) eb(g, 0x41); eb(g, 0xff); modrm_rr(g, 2, in->a.reg); }
            else cgfail(g, "indirect call target");
            break;
        case IR_RET: eb(g, 0xc3); break;
        case IR_SYSCALL: eb(g, 0x0f); eb(g, 0x05); break;
        case IR_TRAP: break;
        case IR_JMP: {
            int t = in->a.block;
            eb(g, 0xe9);
            int at = (int)g->r->len;
            e32(g, 0);
            /* record local fixup */
            {
                CgResult *r = g->r;
                if (r->nrelocs == r->rcap) { int nc=r->rcap?r->rcap*2:64; CgReloc*nr=realloc(r->relocs,(size_t)nc*sizeof(CgReloc)); if(!nr){cgfail(g,"oom");break;} r->relocs=nr; r->rcap=nc; }
                r->relocs[r->nrelocs].at = at;
                r->relocs[r->nrelocs].target = 0;
                r->relocs[r->nrelocs].kind = 100 + t;  /* local block target */
                r->nrelocs++;
            }
            break;
        }
        case IR_BR: {
            int cc = cc_x86(in->cc);
            eb(g, 0x0f); eb(g, 0x80 | cc);
            int at = (int)g->r->len; e32(g, 0);
            CgResult *r = g->r;
            if (r->nrelocs == r->rcap) { int nc=r->rcap?r->rcap*2:64; CgReloc*nr=realloc(r->relocs,(size_t)nc*sizeof(CgReloc)); if(!nr){cgfail(g,"oom");break;} r->relocs=nr; r->rcap=nc; }
            r->relocs[r->nrelocs].at = at; r->relocs[r->nrelocs].target = 0; r->relocs[r->nrelocs].kind = 100 + in->a.block; r->nrelocs++;
            /* fall-through to in->b.block is the next block; verify */
            if (in->b.block != bi + 1) {
                eb(g, 0xe9); int at2 = (int)g->r->len; e32(g, 0);
                if (r->nrelocs == r->rcap) { int nc=r->rcap?r->rcap*2:64; CgReloc*nr=realloc(r->relocs,(size_t)nc*sizeof(CgReloc)); if(!nr){cgfail(g,"oom");break;} r->relocs=nr; r->rcap=nc; }
                r->relocs[r->nrelocs].at = at2; r->relocs[r->nrelocs].target = 0; r->relocs[r->nrelocs].kind = 100 + in->b.block; r->nrelocs++;
            }
            break;
        }
        default: cgfail(g, "cannot encode IR op %s", ir_op_name(in->op));
        }
    }
}

int cg_emit_module(IrModule *m, CgResult *out, char *err, size_t errlen) {
    memset(out, 0, sizeof(*out));
    out->m = m;
    out->nfunc = m->nfuncs;
    out->func_off = calloc((size_t)(m->nfuncs ? m->nfuncs : 1), sizeof(uint64_t));
    if (!out->func_off) { snprintf(err, errlen, "out of memory"); return -1; }
    Cg g = { out, NULL, 0, err, errlen, 0 };
    for (int fi = 0; fi < m->nfuncs; fi++) {
        IrFunc *f = &m->funcs[fi];
        out->func_off[fi] = out->len;
        int *boff = calloc((size_t)(f->nblocks ? f->nblocks : 1), sizeof(int));
        if (!boff) { snprintf(err, errlen, "out of memory"); cg_free(out); return -1; }
        /* Local block fixups are stored with kind 100+blockid and a function-relative 'at'.
         * We resolve them per function after emitting all its blocks. */
        int first_reloc = out->nrelocs;
        g.block_off = boff; g.nblock = 0;
        for (int b = 0; b < f->nblocks; b++) {
            boff[b] = (int)out->len;
            gen_block(&g, f, b);
            if (g.bad) { free(boff); cg_free(out); return -1; }
        }
        /* resolve local block relocs for this function */
        for (int ri = first_reloc; ri < out->nrelocs; ri++) {
            if (out->relocs[ri].kind >= 100) {
                int tb = out->relocs[ri].kind - 100;
                int32_t v = boff[tb] - (out->relocs[ri].at + 4);
                memcpy(out->code + out->relocs[ri].at, &v, 4);
                /* mark consumed */
                out->relocs[ri].kind = -1;
            }
        }
        free(boff);
    }
    /* Compact away consumed local relocs; keep call relocs (kind 0). */
    int w = 0;
    for (int i = 0; i < out->nrelocs; i++) if (out->relocs[i].kind == 0) out->relocs[w++] = out->relocs[i];
    out->nrelocs = w;
    return 0;
}

void cg_free(CgResult *r) {
    free(r->code); free(r->func_off); free(r->relocs);
    memset(r, 0, sizeof(*r));
}
