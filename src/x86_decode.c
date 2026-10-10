#include <stdio.h>
#include <string.h>
#include "x86_decode.h"

typedef struct {
    const unsigned char *p;
    size_t n, i;
    int bad;
} Rd;

static unsigned get8(Rd *r) {
    if (r->i >= r->n) { r->bad = 1; return 0; }
    return r->p[r->i++];
}
static int64_t gets8(Rd *r) { return (int8_t)get8(r); }
static int64_t gets16(Rd *r) { unsigned a = get8(r), b = get8(r); return (int16_t)(a | b << 8); }
static int64_t gets32(Rd *r) {
    uint32_t v = 0;
    for (int k = 0; k < 4; k++) v |= (uint32_t)get8(r) << (8 * k);
    return (int32_t)v;
}
static int64_t get64(Rd *r) {
    uint64_t v = 0;
    for (int k = 0; k < 8; k++) v |= (uint64_t)get8(r) << (8 * k);
    return (int64_t)v;
}

typedef struct {
    int rex, w, r, x, b, opsz;
    int mod, reg, rm;
} Ctx;

static X86Operand reg_op(Ctx *c, int reg, int size) {
    X86Operand o = {0};
    o.kind = XO_REG; o.reg = reg; o.size = size; o.base = o.index = X86_NOREG;
    if (size == 1 && !c->rex && reg >= 4 && reg < 8) { o.high8 = 1; o.reg = reg - 4; }
    return o;
}
static X86Operand imm_op(int64_t v, int size) {
    X86Operand o = {0};
    o.kind = XO_IMM; o.imm = v; o.size = size; o.base = o.index = X86_NOREG;
    return o;
}

/* Reads ModRM (+SIB, disp). Returns the r/m operand. */
static X86Operand modrm(Rd *r, Ctx *c, int size) {
    unsigned m = get8(r);
    c->mod = m >> 6;
    c->reg = ((m >> 3) & 7) | (c->r << 3);
    c->rm = m & 7;
    if (c->mod == 3) return reg_op(c, c->rm | (c->b << 3), size);
    X86Operand o = {0};
    o.kind = XO_MEM; o.size = size; o.scale = 1; o.index = X86_NOREG;
    if (c->rm == 4) {
        unsigned s = get8(r);
        int idx = ((s >> 3) & 7) | (c->x << 3);
        o.scale = 1 << (s >> 6);
        o.index = idx == 4 ? X86_NOREG : idx;
        if (o.index == X86_NOREG) o.scale = 1;
        if ((s & 7) == 5 && c->mod == 0) { o.base = X86_NOREG; o.disp = gets32(r); return o; }
        o.base = (s & 7) | (c->b << 3);
    } else if (c->rm == 5 && c->mod == 0) {
        o.base = X86_RIP; o.disp = gets32(r); return o;
    } else {
        o.base = c->rm | (c->b << 3);
    }
    if (c->mod == 1) o.disp = gets8(r);
    else if (c->mod == 2) o.disp = gets32(r);
    return o;
}

static int64_t immz(Rd *r, Ctx *c) { return c->opsz == 2 ? gets16(r) : gets32(r); }

static void set2(X86Insn *in, X86Opcode op, X86Operand a, X86Operand b) {
    in->op = op; in->nops = 2; in->ops[0] = a; in->ops[1] = b;
}
static void set1(X86Insn *in, X86Opcode op, X86Operand a) { in->op = op; in->nops = 1; in->ops[0] = a; }

static X86Operand rel_op(int64_t d) {
    X86Operand o = {0};
    o.kind = XO_REL; o.disp = d; o.size = 8; o.base = o.index = X86_NOREG;
    return o;
}

static const X86Opcode alu[8] = { X86_ADD, X86_OR, X86_BAD, X86_BAD, X86_AND, X86_SUB, X86_XOR, X86_CMP };
static const X86Opcode shf[8] = { X86_BAD, X86_BAD, X86_BAD, X86_BAD, X86_SHL, X86_SHR, X86_SHL, X86_SAR };

int x86_decode(const unsigned char *p, size_t avail, uint64_t addr, X86Insn *out) {
    memset(out, 0, sizeof(*out));
    out->addr = addr;
    Rd r = { p, avail < 15 ? avail : 15, 0, 0 };
    Ctx c = {0};
    int f3 = 0, f2 = 0, o66 = 0, seg = 0;
    unsigned b;
    for (;;) {
        b = get8(&r);
        if (r.bad) return 0;
        if (b == 0x66) { o66 = 1; continue; }
        if (b == 0xf3) { f3 = 1; continue; }
        if (b == 0xf2) { f2 = 1; continue; }
        if (b == 0x2e || b == 0x3e) { seg = 1; continue; }  /* only legal before a nop */
        break;
    }
    if (b >= 0x40 && b <= 0x4f) {
        c.rex = 1; c.w = (b >> 3) & 1; c.r = (b >> 2) & 1; c.x = (b >> 1) & 1; c.b = b & 1;
        b = get8(&r);
    }
    c.opsz = c.w ? 8 : o66 ? 2 : 4;
    int v = c.opsz;
    X86Operand e, g;

    if (f2 || (f3 && b != 0x90 && b != 0xc3 && b != 0x0f)) goto bad;
    if (f3 && b == 0x0f) {
        /* endbr64 f3 0f 1e fa, endbr32 f3 0f 1e fb; nothing else with f3 0f. */
        unsigned b2 = get8(&r), b3 = get8(&r);
        if (r.bad || c.rex || o66 || seg || b2 != 0x1e || (b3 != 0xfa && b3 != 0xfb)) goto bad;
        out->op = X86_ENDBR; out->cc = b3 == 0xfa ? 64 : 32;
        out->size = (int)r.i;
        return out->size;
    }

    if (b < 0x40 && (b & 7) < 6) {
        X86Opcode op = alu[b >> 3];
        if (op == X86_BAD) goto bad;
        switch (b & 7) {
        case 0: e = modrm(&r, &c, 1); set2(out, op, e, reg_op(&c, c.reg, 1)); break;
        case 1: e = modrm(&r, &c, v); set2(out, op, e, reg_op(&c, c.reg, v)); break;
        case 2: e = modrm(&r, &c, 1); set2(out, op, reg_op(&c, c.reg, 1), e); break;
        case 3: e = modrm(&r, &c, v); set2(out, op, reg_op(&c, c.reg, v), e); break;
        case 4: set2(out, op, reg_op(&c, 0, 1), imm_op(gets8(&r), 1)); break;
        case 5: set2(out, op, reg_op(&c, 0, v), imm_op(immz(&r, &c), v)); break;
        }
    } else if (b >= 0x50 && b <= 0x57) {
        set1(out, X86_PUSH, reg_op(&c, (b & 7) | (c.b << 3), o66 ? 2 : 8));
    } else if (b >= 0x58 && b <= 0x5f) {
        set1(out, X86_POP, reg_op(&c, (b & 7) | (c.b << 3), o66 ? 2 : 8));
    } else if (b == 0x68) {
        set1(out, X86_PUSH, imm_op(gets32(&r), 8));
    } else if (b == 0x6a) {
        set1(out, X86_PUSH, imm_op(gets8(&r), 8));
    } else if (b == 0x69 || b == 0x6b) {
        e = modrm(&r, &c, v);
        int64_t im = b == 0x6b ? gets8(&r) : immz(&r, &c);
        out->op = X86_IMUL; out->nops = 3;
        out->ops[0] = reg_op(&c, c.reg, v); out->ops[1] = e; out->ops[2] = imm_op(im, v);
    } else if (b >= 0x70 && b <= 0x7f) {
        out->cc = b & 15; set1(out, X86_JCC, rel_op(gets8(&r)));
    } else if (b == 0x80 || b == 0x81 || b == 0x83) {
        int sz = b == 0x80 ? 1 : v;
        e = modrm(&r, &c, sz);
        X86Opcode op = alu[c.reg & 7];
        if (op == X86_BAD) goto bad;
        int64_t im = b == 0x81 ? immz(&r, &c) : gets8(&r);
        set2(out, op, e, imm_op(im, sz));
    } else if (b == 0x84 || b == 0x85) {
        int sz = b == 0x84 ? 1 : v;
        e = modrm(&r, &c, sz); set2(out, X86_TEST, e, reg_op(&c, c.reg, sz));
    } else if (b >= 0x88 && b <= 0x8b) {
        int sz = (b & 1) ? v : 1;
        e = modrm(&r, &c, sz);
        g = reg_op(&c, c.reg, sz);
        if (b & 2) set2(out, X86_MOV, g, e); else set2(out, X86_MOV, e, g);
    } else if (b == 0x8d) {
        e = modrm(&r, &c, v);
        if (e.kind != XO_MEM) goto bad;
        set2(out, X86_LEA, reg_op(&c, c.reg, v), e);
    } else if (b == 0x8f) {
        e = modrm(&r, &c, 8);
        if ((c.reg & 7) != 0) goto bad;
        set1(out, X86_POP, e);
    } else if (b == 0x63) {
        /* movsxd r64, r/m32 (REX.W) or movsxd r32, r/m32 */
        e = modrm(&r, &c, 4);
        set2(out, X86_MOVSX, reg_op(&c, c.reg, v), e);
    } else if (b == 0x86 || b == 0x87) {
        int sz = b == 0x86 ? 1 : v;
        e = modrm(&r, &c, sz);
        set2(out, X86_XCHG, e, reg_op(&c, c.reg, sz));
    } else if (b >= 0x90 && b <= 0x97) {
        if (b == 0x90 && !c.b) { out->op = X86_NOP; }
        else {
            int r8 = (b & 7) | (c.b << 3);
            set2(out, X86_XCHG, reg_op(&c, 0, v), reg_op(&c, r8, v));
        }
    } else if (b == 0x98) {
        /* cwde (eax<-ax) or cdqe (rax<-eax) with REX.W */
        int src_sz = c.w ? 4 : 2;
        int dst_sz = c.w ? 8 : 4;
        set2(out, X86_MOVSX, reg_op(&c, 0, dst_sz), reg_op(&c, 0, src_sz));
    } else if (b == 0x99) {
        out->op = X86_CQO; out->ops[0].size = v;
    } else if (b == 0xa8) {
        set2(out, X86_TEST, reg_op(&c, 0, 1), imm_op(gets8(&r), 1));
    } else if (b == 0xa9) {
        set2(out, X86_TEST, reg_op(&c, 0, v), imm_op(immz(&r, &c), v));
    } else if (b >= 0xb0 && b <= 0xb7) {
        set2(out, X86_MOV, reg_op(&c, (b & 7) | (c.b << 3), 1), imm_op(gets8(&r), 1));
    } else if (b >= 0xb8 && b <= 0xbf) {
        int64_t im = c.w ? get64(&r) : c.opsz == 2 ? gets16(&r) : (int64_t)(uint32_t)gets32(&r);
        set2(out, X86_MOV, reg_op(&c, (b & 7) | (c.b << 3), v), imm_op(im, v));
    } else if (b == 0xc0 || b == 0xc1 || (b >= 0xd0 && b <= 0xd3)) {
        int sz = (b & 1) ? v : 1;
        e = modrm(&r, &c, sz);
        X86Opcode op = shf[c.reg & 7];
        if (op == X86_BAD) goto bad;
        X86Operand cnt;
        if (b <= 0xc1) cnt = imm_op((int64_t)(get8(&r)), 1);
        else if (b <= 0xd1) cnt = imm_op(1, 1);
        else { Ctx z = {0}; cnt = reg_op(&z, 1, 1); }
        set2(out, op, e, cnt);
    } else if (b == 0xc9) {
        out->op = X86_LEAVE;
    } else if (b == 0xf4) {
        out->op = X86_HLT;
    } else if (b == 0xc3) {
        out->op = X86_RET;
    } else if (b == 0xc2) {
        set1(out, X86_RET, imm_op((uint16_t)gets16(&r), 2));
    } else if (b == 0xc6 || b == 0xc7) {
        int sz = b == 0xc6 ? 1 : v;
        e = modrm(&r, &c, sz);
        if ((c.reg & 7) != 0) goto bad;
        set2(out, X86_MOV, e, imm_op(b == 0xc6 ? gets8(&r) : immz(&r, &c), sz));
    } else if (b == 0xe8) {
        set1(out, X86_CALL, rel_op(gets32(&r)));
    } else if (b == 0xe9) {
        set1(out, X86_JMP, rel_op(gets32(&r)));
    } else if (b == 0xeb) {
        set1(out, X86_JMP, rel_op(gets8(&r)));
    } else if (b == 0xf6 || b == 0xf7) {
        int sz = b == 0xf6 ? 1 : v;
        e = modrm(&r, &c, sz);
        switch (c.reg & 7) {
        case 0: set2(out, X86_TEST, e, imm_op(sz == 1 ? gets8(&r) : immz(&r, &c), sz)); break;
        case 2: set1(out, X86_NOT, e); break;
        case 3: set1(out, X86_NEG, e); break;
        case 6: set1(out, X86_DIV, e); break;
        case 7: set1(out, X86_IDIV, e); break;
        default: goto bad;
        }
    } else if (b == 0xfe || b == 0xff) {
        int sz = b == 0xfe ? 1 : v;
        unsigned peek = r.i < r.n ? r.p[r.i] : 0;
        int sub = (peek >> 3) & 7;
        if (b == 0xff && (sub == 2 || sub == 4 || sub == 6)) sz = 8;
        e = modrm(&r, &c, sz);
        switch (c.reg & 7) {
        case 0: set1(out, X86_INC, e); break;
        case 1: set1(out, X86_DEC, e); break;
        case 2: if (b == 0xfe) goto bad; set1(out, X86_CALL, e); break;
        case 4: if (b == 0xfe) goto bad; set1(out, X86_JMP, e); break;
        case 6: if (b == 0xfe) goto bad; set1(out, X86_PUSH, e); break;
        default: goto bad;
        }
    } else if (b == 0x0f) {
        unsigned b2 = get8(&r);
        if (b2 == 0x05) out->op = X86_SYSCALL;
        else if (b2 == 0x0b) out->op = X86_UD2;
        else if (b2 >= 0x40 && b2 <= 0x4f) {
            out->cc = b2 & 15;
            e = modrm(&r, &c, v);
            set2(out, X86_CMOVCC, reg_op(&c, c.reg, v), e);
        } else if (b2 == 0x1f) {
            e = modrm(&r, &c, v);
            if ((c.reg & 7) != 0) goto bad;
            out->op = X86_NOP;
        } else if (b2 >= 0x80 && b2 <= 0x8f) {
            out->cc = b2 & 15; set1(out, X86_JCC, rel_op(gets32(&r)));
        } else if (b2 >= 0x90 && b2 <= 0x9f) {
            out->cc = b2 & 15; e = modrm(&r, &c, 1); set1(out, X86_SETCC, e);
        } else if (b2 == 0xaf) {
            e = modrm(&r, &c, v); set2(out, X86_IMUL, reg_op(&c, c.reg, v), e);
        } else if (b2 == 0xb6 || b2 == 0xb7 || b2 == 0xbe || b2 == 0xbf) {
            e = modrm(&r, &c, (b2 & 1) ? 2 : 1);
            set2(out, b2 < 0xbe ? X86_MOVZX : X86_MOVSX, reg_op(&c, c.reg, v), e);
        } else goto bad;
    } else {
        goto bad;
    }
    if (r.bad) goto bad;
    if (f3 && out->op != X86_NOP && out->op != X86_RET) goto bad;
    if (seg && out->op != X86_NOP) goto bad;
    out->size = (int)r.i;
    for (int k = 0; k < out->nops; k++) {
        X86Operand *o = &out->ops[k];
        if (o->kind == XO_REL) o->target = addr + (uint64_t)out->size + (uint64_t)o->disp;
        if (o->kind == XO_MEM && o->base == X86_RIP) o->target = addr + (uint64_t)out->size + (uint64_t)o->disp;
    }
    return out->size;
bad:
    memset(out, 0, sizeof(*out));
    out->addr = addr;
    out->op = X86_BAD;
    return 0;
}

static const char *r64[16] = { "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15" };
static const char *r32[16] = { "eax","ecx","edx","ebx","esp","ebp","esi","edi","r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d" };
static const char *r16[16] = { "ax","cx","dx","bx","sp","bp","si","di","r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w" };
static const char *r8[16] = { "al","cl","dl","bl","spl","bpl","sil","dil","r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b" };
static const char *r8h[4] = { "ah","ch","dh","bh" };

const char *x86_reg_name(int reg, int size, int high8) {
    if (reg == X86_RIP) return "rip";
    if (reg < 0 || reg > 15) return "?";
    if (size == 1) return high8 && reg < 4 ? r8h[reg] : r8[reg];
    if (size == 2) return r16[reg];
    if (size == 4) return r32[reg];
    return r64[reg];
}

static const char *names[X86_OP_COUNT] = {
    "(bad)", "mov", "movz", "movs", "push", "pop", "lea",
    "add", "sub", "imul", "idiv", "div",
    "and", "or", "xor", "shl", "shr", "sar",
    "cmp", "test", "inc", "dec", "neg", "not",
    "jmp", "j", "set", "call", "ret",
    "nop", "cqo", "syscall", "endbr64", "leave", "hlt", "ud2", "cmov", "xchg",
};
static const char *ccs[16] = { "o","no","b","ae","e","ne","be","a","s","ns","p","np","l","ge","le","g" };

const char *x86_op_name(X86Opcode op) { return op >= 0 && op < X86_OP_COUNT ? names[op] : "?"; }
const char *x86_cc_name(int cc) { return cc >= 0 && cc < 16 ? ccs[cc] : "?"; }

static size_t put_op(char *b, size_t n, const X86Operand *o, int branch) {
    switch (o->kind) {
    case XO_REG: return (size_t)snprintf(b, n, "%s%%%s", branch ? "*" : "", x86_reg_name(o->reg, o->size, o->high8));
    case XO_IMM: return (size_t)snprintf(b, n, "$%lld", (long long)o->imm);
    case XO_REL: return (size_t)snprintf(b, n, "0x%llx", (unsigned long long)o->target);
    case XO_MEM: {
        size_t k = 0;
        char tmp[96];
        if (branch) tmp[k++] = '*';
        if (o->base == X86_NOREG) {
            k += (size_t)snprintf(tmp + k, sizeof(tmp) - k, "0x%llx", (unsigned long long)o->disp);
        } else if (o->disp) {
            if (o->disp < 0) k += (size_t)snprintf(tmp + k, sizeof(tmp) - k, "-%llu", (unsigned long long)(-(uint64_t)o->disp));
            else k += (size_t)snprintf(tmp + k, sizeof(tmp) - k, "%llu", (unsigned long long)o->disp);
        }
        if (o->base != X86_NOREG || o->index != X86_NOREG) {
            k += (size_t)snprintf(tmp + k, sizeof(tmp) - k, "(");
            if (o->base != X86_NOREG) k += (size_t)snprintf(tmp + k, sizeof(tmp) - k, "%%%s", x86_reg_name(o->base, 8, 0));
            if (o->index != X86_NOREG) k += (size_t)snprintf(tmp + k, sizeof(tmp) - k, ",%%%s,%d", x86_reg_name(o->index, 8, 0), o->scale);
            k += (size_t)snprintf(tmp + k, sizeof(tmp) - k, ")");
        }
        return (size_t)snprintf(b, n, "%s", tmp);
    }
    default: return 0;
    }
}

static char suffix(int size) { return size == 1 ? 'b' : size == 2 ? 'w' : size == 4 ? 'l' : 'q'; }

void x86_format(const X86Insn *in, char *buf, size_t n) {
    if (!n) return;
    buf[0] = 0;
    char mn[32];
    switch (in->op) {
    case X86_JCC: snprintf(mn, sizeof(mn), "j%s", x86_cc_name(in->cc)); break;
    case X86_SETCC: snprintf(mn, sizeof(mn), "set%s", x86_cc_name(in->cc)); break;
    case X86_ENDBR: snprintf(mn, sizeof(mn), "%s", in->cc == 32 ? "endbr32" : "endbr64"); break;
    case X86_CMOVCC: snprintf(mn, sizeof(mn), "cmov%s", x86_cc_name(in->cc)); break;
    case X86_CQO: snprintf(mn, sizeof(mn), "%s", in->ops[0].size == 8 ? "cqo" : in->ops[0].size == 2 ? "cwtd" : "cltd"); break;
    case X86_MOVZX: case X86_MOVSX:
        if (in->op == X86_MOVSX && in->ops[1].size == 4 && in->ops[0].size == 8
            && in->ops[0].kind == XO_REG && in->ops[1].kind == XO_REG
            && in->ops[0].reg == 0 && in->ops[1].reg == 0)
            snprintf(mn, sizeof(mn), "cltq");
        else if (in->op == X86_MOVSX && in->ops[1].size == 4 && in->ops[0].size == 8)
            snprintf(mn, sizeof(mn), "movslq");
        else
            snprintf(mn, sizeof(mn), "%s%c%c", x86_op_name(in->op), suffix(in->ops[1].size), suffix(in->ops[0].size));
        break;
    default: {
        snprintf(mn, sizeof(mn), "%s", x86_op_name(in->op));
        /* Size suffix only when no register says it. */
        int has_mem = 0, has_reg = 0, sz = 0;
        for (int k = 0; k < in->nops; k++) {
            if (in->ops[k].kind == XO_MEM) { has_mem = 1; sz = in->ops[k].size; }
            if (in->ops[k].kind == XO_REG) has_reg = 1;
        }
        if (has_mem && !has_reg && in->op != X86_LEA && in->op != X86_JMP && in->op != X86_CALL) {
            size_t l = strlen(mn); mn[l] = suffix(sz); mn[l + 1] = 0;
        }
    }
    }
    size_t k = (size_t)snprintf(buf, n, "%s", mn);
    int branch = in->op == X86_JMP || in->op == X86_CALL;
    if (!strcmp(mn, "cltq") || !strcmp(mn, "cqo") || !strcmp(mn, "cltd") || !strcmp(mn, "cwtd")
        || !strcmp(mn, "leave") || !strcmp(mn, "endbr64") || !strcmp(mn, "endbr32"))
        return; /* no operands printed */
    for (int j = in->nops - 1, first = 1; j >= 0; j--, first = 0) {
        if (k >= n) return;
        k += (size_t)snprintf(buf + k, n - k, first ? " " : ", ");
        if (k >= n) return;
        k += put_op(buf + k, n - k, &in->ops[j], branch);
    }
    for (int j = 0; j < in->nops; j++) {
        const X86Operand *o = &in->ops[j];
        if (o->kind == XO_MEM && o->base == X86_RIP && k < n)
            k += (size_t)snprintf(buf + k, n - k, "  # 0x%llx", (unsigned long long)o->target);
    }
}
