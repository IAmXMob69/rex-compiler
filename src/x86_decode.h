#ifndef REX_X86_DECODE_H
#define REX_X86_DECODE_H
#include <stddef.h>
#include <stdint.h>

/* Small x86-64 decoder. Bytes in, structured instruction out.
 * Operands are stored destination first. Formatting is separate.
 */

enum { X86_RIP = 16, X86_NOREG = -1 };

typedef enum { XO_NONE, XO_REG, XO_IMM, XO_MEM, XO_REL } X86OperandKind;

typedef struct {
    X86OperandKind kind;
    int size;           /* bytes */
    int reg;            /* XO_REG: 0-15 */
    int high8;          /* XO_REG size 1: ah/ch/dh/bh */
    int xmm;            /* XO_REG is an xmm register (SSE) */
    int64_t imm;        /* XO_IMM, sign-extended */
    int base, index;    /* XO_MEM: register, X86_RIP, or X86_NOREG */
    int scale;
    int64_t disp;
    uint64_t target;    /* XO_REL, and XO_MEM with base X86_RIP */
} X86Operand;

typedef enum {
    X86_BAD,
    X86_MOV, X86_MOVZX, X86_MOVSX, X86_PUSH, X86_POP, X86_LEA,
    X86_ADD, X86_SUB, X86_IMUL, X86_IDIV, X86_DIV,
    X86_AND, X86_OR, X86_XOR, X86_SHL, X86_SHR, X86_SAR,
    X86_CMP, X86_TEST, X86_INC, X86_DEC, X86_NEG, X86_NOT,
    X86_JMP, X86_JCC, X86_SETCC, X86_CALL, X86_RET,
    X86_NOP, X86_CQO, X86_SYSCALL,
    X86_ENDBR,          /* endbr64/endbr32: no-op for the lift */
    X86_LEAVE,          /* mov %rbp, %rsp; pop %rbp */
    X86_HLT, X86_UD2,   /* terminators */
    X86_CMOVCC,         /* cc in .cc; dst, src */
    X86_XCHG,           /* exchange dst, src */
    X86_SSE,            /* SSE move, zero or packed lane op; .cc holds an SSE_* sub-kind */
    X86_MUL,            /* one operand: rdx:rax = rax * src (unsigned); one-operand X86_IMUL is the signed form */
    X86_OP_COUNT
} X86Opcode;

/* mul/imul with one operand: rdx:rax = rax * src, writing both implicitly */
#define X86_IS_MUL1(in) ((in)->op == X86_MUL || ((in)->op == X86_IMUL && (in)->nops == 1))

/* X86_SSE sub-kinds, stored in X86Insn.cc: data movement, the xor-self zero
 * idiom, and register-only packed integer lane ops (see decode_sse). */
enum {
    SSE_LOAD16,   /* dst xmm = [mem] (16 bytes) */
    SSE_STORE16,  /* [mem] = src xmm (16 bytes) */
    SSE_MOVRR,    /* dst xmm = src xmm (16 bytes) */
    SSE_ZERO,     /* dst xmm = 0 (xorps/pxor self) */
    SSE_LOADQ,    /* dst xmm = zext [mem] (low 8 bytes, high zeroed) */
    SSE_STOREQ,   /* [mem] = src xmm (low 8 bytes) */
    SSE_MOVD_TOX, /* dst xmm = zext src r/m (4 or 8 bytes) */
    SSE_MOVD_FROMX,/* dst r/m = src xmm (low 4 or 8 bytes) */
    /* packed integer lanes: dst xmm OP= src xmm (or imm). ops are dst, src[, imm] */
    SSE_PADDD, SSE_PSUBD,
    SSE_PAND, SSE_POR, SSE_PXOR2,     /* PXOR2: pxor of two distinct regs */
    SSE_PCMPEQB, SSE_PCMPEQW, SSE_PCMPEQD,
    SSE_PCMPGTB, SSE_PCMPGTW, SSE_PCMPGTD,
    SSE_PSHUFD,                        /* ops: dst, src, imm (control byte) */
    SSE_PSRLQ, SSE_PSLLQ,              /* ops: dst, imm (shift count) */
    SSE_PUNPCKLBW, SSE_PUNPCKLWD, SSE_PUNPCKLDQ, SSE_PUNPCKLQDQ,
    SSE_PUNPCKHBW, SSE_PUNPCKHWD, SSE_PUNPCKHDQ, SSE_PUNPCKHQDQ
};

typedef struct {
    X86Opcode op;
    int cc;             /* JCC/SETCC: 0-15, x86 condition encoding */
    int nops;
    X86Operand ops[3];
    int size;           /* encoded length */
    uint64_t addr;
} X86Insn;

/* Returns length (1-15), or 0 for unknown or truncated bytes. Reads
 * at most min(avail, 15) bytes. */
int x86_decode(const unsigned char *p, size_t avail, uint64_t addr, X86Insn *out);
void x86_format(const X86Insn *in, char *buf, size_t n);  /* AT&T, like rex asm */
const char *x86_reg_name(int reg, int size, int high8);
const char *x86_op_name(X86Opcode op);
const char *x86_cc_name(int cc);

#endif
