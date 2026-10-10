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
    X86_OP_COUNT
} X86Opcode;

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
