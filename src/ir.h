#ifndef REX_IR_H
#define REX_IR_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* Machine IR. Sits between the front ends (REX source, x86-64 decoder)
 * and the back ends (native code, REX source). It knows nothing about
 * x86 or REX syntax: registers are plain numbers and a front end decides
 * what they mean.
 *
 * Flags are one implicit value per function. cmp/test write it,
 * br/setcc read it with a condition.
 */

#define IR_NOREG (-1)
#define IR_PC    (-2)   /* base meaning "address of the next instruction" */

typedef enum { IR_O_NONE, IR_O_REG, IR_O_IMM, IR_O_MEM, IR_O_BLOCK, IR_O_ADDR } IrOperandKind;

typedef struct {
    IrOperandKind kind;
    int width;          /* bytes: 1, 2, 4, 8 (0 for block/addr) */
    int reg;            /* IR_O_REG */
    int64_t imm;        /* IR_O_IMM */
    int base, index;    /* IR_O_MEM, IR_NOREG when absent */
    int scale;
    int64_t disp;
    int block;          /* IR_O_BLOCK: block id inside the same function */
    uint64_t addr;      /* IR_O_ADDR: absolute code address */
} IrOperand;

typedef enum {
    IR_NOP,
    IR_MOV,     /* dst = a */
    IR_LOAD,    /* dst = [a] */
    IR_STORE,   /* [dst] = a */
    IR_ADDR,    /* dst = address of mem a (pointer arithmetic) */
    IR_ADD, IR_SUB, IR_MUL, IR_DIVS, IR_REMS,
    IR_AND, IR_OR, IR_XOR, IR_SHL, IR_SHR, IR_SAR,
    IR_NEG, IR_NOT, IR_ZEXT, IR_SEXT,   /* dst = op a (,b) */
    IR_CMP,     /* flags = a - b */
    IR_TEST,    /* flags = a & b */
    IR_SETCC,   /* dst = cc ? 1 : 0 */
    IR_CMOV,    /* dst = cc ? a : dst */
    IR_JMP,     /* goto a (block or addr) */
    IR_BR,      /* if cc goto a else goto b */
    IR_CALL,    /* call a (addr or reg) */
    IR_RET,
    IR_PUSH,    /* sp -= width; [sp] = a */
    IR_POP,     /* dst = [sp]; sp += width */
    IR_SYSCALL, /* platform call, registers per front end */
    IR_TRAP,    /* never reached (after a process exit) */
    IR_OP_COUNT
} IrOp;

typedef enum {
    IR_CC_NONE, IR_CC_EQ, IR_CC_NE,
    IR_CC_LT, IR_CC_LE, IR_CC_GT, IR_CC_GE,
    IR_CC_ULT, IR_CC_ULE, IR_CC_UGT, IR_CC_UGE,
    IR_CC_NEG, IR_CC_POS,
    IR_CC_COUNT
} IrCond;

typedef struct {
    IrOp op;
    IrCond cc;
    IrOperand dst, a, b;   /* call: a = target, b = return address */
    uint64_t origin;    /* source address or line, 0 if none */
} IrInsn;

typedef struct {
    int id;
    uint64_t addr;
    IrInsn *insns;
    int ninsns, cap;
    int succ[2];
    int nsucc;
} IrBlock;

typedef struct {
    char name[64];
    uint64_t addr;
    IrBlock *blocks;    /* ir_block_add may move this array */
    int nblocks, cap;
} IrFunc;

typedef struct {
    IrFunc *funcs;
    int nfuncs, cap;
    const char *(*reg_name)(int reg);   /* optional, for printing */
} IrModule;

IrModule *ir_module_new(void);
void ir_module_free(IrModule *m);
IrFunc *ir_func_add(IrModule *m, const char *name, uint64_t addr);
int ir_block_add(IrFunc *f, uint64_t addr);            /* block id, -1 on failure */
IrInsn *ir_emit(IrFunc *f, int block, IrOp op);        /* NULL on failure */

IrOperand ir_reg(int reg, int width);
IrOperand ir_imm(int64_t v, int width);
IrOperand ir_mem(int base, int index, int scale, int64_t disp, int width);
IrOperand ir_blk(int block);
IrOperand ir_abs(uint64_t addr);

int ir_is_terminator(IrOp op);
int ir_link(IrFunc *f, char *err, size_t errlen);   /* checks shape, fills succ */
const char *ir_op_name(IrOp op);
const char *ir_cc_name(IrCond cc);
void ir_print_operand(FILE *out, const IrModule *m, const IrOperand *o);
void ir_print_func(FILE *out, const IrModule *m, const IrFunc *f);

#endif
