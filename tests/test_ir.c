#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/ir.h"

/* Builds a loop by hand, checks shape, successors, and the printout. */
int main(void) {
    int fails = 0;
    IrModule *m = ir_module_new();
    IrFunc *f = ir_func_add(m, "count", 0x1000);
    int b0 = ir_block_add(f, 0x1000), b1 = ir_block_add(f, 0x1010), b2 = ir_block_add(f, 0x1020);
    IrInsn *i;
    i = ir_emit(f, b0, IR_PUSH); i->a = ir_reg(5, 8);
    i = ir_emit(f, b0, IR_MOV); i->dst = ir_reg(0, 8); i->a = ir_imm(0, 8);
    i = ir_emit(f, b1, IR_ADD); i->dst = ir_reg(0, 8); i->a = ir_reg(0, 8); i->b = ir_imm(1, 8);
    i = ir_emit(f, b1, IR_STORE); i->dst = ir_mem(5, 1, 8, -16, 8); i->a = ir_reg(0, 8);
    i = ir_emit(f, b1, IR_LOAD); i->dst = ir_reg(2, 1); i->a = ir_mem(IR_NOREG, IR_NOREG, 1, 0x402000, 1);
    i = ir_emit(f, b1, IR_ADDR); i->dst = ir_reg(6, 8); i->a = ir_mem(IR_PC, IR_NOREG, 1, 32, 8);
    i = ir_emit(f, b1, IR_CMP); i->a = ir_reg(0, 8); i->b = ir_imm(10, 8);
    i = ir_emit(f, b1, IR_BR); i->cc = IR_CC_LT; i->a = ir_blk(b1); i->b = ir_blk(b2);
    i = ir_emit(f, b2, IR_CALL); i->a = ir_abs(0x2000);
    i = ir_emit(f, b2, IR_POP); i->dst = ir_reg(5, 8);
    i = ir_emit(f, b2, IR_RET);
    char err[128];
    if (ir_link(f, err, sizeof(err))) { printf("FAIL link: %s\n", err); fails++; }
    if (f->blocks[0].nsucc != 1 || f->blocks[0].succ[0] != 1) { printf("FAIL b0 succ\n"); fails++; }
    if (f->blocks[1].nsucc != 2 || f->blocks[1].succ[1] != 2) { printf("FAIL b1 succ\n"); fails++; }
    if (f->blocks[2].nsucc != 0) { printf("FAIL b2 succ\n"); fails++; }
    char *buf = NULL; size_t len = 0;
    FILE *o = open_memstream(&buf, &len);
    ir_print_func(o, m, f);
    fclose(o);
    const char *want =
        "func count @0x1000\n"
        "b0:  ; 0x1000\n    push r5:8\n    mov r0:8, 0\n"
        "b1:  ; 0x1010\n    add r0:8, r0:8, 1\n    store [r5 + r1*8 - 16]:8, r0:8\n"
        "    load r2:1, [0x402000]:1\n    addr r6:8, [pc + 32]:8\n    cmp r0:8, 10\n    br.lt b1, b2\n"
        "b2:  ; 0x1020\n    call 0x2000\n    pop r5:8\n    ret\n";
    if (strcmp(buf, want)) { printf("FAIL print:\n%s", buf); fails++; }
    free(buf);
    /* Bad shapes. */
    IrFunc *g = ir_func_add(m, "bad", 0);
    int c0 = ir_block_add(g, 0);
    i = ir_emit(g, c0, IR_RET);
    i = ir_emit(g, c0, IR_NOP);
    if (!ir_link(g, err, sizeof(err))) { printf("FAIL mid terminator accepted\n"); fails++; }
    g->blocks[0].ninsns = 1;
    i = ir_emit(g, c0, IR_NOP); g->blocks[0].insns[0].op = IR_NOP;
    if (!ir_link(g, err, sizeof(err))) { printf("FAIL fall off end accepted\n"); fails++; }
    g->blocks[0].insns[1].op = IR_BR; g->blocks[0].insns[1].cc = IR_CC_EQ;
    g->blocks[0].insns[1].a = ir_blk(5); g->blocks[0].insns[1].b = ir_blk(0);
    if (!ir_link(g, err, sizeof(err))) { printf("FAIL bad target accepted\n"); fails++; }
    if (ir_emit(g, 9, IR_NOP)) { printf("FAIL emit to missing block\n"); fails++; }
    ir_module_free(m);
    printf("machine ir: %s\n", fails ? "FAILED" : "ok");
    return fails ? 1 : 0;
}
