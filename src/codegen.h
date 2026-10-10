#ifndef REX_CODEGEN_H
#define REX_CODEGEN_H
#include <stddef.h>
#include <stdint.h>
#include "ir.h"

/* IR -> x86-64 machine code. The one native backend. It encodes the IR
 * the x86 lifter produces (registers 0-15 are x86 registers) back into
 * bytes, lays the functions out, and resolves block and call targets.
 * No assembler, no gcc. Output is raw bytes plus relocations by original
 * function address; the ELF writer in recompiler.c places them.
 */

typedef struct { int at; uint64_t target; int kind; } CgReloc;  /* kind: 0 rel32 */

typedef struct {
    unsigned char *code;
    size_t len, cap;
    uint64_t *func_off;     /* new offset of each IR function, by index */
    int nfunc;
    CgReloc *relocs;
    int nrelocs, rcap;
    IrModule *m;
} CgResult;

int cg_emit_module(IrModule *m, CgResult *out, char *err, size_t errlen);
void cg_free(CgResult *r);

#endif
