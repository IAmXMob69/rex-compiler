#ifndef REX_X86_LIFT_H
#define REX_X86_LIFT_H
#include <stddef.h>
#include "cfg.h"
#include "ir.h"

/* x86-64 front end for the machine IR. IR register n is x86 register n
 * (rax=0 ... r15=15). A 32-bit write is followed by an explicit zext,
 * and 8/16-bit writes keep the upper bits, so the IR never relies on
 * x86 register rules. Flags are only produced by cmp/test in the IR;
 * when x86 code branches on an add/sub/and result, the lifter inserts
 * the matching test. Anything it cannot model exactly is refused.
 */

IrModule *x86_lift(const CfgProgram *p, char *err, size_t errlen);
const char *x86_ir_reg_name(int reg);

#endif
