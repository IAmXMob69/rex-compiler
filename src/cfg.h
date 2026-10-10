#ifndef REX_CFG_H
#define REX_CFG_H
#include <stddef.h>
#include <stdint.h>
#include "elfread.h"
#include "x86_decode.h"

/* Control flow recovery. Recursive descent from the entry point:
 * direct calls start new functions, jumps stay inside the function.
 * Nothing is guessed from linear sweeps. Indirect jumps are refused.
 */

#define CFG_MAX_FUNCS 4096
#define CFG_MAX_INSNS (1 << 18)

typedef struct {
    uint64_t start, end;    /* [start, end) */
    int first, n;           /* slice of CfgFunc.insns */
    int succ[2], nsucc;
    int exits;              /* ends in a process exit syscall */
} CfgBlock;

typedef struct {
    uint64_t addr;
    char name[32];
    X86Insn *insns;         /* sorted by address */
    int ninsns;
    CfgBlock *blocks;
    int nblocks;
} CfgFunc;

typedef struct {
    CfgFunc *funcs;
    int nfuncs;
    uint64_t main_addr;     /* first direct call from the entry, 0 if none */
} CfgProgram;

int cfg_build(const RexElf *e, CfgProgram *p, char *err, size_t errlen);
void cfg_free(CfgProgram *p);
int cfg_find_func(const CfgProgram *p, uint64_t addr);
int cfg_find_block(const CfgFunc *f, uint64_t addr);
int cfg_is_exit(const X86Insn *prev, const X86Insn *in);

#endif
