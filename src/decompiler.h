#ifndef REX_DECOMPILER_H
#define REX_DECOMPILER_H
#include <stddef.h>

/* ELF -> CFG -> machine IR -> reconstructed REX source. */

int rex_decompile(const char *in, const char *out, int verbose);
/* Library calls (puts, printf) in the last decompile; copies the first name. */
int rex_decompile_libcalls(char *name, size_t n);
/* Nonzero when a pointer call in the recovered source cannot reach every target (E605); why gets the reason. */
int rex_decompile_fpcalls(char *why, size_t n);
int rex_decompile_bigblock(char *why, size_t n);

#endif
