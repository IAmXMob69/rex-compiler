#ifndef REX_RECOMPILER_H
#define REX_RECOMPILER_H

/* ELF -> CFG -> machine IR -> native backend -> ELF. */
int rex_recompile(const char *in, const char *out, int debug);

#endif
