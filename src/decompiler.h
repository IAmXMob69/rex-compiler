#ifndef REX_DECOMPILER_H
#define REX_DECOMPILER_H

/* ELF -> CFG -> machine IR -> reconstructed REX source. */

int rex_decompile(const char *in, const char *out, int verbose);

#endif
