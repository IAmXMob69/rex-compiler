#ifndef REX_VERIFY_H
#define REX_VERIFY_H
#include <stddef.h>
/* Run two binaries with no args; compare exit status and combined stdout+stderr. */
int rex_verify_bins(const char *a, const char *b, char *err, size_t errlen);
#endif
