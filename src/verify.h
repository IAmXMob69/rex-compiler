#ifndef REX_VERIFY_H
#define REX_VERIFY_H
#include <stddef.h>
/* Run two binaries on the same inputs (argv, stdin); compare exit status,
 * stdout and stderr byte for byte. E604 if the original does not finish. */
int rex_verify_bins(const char *a, const char *b, char *err, size_t errlen, int code);
/* Lift both binaries to IR, normalize, and diff. Plain-English first mismatch. */
int rex_verify_ir(const char *a, const char *b, char *err, size_t errlen, int code);
#endif
