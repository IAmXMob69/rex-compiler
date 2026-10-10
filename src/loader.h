#ifndef REX_LOADER_H
#define REX_LOADER_H
#include <stddef.h>
#include <stdint.h>
#include "elfread.h"
#include "rex_err.h"

/* Binary loader abstraction. One implementation today (ELF64); PE is a
 * recognition stub. Callers open through rex_bin_open / rex_bin_parse and
 * never pick an implementation themselves.
 *
 * A loaded image is still a RexElf: the ELF reader already has segments,
 * sections and code_at. Non-ELF formats that become real loaders will fill
 * the same shape (or a thin adapter). Until then, PE recognition returns a
 * specific error without producing an image.
 */

#define REX_BIN_ERR_UNRECOGNIZED REX_E100_UNRECOGNIZED
#define REX_BIN_ERR_PE_STUB      REX_E101_PE_STUB

typedef struct RexLoader RexLoader;

struct RexLoader {
    const char *name;                                      /* "elf64", "pe" */
    /* Nonzero if this format's magic matches. Reads at most the first
     * few dozen bytes; never allocates. */
    int (*probe)(const unsigned char *data, size_t len);
    /* Parse into a RexElf. Returns 0 on success. On failure writes err and
     * returns nonzero (generic 1, or REX_BIN_ERR_*). */
    int (*parse)(const unsigned char *data, size_t len, RexElf *out, char *err, size_t errlen);
};

/* Registry: first matching probe wins. ELF first, then PE. */
const RexLoader *rex_loader_find(const unsigned char *data, size_t len);

/* Open a path / parse bytes through the registry. On unrecognized formats
 * the error is "unrecognized binary format: <hex of first bytes>" and the
 * return is REX_BIN_ERR_UNRECOGNIZED. PE returns REX_BIN_ERR_PE_STUB. */
int rex_bin_parse(const unsigned char *data, size_t len, RexElf *out, char *err, size_t errlen);
int rex_bin_open(const char *path, RexElf *out, char *err, size_t errlen);

/* Pass-throughs kept for the ELF unit tests and for code that already
 * holds a RexElf. Prefer rex_bin_* at call sites. */
int rex_elf_parse(const unsigned char *data, size_t size, RexElf *out, char *err, size_t errlen);
int rex_elf_open(const char *path, RexElf *out, char *err, size_t errlen);

#endif
