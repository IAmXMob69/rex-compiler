#ifndef REX_ELFREAD_H
#define REX_ELFREAD_H
#include <stddef.h>
#include <stdint.h>

/* ELF64 reader. src/elf.c writes ELF; this one reads it.
 * Input is untrusted: every offset and size is checked before use,
 * nothing is executed, nothing is assumed to be null-terminated.
 */

#define REX_ELF_MAX_FILE  (256u << 20)
#define REX_ELF_MAX_PHDRS 1024
#define REX_ELF_MAX_SHDRS 8192

#define REX_PT_LOAD 1
#define REX_PF_X 1
#define REX_PF_W 2
#define REX_PF_R 4

typedef struct {
    uint32_t type, flags;
    uint64_t offset, vaddr, filesz, memsz, align;
} RexPhdr;

typedef struct {
    char name[64];      /* copied, always terminated, "" if unknown */
    uint32_t type;
    uint64_t flags, addr, offset, size;
} RexShdr;

typedef struct {
    unsigned char *data;
    size_t size;
    uint16_t type, machine;
    uint64_t entry;
    int nph, nsh;
    RexPhdr *ph;
    RexShdr *sh;
} RexElf;

int rex_elf_parse(const unsigned char *data, size_t size, RexElf *out, char *err, size_t errlen);
int rex_elf_open(const char *path, RexElf *out, char *err, size_t errlen);
void rex_elf_free(RexElf *e);
int rex_elf_exec_segments(const RexElf *e);
/* File bytes behind vaddr inside an executable PT_LOAD, NULL if none. */
const unsigned char *rex_elf_code_at(const RexElf *e, uint64_t vaddr, size_t *avail);

#endif
