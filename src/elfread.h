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

/* A function the program borrows from a shared library (libc). got is the
 * slot the dynamic loader fills in; plt is the stub that jumps through it,
 * 0 if the program only calls through the slot. */
typedef struct {
    uint64_t got, plt;
    char name[48];      /* copied, always terminated, identifier characters only */
} RexImport;

#define REX_ELF_MAX_IMPORTS 4096

typedef struct {
    unsigned char *data;
    size_t size;
    uint16_t type, machine;
    uint64_t entry;
    int nph, nsh;
    RexPhdr *ph;
    RexShdr *sh;
    int dynamic;        /* has PT_INTERP or PT_DYNAMIC */
    int interp;         /* has PT_INTERP: started by the dynamic loader */
    int pie;            /* ET_DYN program, read at base 0 */
    int nimp;
    RexImport *imp;
} RexElf;

int rex_elf_parse(const unsigned char *data, size_t size, RexElf *out, char *err, size_t errlen);
int rex_elf_open(const char *path, RexElf *out, char *err, size_t errlen);
void rex_elf_free(RexElf *e);
int rex_elf_exec_segments(const RexElf *e);
/* File bytes behind vaddr inside an executable PT_LOAD, NULL if none. */
const unsigned char *rex_elf_code_at(const RexElf *e, uint64_t vaddr, size_t *avail);
/* Name of the library function whose PLT stub starts at addr, NULL if none. */
const char *rex_elf_import_at(const RexElf *e, uint64_t addr);
/* Name of the library function whose GOT slot is at got, NULL if none. */
const char *rex_elf_import_got(const RexElf *e, uint64_t got);

#endif
