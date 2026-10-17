#ifndef REX_ERR_H
#define REX_ERR_H
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* Stable numbered failure codes.
 * E1xx loader  E2xx decode  E3xx lift  E4xx CFG  E5xx recompile  E6xx decompile
 * Printed as:
 *   <plain English one-liner>
 *   E<nnn>: <details>
 * Exit status is the code when it fits in 8 bits.
 */

enum {
    REX_E100_UNRECOGNIZED = 100,
    REX_E101_PE_STUB      = 101, /* legacy: kept for older messages */
    REX_E102_ELF          = 102,
    REX_E103_IO           = 103,
    REX_E104_PE_MACHINE   = 104, /* not x86-64 */
    REX_E105_PE_MAGIC     = 105, /* not PE32+ */
    REX_E106_PE_IMPORTS   = 106, /* imports required / not supported path */
    REX_E107_PE_RELOCS    = 107,
    REX_E108_PE_TLS       = 108,
    REX_E109_PE_DOTNET    = 109,
    REX_E110_PE_PACKED    = 110,

    REX_E200_OPCODE       = 200,
    REX_E201_TRUNCATED    = 201,

    REX_E300_LIFT         = 300,
    REX_E301_FLAGS        = 301,
    REX_E302_IDIV         = 302,

    REX_E400_CFG          = 400,
    REX_E401_INDIRECT_JMP = 401,
    REX_E402_IRREDUCIBLE  = 402,
    REX_E403_NO_CODE      = 403,

    REX_E500_RECOMPILE    = 500,
    REX_E501_VERIFY       = 501,
    REX_E502_PE_REBUILD   = 502, /* cannot recompile PE yet */

    REX_E600_DECOMPILE    = 600,
    REX_E601_VERIFY       = 601,
    REX_E602_LIBCALL      = 602  /* match: calls a shared library */
};

static inline const char *rex_err_plain(int code) {
    switch (code) {
    case REX_E100_UNRECOGNIZED: return "I do not recognize this file type.";
    case REX_E101_PE_STUB:      return "This Windows program needs a feature I do not support yet.";
    case REX_E102_ELF:          return "This Linux-style program file is a kind I can't open.";
    case REX_E103_IO:           return "I could not read that file.";
    case REX_E104_PE_MACHINE:   return "This Windows program is built for a different kind of processor than the one I handle (x86-64).";
    case REX_E105_PE_MAGIC:     return "This Windows program is 32-bit, and I only handle 64-bit ones.";
    case REX_E106_PE_IMPORTS:   return "This Windows program borrows code from other files in a way I can't follow yet.";
    case REX_E107_PE_RELOCS:    return "This Windows program needs its addresses adjusted when it loads, and I can't do that yet.";
    case REX_E108_PE_TLS:       return "This Windows program keeps separate data for each task it runs at once, and I can't handle that yet.";
    case REX_E109_PE_DOTNET:    return "This is a .NET program, and I only read programs built to run straight on the processor.";
    case REX_E110_PE_PACKED:    return "This program looks squeezed or scrambled, so I won't guess what it does.";
    case REX_E200_OPCODE:       return "I found a processor instruction I don't know yet.";
    case REX_E201_TRUNCATED:    return "The file ends in the middle of an instruction.";
    case REX_E300_LIFT:         return "I couldn't translate that instruction into my own working format.";
    case REX_E301_FLAGS:        return "I lost track of the processor's true/false flags at this spot.";
    case REX_E302_IDIV:         return "This divide step is written in a way I don't handle yet.";
    case REX_E400_CFG:          return "I couldn't map out all the paths this program can take.";
    case REX_E401_INDIRECT_JMP: return "The program jumps to a spot it only figures out while running, so I can't follow it.";
    case REX_E402_IRREDUCIBLE:  return "This program's paths are too tangled for me to follow right now.";
    case REX_E403_NO_CODE:      return "That address isn't in the part of the file that holds code.";
    case REX_E500_RECOMPILE:    return "I couldn't build the new program file.";
    case REX_E501_VERIFY:       return "The new program acted differently from the original when I ran both.";
    case REX_E502_PE_REBUILD:   return "I couldn't rebuild that Windows program correctly.";
    case REX_E600_DECOMPILE:    return "I couldn't turn this program back into readable code.";
    case REX_E601_VERIFY:       return "The code I got back acted differently from the original when I ran both.";
    case REX_E602_LIBCALL:      return "This program calls code from a shared library (like printf), and I can't rebuild those calls yet.";
    default:                    return "Something went wrong.";
    }
}

/* Write plain line + "E<code>: <fmt…>" into err. Returns code. */
/* Color-aware refusal printer (defined in rex.c). Byte-identical to
 * "rex: <msg>\n" when color is off. */
void rex_refuse(const char *msg);

static inline int rex_errf(char *err, size_t errlen, int code, const char *fmt, ...) {
    char body[160];
    va_list ap; va_start(ap, fmt); vsnprintf(body, sizeof(body), fmt, ap); va_end(ap);
    if (err && errlen) {
        const char *plain = rex_err_plain(code);
        int n = snprintf(err, errlen, "%s\nE%d: ", plain, code);
        if (n < 0) n = 0;
        if ((size_t)n < errlen) snprintf(err + n, errlen - (size_t)n, "%s", body);
    }
    return code;
}

/* Look up a code for `rex explain E203`. */
static inline int rex_err_explain(int code, char *out, size_t outn) {
    if (!out || !outn) return 1;
    const char *plain = rex_err_plain(code);
    if (!strcmp(plain, "Something went wrong.")) {
        snprintf(out, outn, "I do not have a note for code %d. Try rex help.", code);
        return 1;
    }
    snprintf(out, outn, "%s\nE%d", plain, code);
    return 0;
}

#endif
