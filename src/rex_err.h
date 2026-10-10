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
    REX_E101_PE_STUB      = 101,
    REX_E102_ELF          = 102,
    REX_E103_IO           = 103,

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

    REX_E600_DECOMPILE    = 600,
    REX_E601_VERIFY       = 601
};

static inline const char *rex_err_plain(int code) {
    switch (code) {
    case REX_E100_UNRECOGNIZED: return "I do not recognize this file type.";
    case REX_E101_PE_STUB:      return "This looks like a Windows program; I cannot open those yet.";
    case REX_E102_ELF:          return "This ELF file is not a kind I can open.";
    case REX_E103_IO:           return "I could not read that file.";
    case REX_E200_OPCODE:       return "I hit an instruction I do not know yet.";
    case REX_E201_TRUNCATED:    return "The instruction bytes were cut off.";
    case REX_E300_LIFT:         return "I could not turn that instruction into my IR.";
    case REX_E301_FLAGS:        return "I could not follow the CPU flags here.";
    case REX_E302_IDIV:         return "This divide instruction is a shape I do not support.";
    case REX_E400_CFG:          return "I could not rebuild the control-flow graph.";
    case REX_E401_INDIRECT_JMP: return "I hit a jump to a computed address.";
    case REX_E402_IRREDUCIBLE:  return "This control flow is too tangled for me right now.";
    case REX_E403_NO_CODE:      return "That address is not inside executable code.";
    case REX_E500_RECOMPILE:    return "I could not write a new binary.";
    case REX_E501_VERIFY:       return "The new binary did not match the original when I ran both.";
    case REX_E600_DECOMPILE:    return "I could not turn the binary back into source.";
    case REX_E601_VERIFY:       return "The recovered source did not match the original when I ran both.";
    default:                    return "Something went wrong.";
    }
}

/* Write plain line + "E<code>: <fmt…>" into err. Returns code. */
static inline int rex_errf(char *err, size_t errlen, int code, const char *fmt, ...) {
    char body[192];
    va_list ap; va_start(ap, fmt); vsnprintf(body, sizeof(body), fmt, ap); va_end(ap);
    if (err && errlen)
        snprintf(err, errlen, "%s\nE%d: %s", rex_err_plain(code), code, body);
    return code;
}

/* Look up a code for `rex explain E203`. */
static inline int rex_err_explain(int code, char *out, size_t outn) {
    if (!out || !outn) return 1;
    const char *plain = rex_err_plain(code);
    if (!strcmp(plain, "Something went wrong.") && (code < 100 || code > 601)) {
        snprintf(out, outn, "I do not have a note for code %d. Try rex help.", code);
        return 1;
    }
    snprintf(out, outn, "%s\nE%d", plain, code);
    return 0;
}

#endif
