/* rex_color.h - optional colored diagnostics for rex.
 * Single header. In exactly one .c file: #define REX_COLOR_IMPL before including.
 * Plain text is the default; color only when stderr is a TTY, NO_COLOR is unset,
 * and TERM is not "dumb". Override: rex_color_init(REX_COLOR_ALWAYS / NEVER / AUTO). */
#ifndef REX_COLOR_H
#define REX_COLOR_H
#include <stdio.h>

typedef enum { REX_COLOR_AUTO, REX_COLOR_ALWAYS, REX_COLOR_NEVER } rex_color_mode;
typedef enum { REX_SEV_ERROR, REX_SEV_WARNING, REX_SEV_NOTE } rex_severity;

void rex_color_init(rex_color_mode mode);   /* call once at startup */
int  rex_color_enabled(void);
/* Prints: file:line:col: error[E0123]: message\n  (colored when enabled) */
void rex_diag(FILE *out, rex_severity sev, const char *file, int line, int col,
              const char *code, const char *msg);

#ifdef REX_COLOR_IMPL
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int rex__color_on = 0;
static rex_color_mode rex__mode = REX_COLOR_AUTO;

/* Basic 16-color SGR only. Bold + default foreground works on dark and light.
 * No yellow/white/black: they vanish on one background or the other. */
#define REX__RESET "\033[0m"
#define REX__BOLD  "\033[1m"
#define REX__ERR   "\033[1;31m"   /* bold red */
#define REX__WARN  "\033[1;35m"   /* bold magenta */
#define REX__NOTE  "\033[1;36m"   /* bold cyan */

void rex_color_init(rex_color_mode mode) {
    rex__mode = mode;
    if (mode == REX_COLOR_ALWAYS) { rex__color_on = 1; return; }
    if (mode == REX_COLOR_NEVER)  { rex__color_on = 0; return; }
    const char *nc = getenv("NO_COLOR");
    const char *term = getenv("TERM");
    rex__color_on = !(nc && nc[0]) && isatty(STDERR_FILENO) &&
                    !(term && strcmp(term, "dumb") == 0);
}

int rex_color_enabled(void) { return rex__color_on; }

void rex_diag(FILE *out, rex_severity sev, const char *file, int line, int col,
              const char *code, const char *msg) {
    static const char *const names[] = { "error", "warning", "note" };
    if ((unsigned)sev > REX_SEV_NOTE) sev = REX_SEV_ERROR;
    if (!msg) msg = "";
    int on = rex__color_on &&
             (rex__mode == REX_COLOR_ALWAYS || isatty(fileno(out)));
    static const char *const cols[]  = { REX__ERR, REX__WARN, REX__NOTE };
    const char *b = on ? REX__BOLD : "";
    const char *c = on ? cols[sev] : "";
    const char *r = on ? REX__RESET : "";
    if (file) {
        fprintf(out, "%s%s", b, file);
        if (line > 0) fprintf(out, ":%d", line);
        if (line > 0 && col > 0) fprintf(out, ":%d", col);
        fprintf(out, ":%s ", r);
    }
    fprintf(out, "%s%s", c, names[sev]);
    if (code && code[0]) fprintf(out, "[%s]", code);
    fprintf(out, ":%s %s\n", r, msg);
}
#endif
#endif
