#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* REX — a small native compiler for Arch.
 * Integer language, SysV AMD64, libc runtime.
 * No LLVM. The empire does not rent its code generator.
 */

#define REX_VERSION "0.17.0"

#ifndef REX_PREFIX
#define REX_PREFIX "/usr/local"
#endif

typedef enum {
    T_EOF = 0, T_FN, T_LET, T_IF, T_ELSE, T_WHILE, T_DO, T_FOR, T_BREAK, T_CONTINUE, T_SWITCH, T_CASE, T_DEFAULT, T_ENUM, T_PRINT, T_EXEC,
    T_RETURN, T_READ, T_STRUCT, T_IDENT, T_NUM, T_STR,
    T_LPAREN, T_RPAREN, T_LBRACE, T_RBRACE, T_LBRACK, T_RBRACK, T_SEMI, T_COMMA, T_EQ,
    T_PLUS, T_MINUS, T_STAR, T_SLASH, T_PERCENT, T_AMP, T_PIPE, T_CARET, T_TILDE, T_SHL, T_SHR, T_INC, T_DEC, T_PLUSEQ, T_MINUSEQ, T_STAREQ, T_QUEST, T_DOT, T_ARROW, T_COLON,
    T_EQEQ, T_NE, T_LT, T_GT, T_LE, T_GE,
    T_ANDAND, T_OROR, T_BANG
} TokKind;

typedef struct {
    TokKind kind;
    char *text;
    long num;
    int line;
    int col;
} Token;

typedef enum {
    N_PROGRAM, N_FN, N_BLOCK, N_LET, N_ASSIGN, N_PRINT, N_EXEC,
    N_RETURN, N_IF, N_WHILE, N_FOR, N_BREAK, N_EXPRSTMT, N_BIN, N_UNARY, N_NUM,
    N_STR, N_VAR, N_CALL, N_READ, N_INDEX, N_ADDR, N_FIELD, N_STORE, N_CONTINUE, N_SWITCH
} NodeKind;

typedef struct Node Node;
struct Node {
    NodeKind kind;
    int line;
    char *name;
    long num;
    char *str;
    int op;
    Node *a, *b, *c;
    Node **kids;
    int nkids;
    int ncap;
};

typedef struct {
    char *src;
    int len;
    int pos;
    int line;
    int col;
    Token tok;
    char *path;
} Lexer;

typedef struct {
    char *name;
    int offset; /* first slot, negative rbp offset */
    int len;    /* 0 int, >0 array, -1 string, -2 pointer, -3 struct */
    int aux;    /* struct id when len == -3 */
    int declared;
} Local;

typedef struct {
    char *name;
    Local locals[64];
    int nlocals;
    int slots;
    int stack;
    int is_main;
    int ret_ty;
} FnCtx;

static FILE *g_out;
static int g_lbl;
static int g_depth;
static FnCtx *g_fn;
static int g_break = -1;
static int g_cont = -1;
static char *g_src;
static char *g_path;
static int col_of(int line, const char *name);

typedef struct { char *name; long val; } Macro;
static Macro g_macros[64];
static int g_nmacros;

static int macro_find(const char *name) {
    for (int i = 0; i < g_nmacros; i++) if (!strcmp(g_macros[i].name, name)) return i;
    return -1;
}
static char **g_fns;
static int *g_arity;
static int *g_pty;
static int g_nfn;
static int g_err;
static char g_tmpasm[64];

typedef struct { char *name; char *fields[8]; int nfields; } SDef;
static SDef g_sd[16];
static int g_nsd;

static int struct_find(const char *name) {
    for (int i = 0; i < g_nsd; i++) if (!strcmp(g_sd[i].name, name)) return i;
    return -1;
}
static int field_find(int id, const char *f) {
    for (int i = 0; i < g_sd[id].nfields; i++) if (!strcmp(g_sd[id].fields[i], f)) return i;
    return -1;
}

static void cleanup_tmp(void) {
    if (g_tmpasm[0]) {
        unlink(g_tmpasm);
        g_tmpasm[0] = 0;
    }
}

static void die(const char *fmt, ...) {
    va_list ap;
    cleanup_tmp();
    va_start(ap, fmt);
    fputs("rex: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    exit(1);
}

static void show_line(int line, int col) {
    if (!g_src || line < 1) return;
    int n = 1;
    const char *p = g_src;
    while (*p && n < line) {
        if (*p == '\n') n++;
        p++;
    }
    const char *end = p;
    while (*end && *end != '\n') end++;
    fprintf(stderr, "    %.*s\n", (int)(end - p), p);
    fputs("    ", stderr);
    int mark = col < 1 ? 1 : col;
    for (int i = 1; i < mark && i < 200; i++) fputc(' ', stderr);
    fputs("^\n", stderr);
}

static void error_at(int line, int col, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "%s:%d:%d: error: ", g_path ? g_path : "rex", line, col);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    show_line(line, col);
    g_err++;
}

static void fail_at(int line, int col, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "%s:%d:%d: error: ", g_path ? g_path : "rex", line, col);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    show_line(line, col);
    g_err++;
    die("aborting after %d error%s", g_err, g_err == 1 ? "" : "s");
}

static char *xstrdup(const char *s) {
    size_t n = strlen(s);
    char *p = malloc(n + 1);
    if (!p) die("out of memory");
    memcpy(p, s, n + 1);
    return p;
}

static char *xstrndup(const char *s, size_t n) {
    char *p = malloc(n + 1);
    if (!p) die("out of memory");
    memcpy(p, s, n);
    p[n] = 0;
    return p;
}

static Node *node_new(NodeKind k, int line) {
    Node *n = calloc(1, sizeof(Node));
    if (!n) die("out of memory");
    n->kind = k;
    n->line = line;
    return n;
}

static void node_add(Node *p, Node *c) {
    if (p->nkids == p->ncap) {
        p->ncap = p->ncap ? p->ncap * 2 : 8;
        p->kids = realloc(p->kids, (size_t)p->ncap * sizeof(Node *));
        if (!p->kids) die("out of memory");
    }
    p->kids[p->nkids++] = c;
}

static int startswith_kw(const char *s, const char *kw, int n) {
    int k = (int)strlen(kw);
    if (n != k) return 0;
    return memcmp(s, kw, (size_t)k) == 0;
}

static void lex_next(Lexer *L) {
    const char *s = L->src;
    int i = L->pos;
    for (;;) {
        while (i < L->len && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n')) {
            if (s[i] == '\n') { L->line++; L->col = 1; }
            else L->col++;
            i++;
        }
        if (i + 1 < L->len && s[i] == '/' && s[i + 1] == '/') {
            while (i < L->len && s[i] != '\n') i++;
            continue;
        }
        if (i + 1 < L->len && s[i] == '/' && s[i + 1] == '*') {
            i += 2; L->col += 2;
            while (i + 1 < L->len && !(s[i] == '*' && s[i + 1] == '/')) {
                if (s[i] == '\n') { L->line++; L->col = 1; }
                else L->col++;
                i++;
            }
            if (i + 1 >= L->len) fail_at(L->line, L->col, "unterminated block comment");
            i += 2; L->col += 2;
            continue;
        }
        if (s[i] == '#') {
            int h = i;
            while (h < L->len && s[h] != '\n') h++;
            int k = i + 1;
            while (k < h && (s[k] == ' ' || s[k] == '\t')) k++;
            if (h - k >= 6 && !strncmp(s + k, "define", 6) && (k + 6 == h || s[k + 6] == ' ' || s[k + 6] == '\t')) {
                k += 6;
                while (k < h && (s[k] == ' ' || s[k] == '\t')) k++;
                int ns = k;
                while (k < h && (isalnum((unsigned char)s[k]) || s[k] == '_')) k++;
                if (k == ns) die("%s:%d: #define wants a name", L->path, L->line);
                while (k < h && (s[k] == ' ' || s[k] == '\t')) k++;
                if (k >= h || !isdigit((unsigned char)s[k])) die("%s:%d: #define wants an integer", L->path, L->line);
                long v = 0;
                while (k < h && isdigit((unsigned char)s[k])) {
                    v = v * 10 + (s[k] - '0');
                    k++;
                }
                if (g_nmacros >= 64) die("too many #define");
                g_macros[g_nmacros].name = xstrndup(s + ns, (size_t)(k > ns ? (strchr(s + ns, ' ') ? strchr(s + ns, ' ') - (s + ns) : k - ns) : 0));
                /* name length is the identifier span, not the value span */
                free(g_macros[g_nmacros].name);
                int ne = ns;
                while (ne < h && (isalnum((unsigned char)s[ne]) || s[ne] == '_')) ne++;
                g_macros[g_nmacros].name = xstrndup(s + ns, (size_t)(ne - ns));
                g_macros[g_nmacros].val = v;
                g_nmacros++;
            } else {
                die("%s:%d: only #define NAME integer is supported", L->path, L->line);
            }
            i = h;
            continue;
        }
        break;
    }
    Token t;
    memset(&t, 0, sizeof(t));
    t.line = L->line;
    t.col = L->col;
    if (i >= L->len) {
        t.kind = T_EOF;
        L->pos = i;
        L->tok = t;
        return;
    }
    char c = s[i];
    if (isalpha((unsigned char)c) || c == '_') {
        int start = i;
        int col = L->col;
        while (i < L->len && (isalnum((unsigned char)s[i]) || s[i] == '_')) i++;
        int n = i - start;
        t.col = col;
        t.text = xstrndup(s + start, (size_t)n);
        if (startswith_kw(t.text, "fn", n)) t.kind = T_FN;
        else if (startswith_kw(t.text, "let", n)) t.kind = T_LET;
        else if (startswith_kw(t.text, "if", n)) t.kind = T_IF;
        else if (startswith_kw(t.text, "else", n)) t.kind = T_ELSE;
        else if (startswith_kw(t.text, "while", n)) t.kind = T_WHILE;
        else if (startswith_kw(t.text, "do", n)) t.kind = T_DO;
        else if (startswith_kw(t.text, "for", n)) t.kind = T_FOR;
        else if (startswith_kw(t.text, "break", n)) t.kind = T_BREAK;
        else if (startswith_kw(t.text, "continue", n)) t.kind = T_CONTINUE;
        else if (startswith_kw(t.text, "switch", n)) t.kind = T_SWITCH;
        else if (startswith_kw(t.text, "case", n)) t.kind = T_CASE;
        else if (startswith_kw(t.text, "default", n)) t.kind = T_DEFAULT;
        else if (startswith_kw(t.text, "enum", n)) t.kind = T_ENUM;
        else if (startswith_kw(t.text, "print", n)) t.kind = T_PRINT;
        else if (startswith_kw(t.text, "exec", n)) t.kind = T_EXEC;
        else if (startswith_kw(t.text, "return", n)) t.kind = T_RETURN;
        else if (startswith_kw(t.text, "read", n)) t.kind = T_READ;
        else if (startswith_kw(t.text, "struct", n)) t.kind = T_STRUCT;
        else t.kind = T_IDENT;
        if (t.kind == T_IDENT) {
            int m = macro_find(t.text);
            if (m >= 0) {
                free(t.text);
                t.text = NULL;
                t.kind = T_NUM;
                t.num = g_macros[m].val;
            }
        }
        L->col += n;
        L->pos = i;
        L->tok = t;
        return;
    }
    if (isdigit((unsigned char)c)) {
        int col = L->col;
        unsigned long long v = 0;
        int overflow = 0;
        if (s[i] == '0' && i + 1 < L->len && (s[i + 1] == 'x' || s[i + 1] == 'X')) {
            i += 2; L->col += 2;
            if (i >= L->len || !isxdigit((unsigned char)s[i])) die("%s:%d: bad hex literal", L->path, L->line);
            while (i < L->len && isxdigit((unsigned char)s[i])) {
                unsigned digit = (unsigned)s[i];
                if (digit >= '0' && digit <= '9') digit -= '0';
                else if (digit >= 'a' && digit <= 'f') digit = digit - 'a' + 10;
                else digit = digit - 'A' + 10;
                if (v > (unsigned long long)LONG_MAX / 16ull) overflow = 1;
                v = v * 16ull + digit;
                i++; L->col++;
            }
        } else {
            while (i < L->len && isdigit((unsigned char)s[i])) {
                unsigned digit = (unsigned)(s[i] - '0');
                if (v > (unsigned long long)LONG_MAX / 10ull ||
                    (v == (unsigned long long)LONG_MAX / 10ull &&
                     digit > (unsigned)(LONG_MAX % 10)))
                    overflow = 1;
                v = v * 10ull + digit;
                i++;
                L->col++;
            }
        }
        if (overflow)
            die("%s:%d:%d: integer literal does not fit in signed 64-bit", L->path, L->line, col);
        t.kind = T_NUM;
        t.num = (long)v;
        t.col = col;
        L->pos = i;
        L->tok = t;
        return;
    }
    if (c == '"') {
        int col = L->col;
        i++; L->col++;
        size_t cap = 32, n = 0;
        char *buf = malloc(cap);
        if (!buf) die("out of memory");
        while (i < L->len && s[i] != '"') {
            char ch = s[i];
            if (ch == '\n') fail_at(L->line, L->col, "unterminated string");
            if (ch == '\\' && i + 1 < L->len) {
                i++; L->col++;
                char e = s[i];
                if (e == 'n') ch = '\n';
                else if (e == 't') ch = '\t';
                else if (e == '\\' || e == '"') ch = e;
                else ch = e;
            }
            if (n + 1 >= cap) {
                cap *= 2;
                buf = realloc(buf, cap);
                if (!buf) die("out of memory");
            }
            buf[n++] = ch;
            i++; L->col++;
        }
        if (i >= L->len || s[i] != '"') fail_at(t.line, t.col, "unterminated string");
        i++; L->col++;
        buf[n] = 0;
        t.kind = T_STR;
        t.text = buf;
        t.col = col;
        L->pos = i;
        L->tok = t;
        return;
    }
    if (c == '\'') {
        int col = L->col;
        i++; L->col++;
        if (i >= L->len) die("%s:%d: unterminated character", L->path, L->line);
        char ch = s[i];
        if (ch == '\\' && i + 1 < L->len) {
            i++; L->col++;
            char e = s[i];
            if (e == 'n') ch = '\n';
            else if (e == 't') ch = '\t';
            else if (e == '0') ch = 0;
            else ch = e;
        }
        i++; L->col++;
        if (i >= L->len || s[i] != '\'') die("%s:%d: unterminated character", L->path, L->line);
        i++; L->col++;
        t.kind = T_NUM;
        t.num = (unsigned char)ch;
        t.col = col;
        L->pos = i;
        L->tok = t;
        return;
    }
    int col = L->col;
    if (i + 1 < L->len) {
        if (s[i] == '=' && s[i + 1] == '=') { t.kind = T_EQEQ; L->pos = i + 2; L->col += 2; t.col = col; L->tok = t; return; }
        if (s[i] == '&' && s[i + 1] == '&') { t.kind = T_ANDAND; L->pos = i + 2; L->col += 2; t.col = col; L->tok = t; return; }
        if (s[i] == '|' && s[i + 1] == '|') { t.kind = T_OROR; L->pos = i + 2; L->col += 2; t.col = col; L->tok = t; return; }
        if (s[i] == '+' && s[i + 1] == '=') { t.kind = T_PLUSEQ; L->pos = i + 2; L->col += 2; t.col = col; L->tok = t; return; }
        if (s[i] == '-' && s[i + 1] == '=') { t.kind = T_MINUSEQ; L->pos = i + 2; L->col += 2; t.col = col; L->tok = t; return; }
        if (s[i] == '*' && s[i + 1] == '=') { t.kind = T_STAREQ; L->pos = i + 2; L->col += 2; t.col = col; L->tok = t; return; }
        if (s[i] == '+' && s[i + 1] == '+') { t.kind = T_INC; L->pos = i + 2; L->col += 2; t.col = col; L->tok = t; return; }
        if (s[i] == '-' && s[i + 1] == '-') { t.kind = T_DEC; L->pos = i + 2; L->col += 2; t.col = col; L->tok = t; return; }
        if (s[i] == '-' && s[i + 1] == '>') { t.kind = T_ARROW; L->pos = i + 2; L->col += 2; t.col = col; L->tok = t; return; }
        if (s[i] == '<' && s[i + 1] == '<') { t.kind = T_SHL; L->pos = i + 2; L->col += 2; t.col = col; L->tok = t; return; }
        if (s[i] == '>' && s[i + 1] == '>') { t.kind = T_SHR; L->pos = i + 2; L->col += 2; t.col = col; L->tok = t; return; }
        if (s[i] == '!' && s[i + 1] == '=') { t.kind = T_NE; L->pos = i + 2; L->col += 2; t.col = col; L->tok = t; return; }
        if (s[i] == '<' && s[i + 1] == '=') { t.kind = T_LE; L->pos = i + 2; L->col += 2; t.col = col; L->tok = t; return; }
        if (s[i] == '>' && s[i + 1] == '=') { t.kind = T_GE; L->pos = i + 2; L->col += 2; t.col = col; L->tok = t; return; }
    }
    TokKind k = T_EOF;
    switch (c) {
        case ':': k = T_COLON; break;
        case '&': k = T_AMP; break;
        case '|': k = T_PIPE; break;
        case '^': k = T_CARET; break;
        case '~': k = T_TILDE; break;
        case '?': k = T_QUEST; break;
        case '.': k = T_DOT; break;
        case '(': k = T_LPAREN; break;
        case ')': k = T_RPAREN; break;
        case '{': k = T_LBRACE; break;
        case '}': k = T_RBRACE; break;
        case '[': k = T_LBRACK; break;
        case ']': k = T_RBRACK; break;
        case ';': k = T_SEMI; break;
        case ',': k = T_COMMA; break;
        case '=': k = T_EQ; break;
        case '!': k = T_BANG; break;
        case '+': k = T_PLUS; break;
        case '-': k = T_MINUS; break;
        case '*': k = T_STAR; break;
        case '/': k = T_SLASH; break;
        case '%': k = T_PERCENT; break;
        case '<': k = T_LT; break;
        case '>': k = T_GT; break;
        default:
            fail_at(L->line, L->col, "stray character '%c'", c);
    }
    t.kind = k;
    t.col = col;
    L->pos = i + 1;
    L->col++;
    L->tok = t;
}

static int g_panic;

static void expect(Lexer *L, TokKind k, const char *what) {
    if (L->tok.kind == k) {
        g_panic = 0;
        lex_next(L);
        return;
    }
    if (!g_panic) error_at(L->tok.line, L->tok.col, "expected %s", what);
    g_panic = 1;
}

static void sync_stmt(Lexer *L) {
    int guard = 0;
    while (L->tok.kind != T_SEMI && L->tok.kind != T_RBRACE && L->tok.kind != T_EOF && guard < 1000) {
        lex_next(L);
        guard++;
    }
    if (L->tok.kind == T_SEMI) lex_next(L);
    g_panic = 0;
}

static Node *parse_expr(Lexer *L);

static void parse_args(Lexer *L, Node *call) {
    expect(L, T_LPAREN, "'('");
    if (L->tok.kind == T_RPAREN) {
        lex_next(L);
        return;
    }
    for (;;) {
        node_add(call, parse_expr(L));
        if (L->tok.kind != T_COMMA) break;
        lex_next(L);
    }
    expect(L, T_RPAREN, "')'");
    if (call->nkids > 6) fail_at(call->line, 1, "at most 6 arguments");
}

static Node *parse_primary(Lexer *L) {
    Token t = L->tok;
    if (t.kind == T_NUM) {
        Node *n = node_new(N_NUM, t.line);
        n->num = t.num;
        lex_next(L);
        return n;
    }
    if (t.kind == T_STR) {
        Node *n = node_new(N_STR, t.line);
        n->str = xstrdup(t.text);
        lex_next(L);
        return n;
    }
    if (t.kind == T_READ) {
        lex_next(L);
        expect(L, T_LPAREN, "'('");
        expect(L, T_RPAREN, "')'");
        return node_new(N_READ, t.line);
    }
    if (t.kind == T_IDENT) {
        char *name = xstrdup(t.text);
        lex_next(L);
        if (L->tok.kind == T_LPAREN) {
            Node *n = node_new(N_CALL, t.line);
            n->name = name;
            parse_args(L, n);
            return n;
        }
        if (L->tok.kind == T_LBRACK) {
            Node *n = node_new(N_INDEX, t.line);
            n->name = name;
            lex_next(L);
            n->a = parse_expr(L);
            expect(L, T_RBRACK, "']'");
            return n;
        }
        Node *n = node_new(N_VAR, t.line);
        n->name = name;
        return n;
    }
    if (t.kind == T_LPAREN) {
        lex_next(L);
        Node *n = parse_expr(L);
        expect(L, T_RPAREN, "')'");
        return n;
    }
    error_at(t.line, t.col, "expected expression");
    g_panic = 1;
    Node *bad = node_new(N_NUM, t.line);
    bad->num = 0;
    if (L->tok.kind != T_EOF && L->tok.kind != T_SEMI && L->tok.kind != T_RBRACE && L->tok.kind != T_RPAREN)
        lex_next(L);
    return bad;
}

static Node *parse_primary(Lexer *L);

static Node *parse_postfix(Lexer *L) {
    Node *n = parse_primary(L);
    while (L->tok.kind == T_DOT || L->tok.kind == T_ARROW) {
        int arrow = L->tok.kind == T_ARROW;
        int line = L->tok.line;
        lex_next(L);
        if (L->tok.kind != T_IDENT) die("line %d: expected field name", L->tok.line);
        Node *f = node_new(N_FIELD, line);
        f->a = n;
        f->name = xstrdup(L->tok.text);
        f->num = arrow;
        lex_next(L);
        n = f;
    }
    while (n->kind == N_VAR && (L->tok.kind == T_INC || L->tok.kind == T_DEC)) {
        Node *u = node_new(N_UNARY, L->tok.line);
        u->op = L->tok.kind;
        u->num = 1;
        u->a = n;
        lex_next(L);
        n = u;
    }
    return n;
}

static Node *parse_unary(Lexer *L) {
    if (L->tok.kind == T_AMP) {
        int line = L->tok.line;
        lex_next(L);
        if (L->tok.kind != T_IDENT) die("line %d: & wants a name", line);
        Node *n = node_new(N_ADDR, line);
        n->name = xstrdup(L->tok.text);
        lex_next(L);
        return n;
    }
    if (L->tok.kind == T_STAR) {
        int line = L->tok.line;
        lex_next(L);
        Node *n = node_new(N_UNARY, line);
        n->op = T_STAR;
        n->a = parse_unary(L);
        return n;
    }
    if (L->tok.kind == T_INC || L->tok.kind == T_DEC) {
        int op = L->tok.kind;
        int line = L->tok.line;
        lex_next(L);
        Node *n = node_new(N_UNARY, line);
        n->op = op;
        n->num = 0;
        n->a = parse_unary(L);
        if (!n->a || n->a->kind != N_VAR) die("line %d: ++ and -- want a name", line);
        return n;
    }
    if (L->tok.kind == T_MINUS || L->tok.kind == T_BANG || L->tok.kind == T_TILDE) {
        int op = L->tok.kind;
        int line = L->tok.line;
        lex_next(L);
        Node *n = node_new(N_UNARY, line);
        n->op = op;
        n->a = parse_unary(L);
        return n;
    }
    return parse_postfix(L);
}

static Node *parse_factor(Lexer *L) {
    Node *n = parse_unary(L);
    while (L->tok.kind == T_STAR || L->tok.kind == T_SLASH || L->tok.kind == T_PERCENT) {
        int op = L->tok.kind;
        int line = L->tok.line;
        lex_next(L);
        Node *b = node_new(N_BIN, line);
        b->op = op;
        b->a = n;
        b->b = parse_unary(L);
        n = b;
    }
    return n;
}

static Node *parse_term(Lexer *L) {
    Node *n = parse_factor(L);
    while (L->tok.kind == T_PLUS || L->tok.kind == T_MINUS) {
        int op = L->tok.kind;
        int line = L->tok.line;
        lex_next(L);
        Node *b = node_new(N_BIN, line);
        b->op = op;
        b->a = n;
        b->b = parse_factor(L);
        n = b;
    }
    return n;
}

static Node *parse_shift(Lexer *L) {
    Node *n = parse_term(L);
    while (L->tok.kind == T_SHL || L->tok.kind == T_SHR) {
        int op = L->tok.kind;
        int line = L->tok.line;
        lex_next(L);
        Node *b = node_new(N_BIN, line);
        b->op = op;
        b->a = n;
        b->b = parse_term(L);
        n = b;
    }
    return n;
}

static Node *parse_cmp(Lexer *L) {
    Node *n = parse_shift(L);
    while (L->tok.kind == T_LT || L->tok.kind == T_GT || L->tok.kind == T_LE || L->tok.kind == T_GE) {
        int op = L->tok.kind;
        int line = L->tok.line;
        lex_next(L);
        Node *b = node_new(N_BIN, line);
        b->op = op;
        b->a = n;
        b->b = parse_term(L);
        n = b;
    }
    return n;
}

static Node *parse_eq(Lexer *L) {
    Node *n = parse_cmp(L);
    while (L->tok.kind == T_EQEQ || L->tok.kind == T_NE) {
        int op = L->tok.kind;
        int line = L->tok.line;
        lex_next(L);
        Node *b = node_new(N_BIN, line);
        b->op = op;
        b->a = n;
        b->b = parse_cmp(L);
        n = b;
    }
    return n;
}

static Node *parse_bitand(Lexer *L) {
    Node *n = parse_eq(L);
    while (L->tok.kind == T_AMP) {
        int line = L->tok.line;
        lex_next(L);
        Node *b = node_new(N_BIN, line);
        b->op = T_AMP;
        b->a = n;
        b->b = parse_eq(L);
        n = b;
    }
    return n;
}

static Node *parse_bitxor(Lexer *L) {
    Node *n = parse_bitand(L);
    while (L->tok.kind == T_CARET) {
        int line = L->tok.line;
        lex_next(L);
        Node *b = node_new(N_BIN, line);
        b->op = T_CARET;
        b->a = n;
        b->b = parse_bitand(L);
        n = b;
    }
    return n;
}

static Node *parse_bitor(Lexer *L) {
    Node *n = parse_bitxor(L);
    while (L->tok.kind == T_PIPE) {
        int line = L->tok.line;
        lex_next(L);
        Node *b = node_new(N_BIN, line);
        b->op = T_PIPE;
        b->a = n;
        b->b = parse_bitxor(L);
        n = b;
    }
    return n;
}

static Node *parse_and(Lexer *L) {
    Node *n = parse_bitor(L);
    while (L->tok.kind == T_ANDAND) {
        int line = L->tok.line;
        lex_next(L);
        Node *b = node_new(N_BIN, line);
        b->op = T_ANDAND;
        b->a = n;
        b->b = parse_bitor(L);
        n = b;
    }
    return n;
}

static Node *parse_expr(Lexer *L) {
    Node *n = parse_and(L);
    while (L->tok.kind == T_OROR) {
        int line = L->tok.line;
        lex_next(L);
        Node *b = node_new(N_BIN, line);
        b->op = T_OROR;
        b->a = n;
        b->b = parse_and(L);
        n = b;
    }
    if (L->tok.kind == T_QUEST) {
        int line = L->tok.line;
        lex_next(L);
        Node *t = node_new(N_IF, line);
        t->a = n;
        t->b = parse_expr(L);
        expect(L, T_COLON, "':'");
        t->c = parse_expr(L);
        t->num = 1;
        return t;
    }
    return n;
}

static Node *parse_block(Lexer *L);

static Node *parse_stmt(Lexer *L) {
    Token t = L->tok;
    if (t.kind == T_LET) {
        lex_next(L);
        if (L->tok.kind != T_IDENT) {
            error_at(L->tok.line, L->tok.col, "expected name after let");
            g_panic = 1;
            sync_stmt(L);
            return node_new(N_EXPRSTMT, t.line);
        }
        Node *n = node_new(N_LET, t.line);
        n->name = xstrdup(L->tok.text);
        lex_next(L);
        if (L->tok.kind == T_COLON) {
            lex_next(L);
            if (L->tok.kind != T_IDENT) {
                error_at(L->tok.line, L->tok.col, "expected int, str, or ptr");
                g_panic = 1;
            } else if (!strcmp(L->tok.text, "int")) n->op = 1;
            else if (!strcmp(L->tok.text, "str")) n->op = -1;
            else if (!strcmp(L->tok.text, "ptr")) n->op = -2;
            else error_at(L->tok.line, L->tok.col, "unknown type '%s'", L->tok.text);
            if (L->tok.kind == T_IDENT) lex_next(L);
        }
        if (L->tok.kind == T_LBRACK) {
            lex_next(L);
            if (L->tok.kind != T_NUM || L->tok.num < 1 || L->tok.num > 64)
                fail_at(L->tok.line, L->tok.col, "array length must be a constant from 1 to 64");
            n->num = L->tok.num;
            lex_next(L);
            expect(L, T_RBRACK, "']'");
            expect(L, T_SEMI, "';'");
            return n;
        }
        expect(L, T_EQ, "'='");
        n->a = parse_expr(L);
        expect(L, T_SEMI, "';'");
        return n;
    }
    if (t.kind == T_PRINT || t.kind == T_EXEC) {
        int is_exec = t.kind == T_EXEC;
        lex_next(L);
        expect(L, T_LPAREN, "'('");
        Node *n = node_new(is_exec ? N_EXEC : N_PRINT, t.line);
        n->a = parse_expr(L);
        expect(L, T_RPAREN, "')'");
        expect(L, T_SEMI, "';'");
        return n;
    }
    if (t.kind == T_RETURN) {
        lex_next(L);
        Node *n = node_new(N_RETURN, t.line);
        n->a = parse_expr(L);
        expect(L, T_SEMI, "';'");
        return n;
    }
    if (t.kind == T_IF) {
        lex_next(L);
        expect(L, T_LPAREN, "'('");
        Node *n = node_new(N_IF, t.line);
        n->a = parse_expr(L);
        expect(L, T_RPAREN, "')'");
        n->b = parse_block(L);
        if (L->tok.kind == T_ELSE) {
            lex_next(L);
            /* else if (...) is a statement, not a bare block. */
            if (L->tok.kind == T_IF) n->c = parse_stmt(L);
            else n->c = parse_block(L);
        }
        return n;
    }
    if (t.kind == T_SWITCH) {
        lex_next(L);
        expect(L, T_LPAREN, "'('");
        Node *n = node_new(N_SWITCH, t.line);
        n->a = parse_expr(L);
        expect(L, T_RPAREN, "')'");
        expect(L, T_LBRACE, "'{'");
        while (L->tok.kind != T_RBRACE && L->tok.kind != T_EOF) {
            Node *arm = node_new(N_SWITCH, L->tok.line);
            if (L->tok.kind == T_CASE) {
                lex_next(L);
                if (L->tok.kind != T_NUM) die("line %d: case wants a constant", L->tok.line);
                arm->num = L->tok.num;
                lex_next(L);
                expect(L, T_COLON, "':'");
            } else if (L->tok.kind == T_DEFAULT) {
                lex_next(L);
                expect(L, T_COLON, "':'");
                arm->num = LONG_MIN;
            } else {
                die("line %d: expected case or default", L->tok.line);
            }
            arm->a = parse_stmt(L);
            node_add(n, arm);
        }
        expect(L, T_RBRACE, "'}'");
        return n;
    }
    if (t.kind == T_WHILE) {
        lex_next(L);
        expect(L, T_LPAREN, "'('");
        Node *n = node_new(N_WHILE, t.line);
        n->a = parse_expr(L);
        expect(L, T_RPAREN, "')'");
        n->b = parse_block(L);
        return n;
    }
    if (t.kind == T_DO) {
        lex_next(L);
        Node *n = node_new(N_WHILE, t.line);
        n->num = 1;
        n->b = parse_block(L);
        expect(L, T_WHILE, "'while'");
        expect(L, T_LPAREN, "'('");
        n->a = parse_expr(L);
        expect(L, T_RPAREN, "')'");
        expect(L, T_SEMI, "';'");
        return n;
    }
    if (t.kind == T_FOR) {
        /* for let i = 0; i < n; i = i + 1 { ... } */
        lex_next(L);
        Node *n = node_new(N_FOR, t.line);
        n->a = parse_stmt(L);
        n->b = parse_expr(L);
        expect(L, T_SEMI, "';'");
        if (L->tok.kind != T_IDENT) die("line %d: for step wants name = expr", L->tok.line);
        {
            char *name = xstrdup(L->tok.text);
            int line = L->tok.line;
            lex_next(L);
            expect(L, T_EQ, "'='");
            Node *st = node_new(N_ASSIGN, line);
            st->name = name;
            st->a = parse_expr(L);
            if (L->tok.kind == T_SEMI) lex_next(L);
            n->c = st;
        }
        node_add(n, parse_block(L));
        return n;
    }
    if (t.kind == T_STAR) {
        Node *dest = parse_unary(L);
        expect(L, T_EQ, "'='");
        Node *n = node_new(N_STORE, t.line);
        n->a = dest;
        n->b = parse_expr(L);
        expect(L, T_SEMI, "';'");
        return n;
    }
    if (t.kind == T_BREAK) {
        lex_next(L);
        expect(L, T_SEMI, "';'");
        return node_new(N_BREAK, t.line);
    }
    if (t.kind == T_CONTINUE) {
        lex_next(L);
        expect(L, T_SEMI, "';'");
        return node_new(N_CONTINUE, t.line);
    }
    if (t.kind == T_LBRACE) return parse_block(L);
    if (t.kind == T_IDENT) {
        char *name = xstrdup(t.text);
        int line = t.line;
        lex_next(L);
        if (L->tok.kind == T_DOT || L->tok.kind == T_ARROW) {
            int arrow = L->tok.kind == T_ARROW;
            lex_next(L);
            if (L->tok.kind != T_IDENT) die("line %d: expected field name", L->tok.line);
            Node *n = node_new(N_ASSIGN, line);
            n->name = name;
            n->str = xstrdup(L->tok.text);
            n->num = arrow;
            lex_next(L);
            expect(L, T_EQ, "'='");
            n->a = parse_expr(L);
            expect(L, T_SEMI, "';'");
            return n;
        }
        if (L->tok.kind == T_LBRACK) {
            lex_next(L);
            Node *n = node_new(N_ASSIGN, line);
            n->name = name;
            n->a = parse_expr(L);
            expect(L, T_RBRACK, "']'");
            expect(L, T_EQ, "'='");
            n->b = parse_expr(L);
            expect(L, T_SEMI, "';'");
            return n;
        }
        if (L->tok.kind == T_EQ) {
            lex_next(L);
            Node *n = node_new(N_ASSIGN, line);
            n->name = name;
            n->a = parse_expr(L);
            expect(L, T_SEMI, "';'");
            return n;
        }
        if (L->tok.kind == T_PLUSEQ || L->tok.kind == T_MINUSEQ || L->tok.kind == T_STAREQ) {
            int op = L->tok.kind;
            lex_next(L);
            Node *n = node_new(N_ASSIGN, line);
            n->name = name;
            n->op = op;
            n->a = parse_expr(L);
            expect(L, T_SEMI, "';'");
            return n;
        }
        if (L->tok.kind == T_INC || L->tok.kind == T_DEC) {
            Node *n = node_new(N_EXPRSTMT, line);
            Node *u = node_new(N_UNARY, line);
            u->op = L->tok.kind;
            u->num = 1;
            u->a = node_new(N_VAR, line);
            u->a->name = name;
            lex_next(L);
            expect(L, T_SEMI, "';'");
            n->a = u;
            return n;
        }
        if (L->tok.kind == T_LPAREN) {
            Node *n = node_new(N_EXPRSTMT, line);
            Node *c = node_new(N_CALL, line);
            c->name = name;
            parse_args(L, c);
            expect(L, T_SEMI, "';'");
            n->a = c;
            return n;
        }
        error_at(line, t.col, "expected '=' or '(' after name");
        g_panic = 1;
        sync_stmt(L);
        return node_new(N_EXPRSTMT, line);
    }
    error_at(t.line, t.col, "expected statement");
    g_panic = 1;
    sync_stmt(L);
    return node_new(N_EXPRSTMT, t.line);
}

static Node *parse_block(Lexer *L) {
    int line = L->tok.line;
    expect(L, T_LBRACE, "'{'");
    Node *n = node_new(N_BLOCK, line);
    while (L->tok.kind != T_RBRACE && L->tok.kind != T_EOF) {
        if (g_panic) sync_stmt(L);
        if (L->tok.kind == T_RBRACE || L->tok.kind == T_EOF) break;
        int before = g_err;
        Node *s = parse_stmt(L);
        (void)before;
        if (g_panic) sync_stmt(L);
        if (s) node_add(n, s);
    }
    expect(L, T_RBRACE, "'}'");
    return n;
}

static void parse_struct(Lexer *L) {
    expect(L, T_STRUCT, "'struct'");
    if (L->tok.kind != T_IDENT) die("line %d: expected struct name", L->tok.line);
    if (g_nsd >= 16) die("too many structs");
    SDef *s = &g_sd[g_nsd];
    memset(s, 0, sizeof(*s));
    s->name = xstrdup(L->tok.text);
    lex_next(L);
    expect(L, T_LBRACE, "'{'");
    while (L->tok.kind == T_IDENT) {
        if (s->nfields >= 8) die("line %d: at most 8 fields", L->tok.line);
        s->fields[s->nfields++] = xstrdup(L->tok.text);
        lex_next(L);
        expect(L, T_SEMI, "';'");
    }
    if (s->nfields < 1) die("struct %s has no fields", s->name);
    expect(L, T_RBRACE, "'}'");
    g_nsd++;
}

typedef struct { char *name; long init; int kind; } Glob;
static Glob g_globs[32];
static int g_nglobs;

static int glob_find(const char *name) {
    for (int i = 0; i < g_nglobs; i++) if (!strcmp(g_globs[i].name, name)) return i;
    return -1;
}

static void parse_global(Lexer *L) {
    expect(L, T_LET, "'let'");
    if (L->tok.kind != T_IDENT) die("line %d: expected global name", L->tok.line);
    if (g_nglobs >= 32) die("too many globals");
    g_globs[g_nglobs].name = xstrdup(L->tok.text);
    lex_next(L);
    expect(L, T_EQ, "'='");
    if (L->tok.kind != T_NUM) die("line %d: global must be an integer constant", L->tok.line);
    g_globs[g_nglobs].init = L->tok.num;
    g_nglobs++;
    lex_next(L);
    expect(L, T_SEMI, "';'");
}

static void parse_enum(Lexer *L) {
    expect(L, T_ENUM, "'enum'");
    if (L->tok.kind != T_IDENT) die("line %d: expected enum name", L->tok.line);
    lex_next(L);
    expect(L, T_LBRACE, "'{'");
    long v = 0;
    if (L->tok.kind == T_RBRACE) die("line %d: empty enum", L->tok.line);
    for (;;) {
        if (L->tok.kind != T_IDENT) die("line %d: expected enum constant", L->tok.line);
        if (g_nmacros >= 64) die("too many constants");
        char *name = xstrdup(L->tok.text);
        lex_next(L);
        if (L->tok.kind == T_EQ) {
            lex_next(L);
            if (L->tok.kind != T_NUM) die("line %d: enum wants an integer", L->tok.line);
            v = L->tok.num;
            lex_next(L);
        }
        g_macros[g_nmacros].name = name;
        g_macros[g_nmacros].val = v;
        g_nmacros++;
        v++;
        if (L->tok.kind != T_COMMA) break;
        lex_next(L);
        if (L->tok.kind == T_RBRACE) break;
    }
    expect(L, T_RBRACE, "'}'");
}

static Node *parse_program(Lexer *L) {
    Node *p = node_new(N_PROGRAM, 1);
    while (L->tok.kind != T_EOF) {
        if (L->tok.kind == T_STRUCT) {
            parse_struct(L);
            continue;
        }
        if (L->tok.kind == T_ENUM) {
            parse_enum(L);
            continue;
        }
        if (L->tok.kind == T_LET) {
            parse_global(L);
            continue;
        }
        int line = L->tok.line;
        expect(L, T_FN, "'fn'");
        if (L->tok.kind != T_IDENT) die("expected function name");
        Node *fn = node_new(N_FN, line);
        fn->name = xstrdup(L->tok.text);
        lex_next(L);
        expect(L, T_LPAREN, "'('");
        if (L->tok.kind != T_RPAREN) {
            for (;;) {
                if (L->tok.kind != T_IDENT) die("line %d: expected parameter name", L->tok.line);
                Node *param = node_new(N_VAR, L->tok.line);
                param->name = xstrdup(L->tok.text);
                lex_next(L);
                if (L->tok.kind == T_COLON) {
                    lex_next(L);
                    if (L->tok.kind == T_IDENT && !strcmp(L->tok.text, "int")) param->op = 1;
                    else if (L->tok.kind == T_IDENT && !strcmp(L->tok.text, "str")) param->op = -1;
                    else if (L->tok.kind == T_IDENT && !strcmp(L->tok.text, "ptr")) param->op = -2;
                    else error_at(L->tok.line, L->tok.col, "expected int, str, or ptr");
                    if (L->tok.kind == T_IDENT) lex_next(L);
                }
                node_add(fn, param);
                if (L->tok.kind != T_COMMA) break;
                lex_next(L);
            }
        }
        if (fn->nkids > 6) die("line %d: at most 6 parameters", line);
        if (strcmp(fn->name, "main") == 0 && fn->nkids != 0)
            die("line %d: main() takes no parameters", line);
        expect(L, T_RPAREN, "')'");
        if (L->tok.kind == T_COLON) {
            lex_next(L);
            if (L->tok.kind == T_IDENT && !strcmp(L->tok.text, "int")) fn->op = 1;
            else if (L->tok.kind == T_IDENT && !strcmp(L->tok.text, "str")) fn->op = -1;
            else if (L->tok.kind == T_IDENT && !strcmp(L->tok.text, "ptr")) fn->op = -2;
            else error_at(L->tok.line, L->tok.col, "expected int, str, or ptr");
            if (L->tok.kind == T_IDENT) lex_next(L);
        }
        fn->a = parse_block(L);
        node_add(p, fn);
    }
    return p;
}

static int fn_arity(const char *name) {
    for (int i = 0; i < g_nfn; i++)
        if (strcmp(g_fns[i], name) == 0) return g_arity[i];
    return -1;
}

static void collect_fns(Node *p) {
    g_nfn = p->nkids;
    g_fns = calloc((size_t)g_nfn, sizeof(char *));
    g_arity = calloc((size_t)g_nfn, sizeof(int));
    g_pty = calloc((size_t)g_nfn * 6, sizeof(int));
    if (!g_fns || !g_arity || !g_pty) die("out of memory");
    int saw_main = 0;
    for (int i = 0; i < p->nkids; i++) {
        g_fns[i] = p->kids[i]->name;
        g_arity[i] = p->kids[i]->nkids;
        for (int a = 0; a < p->kids[i]->nkids && a < 6; a++)
            g_pty[i * 6 + a] = p->kids[i]->kids[a]->op;
        if (strcmp(p->kids[i]->name, "main") == 0) saw_main = 1;
        for (int j = 0; j < i; j++) {
            if (strcmp(g_fns[j], g_fns[i]) == 0)
                die("duplicate function '%s'", g_fns[i]);
        }
    }
    if (!saw_main) die("no main() — even revolutions need an entry point");
}

static int local_find(FnCtx *fn, const char *name) {
    for (int i = 0; i < fn->nlocals; i++)
        if (strcmp(fn->locals[i].name, name) == 0) return i;
    return -1;
}

static int local_add_slots(FnCtx *fn, const char *name, int line, int count, int is_array) {
    if (local_find(fn, name) >= 0) fail_at(line, col_of(line, name), "'%s' already declared", name);
    if (count < 1) die("line %d: bad slot count", line);
    if (fn->nlocals >= 64) die("line %d: too many names", line);
    if (fn->slots + count > 64) die("line %d: too many locals (limit 64 slots)", line);
    int off = (fn->slots + 1) * 8;
    fn->locals[fn->nlocals].name = xstrdup(name);
    fn->locals[fn->nlocals].offset = off;
    fn->locals[fn->nlocals].len = is_array ? count : 0;
    fn->locals[fn->nlocals].declared = 0;
    fn->nlocals++;
    fn->slots += count;
    fn->stack = (fn->slots * 8 + 15) & ~15;
    return fn->nlocals - 1;
}

static int local_add(FnCtx *fn, const char *name, int line) {
    return local_add_slots(fn, name, line, 1, 0);
}

static int col_of(int line, const char *name) {
    if (!g_src || !name || line < 1) return 1;
    int n = 1;
    const char *p = g_src;
    while (*p && n < line) {
        if (*p == '\n') n++;
        p++;
    }
    const char *hit = strstr(p, name);
    if (!hit) return 1;
    return (int)(hit - p) + 1;
}

static void require_declared(FnCtx *fn, const char *name, int line) {
    int i = local_find(fn, name);
    if (i < 0) {
        error_at(line, col_of(line, name), "unknown name '%s'", name);
        die("aborting after %d error%s", g_err, g_err == 1 ? "" : "s");
    }
    if (!fn->locals[i].declared) {
        error_at(line, col_of(line, name), "'%s' used before declaration", name);
        die("aborting after %d error%s", g_err, g_err == 1 ? "" : "s");
    }
}

static void scan_locals(FnCtx *fn, Node *n) {
    if (!n) return;
    if (n->kind == N_LET) {
        if (n->num > 0) {
            local_add_slots(fn, n->name, n->line, (int)n->num, 1);
        } else {
            int slot = local_add(fn, n->name, n->line);
            if (n->op == -1) fn->locals[slot].len = -1;
            else if (n->op == -2) fn->locals[slot].len = -2;
            else if (n->a && n->a->kind == N_STR) fn->locals[slot].len = -1;
            else if (n->a && n->a->kind == N_ADDR) {
                fn->locals[slot].len = -2;
                int j = local_find(fn, n->a->name);
                if (j >= 0 && fn->locals[j].len == -3) fn->locals[slot].aux = fn->locals[j].aux;
            }
            else if (n->a && n->a->kind == N_CALL && n->a->name && !strcmp(n->a->name, "alloc"))
                fn->locals[slot].len = -2;
            else if (n->a && n->a->kind == N_CALL && n->a->name && !strcmp(n->a->name, "load"))
                fn->locals[slot].len = -1;
            else if (n->a && n->a->kind == N_VAR) {
                int sid = struct_find(n->a->name);
                if (sid >= 0) {
                    /* replace the one-slot local with a struct */
                    fn->nlocals--;
                    fn->slots--;
                    int slot2 = local_add_slots(fn, n->name, n->line, g_sd[sid].nfields, 0);
                    fn->locals[slot2].len = -3;
                    fn->locals[slot2].aux = sid;
                } else if (fn_arity(n->a->name) >= 0) {
                    fn->locals[slot].len = -4;
                } else {
                    int j = local_find(fn, n->a->name);
                    if (j >= 0) fn->locals[slot].len = fn->locals[j].len < 0 ? fn->locals[j].len : 0;
                }
            }
        }
    }
    if (n->kind == N_BLOCK || n->kind == N_FOR) {
        for (int i = 0; i < n->nkids; i++) scan_locals(fn, n->kids[i]);
        if (n->kind == N_FOR) {
            scan_locals(fn, n->a);
            scan_locals(fn, n->b);
            scan_locals(fn, n->c);
        }
    } else {
        scan_locals(fn, n->a);
        scan_locals(fn, n->b);
        scan_locals(fn, n->c);
        for (int i = 0; i < n->nkids; i++) scan_locals(fn, n->kids[i]);
    }
}

static void emit(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(g_out, fmt, ap);
    va_end(ap);
    fputc('\n', g_out);
}

static void emit_push(const char *reg) {
    emit("    push %s", reg);
    g_depth++;
}

static void emit_pop(const char *reg) {
    emit("    pop %s", reg);
    g_depth--;
}

/* RSP must be 16-byte aligned immediately before CALL. */
static void emit_call(const char *sym) {
    if (g_depth & 1) {
        emit("    sub $8, %%rsp");
        emit("    call %s", sym);
        emit("    add $8, %%rsp");
    } else {
        emit("    call %s", sym);
    }
}

static int newlbl(void) { return g_lbl++; }

static int str_id;
typedef struct { int id; char *s; } StrEnt;
static StrEnt *g_strs;
static int g_nstr, g_strcap;
static void remember_str(int id, const char *s);

static void gen_expr(Node *n);

static int expr_is_ptr(Node *n) {
    if (!n) return 0;
    if (n->kind == N_BIN && (n->op == T_PLUS || n->op == T_MINUS))
        return expr_is_ptr(n->a) || expr_is_ptr(n->b);
    if (n->kind == N_ADDR) return 1;
    if (n->kind == N_CALL && n->name && !strcmp(n->name, "alloc")) return 1;
    if (n->kind == N_VAR) {
        int i = local_find(g_fn, n->name);
        if (i >= 0 && g_fn->locals[i].len == -2) return 1;
    }
    return 0;
}

static int expr_is_str(Node *n) {
    if (!n) return 0;
    if (n->kind == N_STR) return 1;
    if (n->kind == N_CALL && n->name && !strcmp(n->name, "load")) return 1;
    if (n->kind == N_VAR) {
        int i = local_find(g_fn, n->name);
        if (i >= 0 && g_fn->locals[i].len == -1) return 1;
    }
    return 0;
}

static void gen_cmp(int op, int dest) {
    const char *cc = "e";
    switch (op) {
        case T_EQEQ: cc = "e"; break;
        case T_NE: cc = "ne"; break;
        case T_LT: cc = "l"; break;
        case T_GT: cc = "g"; break;
        case T_LE: cc = "le"; break;
        case T_GE: cc = "ge"; break;
    }
    emit("    cmp %%rcx, %%rax");
    emit("    set%s %%al", cc);
    emit("    movzx %%al, %%eax");
    (void)dest;
}

static void gen_expr(Node *n) {
    switch (n->kind) {
        case N_NUM:
            emit("    mov $%ld, %%rax", n->num);
            return;
        case N_VAR: {
            int i = local_find(g_fn, n->name);
            if (i < 0) {
                if (fn_arity(n->name) >= 0) {
                    emit("    lea rexfn_%s(%%rip), %%rax", n->name);
                    return;
                }
                int g = glob_find(n->name);
                if (g < 0) {
                    error_at(n->line, col_of(n->line, n->name), "unknown name '%s'", n->name);
                    die("aborting after %d error%s", g_err, g_err == 1 ? "" : "s");
                }
                emit("    mov rex_g_%s(%%rip), %%rax", n->name);
                return;
            }
            require_declared(g_fn, n->name, n->line);
            if (g_fn->locals[i].len > 0)
                fail_at(n->line, col_of(n->line, n->name), "array '%s' is not an integer", n->name);
            if (g_fn->locals[i].len == -3)
                fail_at(n->line, col_of(n->line, n->name), "struct '%s' is not an integer", n->name);
            emit("    mov -%d(%%rbp), %%rax", g_fn->locals[i].offset);
            return;
        }
        case N_ADDR: {
            require_declared(g_fn, n->name, n->line);
            int i = local_find(g_fn, n->name);
            if (g_fn->locals[i].len > 0 || g_fn->locals[i].len == -1)
                die("line %d: cannot take the address of '%s'", n->line, n->name);
            emit("    lea -%d(%%rbp), %%rax", g_fn->locals[i].offset);
            return;
        }
        case N_FIELD: {
            if (!n->a || n->a->kind != N_VAR) die("line %d: field wants a name", n->line);
            require_declared(g_fn, n->a->name, n->line);
            int i = local_find(g_fn, n->a->name);
            if (n->num) {
                if (g_fn->locals[i].len != -2 || g_fn->locals[i].aux < 0)
                    die("line %d: '%s' is not a struct pointer", n->line, n->a->name);
                int fi = field_find(g_fn->locals[i].aux, n->name);
                if (fi < 0) die("line %d: no field '%s'", n->line, n->name);
                emit("    mov -%d(%%rbp), %%rax", g_fn->locals[i].offset);
                if (fi == 0) emit("    mov (%%rax), %%rax");
                else emit("    mov -%d(%%rax), %%rax", fi * 8);
                return;
            }
            if (g_fn->locals[i].len != -3) die("line %d: '%s' is not a struct", n->line, n->a->name);
            int fi = field_find(g_fn->locals[i].aux, n->name);
            if (fi < 0) die("line %d: no field '%s'", n->line, n->name);
            emit("    mov -%d(%%rbp), %%rax", g_fn->locals[i].offset + fi * 8);
            return;
        }
        case N_INDEX: {
            int i = local_find(g_fn, n->name);
            int g = -1;
            if (i < 0) {
                g = glob_find(n->name);
                if (g < 0) {
                    error_at(n->line, col_of(n->line, n->name), "unknown name '%s'", n->name);
                    die("aborting after %d error%s", g_err, g_err == 1 ? "" : "s");
                }
            } else require_declared(g_fn, n->name, n->line);
            int bad = newlbl();
            int ok = newlbl();
            int id = str_id++;
            remember_str(id, "index out of range");
            int heap = 0;
            if (i >= 0 && (g_fn->locals[i].len == -2 || !strcmp(n->name, "names") || !strcmp(n->name, "lens") || !strcmp(n->name, "offs") || !strcmp(n->name, "firsts"))) heap = 1;
            if (g >= 0 && (g_globs[g].kind == 2 || !strcmp(n->name, "names") || !strcmp(n->name, "lens") || !strcmp(n->name, "offs") || !strcmp(n->name, "firsts"))) heap = 1;
            if (heap) {
                gen_expr(n->a);
                emit_push("%rax");
                if (g >= 0) emit("    mov rex_g_%s(%%rip), %%rax", n->name);
                else emit("    mov -%d(%%rbp), %%rax", g_fn->locals[i].offset);
                emit("    mov -8(%%rax), %%rdx");
                emit_pop("%rcx");
                emit("    cmp $0, %%rcx");
                emit("    jl .L%d", bad);
                emit("    cmp %%rdx, %%rcx");
                emit("    jl .L%d", ok);
                emit(".L%d:", bad);
                emit("    lea .LS%d(%%rip), %%rdi", id);
                emit_call("rex_fail");
                emit(".L%d:", ok);
                if (g >= 0) emit("    mov rex_g_%s(%%rip), %%rax", n->name);
                else emit("    mov -%d(%%rbp), %%rax", g_fn->locals[i].offset);
                emit("    mov (%%rax,%%rcx,8), %%rax");
                return;
            }
            if (i >= 0 && g_fn->locals[i].len > 0) {
                gen_expr(n->a);
                emit("    cmp $0, %%rax");
                emit("    jl .L%d", bad);
                emit("    cmp $%d, %%rax", g_fn->locals[i].len);
                emit("    jl .L%d", ok);
                emit(".L%d:", bad);
                emit("    lea .LS%d(%%rip), %%rdi", id);
                emit_call("rex_fail");
                emit(".L%d:", ok);
                emit("    imul $8, %%rax");
                emit("    neg %%rax");
                emit("    mov -%d(%%rbp, %%rax), %%rax", g_fn->locals[i].offset);
                return;
            }
            gen_expr(n->a);
            emit_push("%rax");
            if (g >= 0) emit("    mov rex_g_%s(%%rip), %%rdi", n->name);
            else emit("    mov -%d(%%rbp), %%rdi", g_fn->locals[i].offset);
            emit_call("rex_strlen");
            emit("    mov %%rax, %%rcx");
            emit_pop("%rax");
            emit("    cmp $0, %%rax");
            emit("    jl .L%d", bad);
            emit("    cmp %%rcx, %%rax");
            emit("    jle .L%d", ok);
            emit("    xor %%eax, %%eax");
            emit("    jmp .L%d", ok);
            emit(".L%d:", bad);
            emit("    lea .LS%d(%%rip), %%rdi", id);
            emit_call("rex_fail");
            emit(".L%d:", ok);
            emit("    mov %%rax, %%rcx");
            if (g >= 0) emit("    mov rex_g_%s(%%rip), %%rax", n->name);
            else emit("    mov -%d(%%rbp), %%rax", g_fn->locals[i].offset);
            emit("    movzbl (%%rax,%%rcx), %%eax");
            return;
        }
        case N_READ:
            emit_call("rex_read_int");
            return;
        case N_CALL: {
            if (strcmp(n->name, "len") == 0) {
                if (n->nkids != 1 || n->kids[0]->kind != N_VAR)
                    die("line %d: len() wants a name", n->line);
                require_declared(g_fn, n->kids[0]->name, n->line);
                int i = local_find(g_fn, n->kids[0]->name);
                if (g_fn->locals[i].len > 0) {
                    emit("    mov $%d, %%rax", g_fn->locals[i].len);
                    return;
                }
                if (g_fn->locals[i].len == -1) {
                    emit("    mov -%d(%%rbp), %%rdi", g_fn->locals[i].offset);
                    emit_call("rex_strlen");
                    return;
                }
                if (g_fn->locals[i].len == -2) {
                    emit("    mov -%d(%%rbp), %%rax", g_fn->locals[i].offset);
                    emit("    mov -8(%%rax), %%rax");
                    return;
                }
                die("line %d: len() wants an array, string, or heap block", n->line);
            }
            if (strcmp(n->name, "putc") == 0) {
                if (n->nkids != 1) die("line %d: putc() wants a character", n->line);
                gen_expr(n->kids[0]);
                emit("    mov %%rax, %%rdi");
                emit_call("rex_putc");
                return;
            }
            if (strcmp(n->name, "putn") == 0) {
                if (n->nkids != 1) die("line %d: putn() wants a number", n->line);
                gen_expr(n->kids[0]);
                emit("    mov %%rax, %%rdi");
                emit_call("rex_put_int");
                return;
            }
            if (strcmp(n->name, "put") == 0) {
                if (n->nkids != 1 || !expr_is_str(n->kids[0])) die("line %d: put() wants a string", n->line);
                gen_expr(n->kids[0]);
                emit("    mov %%rax, %%rdi");
                emit_call("rex_put_str");
                return;
            }
            if (strcmp(n->name, "load") == 0) {
                if (n->nkids != 1 || !expr_is_str(n->kids[0])) die("line %d: load() wants a path", n->line);
                gen_expr(n->kids[0]);
                emit("    mov %%rax, %%rdi");
                emit_call("rex_load");
                return;
            }
            if (strcmp(n->name, "alloc") == 0) {
                if (n->nkids != 1) die("line %d: alloc() wants one count", n->line);
                gen_expr(n->kids[0]);
                emit("    mov %%rax, %%rdi");
                emit_call("rex_alloc");
                return;
            }
            if (strcmp(n->name, "free") == 0) {
                if (n->nkids != 1) die("line %d: free() wants one pointer", n->line);
                gen_expr(n->kids[0]);
                emit("    mov %%rax, %%rdi");
                emit_call("rex_free");
                return;
            }
            int want = fn_arity(n->name);
            if (want < 0) {
                int slot = local_find(g_fn, n->name);
                if (slot < 0 || g_fn->locals[slot].len != -4)
                    fail_at(n->line, col_of(n->line, n->name), "unknown function '%s'", n->name);
                static const char *ireg[] = {"%rdi", "%rsi", "%rdx", "%rcx", "%r8", "%r9"};
                for (int i = 0; i < n->nkids; i++) {
                    gen_expr(n->kids[i]);
                    emit_push("%rax");
                }
                for (int i = n->nkids - 1; i >= 0; i--) emit_pop(ireg[i]);
                emit("    mov -%d(%%rbp), %%rax", g_fn->locals[slot].offset);
                if (g_depth & 1) {
                    emit("    sub $8, %%rsp");
                    emit("    call *%%rax");
                    emit("    add $8, %%rsp");
                } else {
                    emit("    call *%%rax");
                }
                return;
            }
            if (strcmp(n->name, "main") == 0) fail_at(n->line, col_of(n->line, "main"), "do not call main");
            if (want != n->nkids)
                fail_at(n->line, col_of(n->line, n->name), "%s() wants %d argument%s, got %d", n->name, want, want == 1 ? "" : "s", n->nkids);
            static const char *areg[] = {"%rdi", "%rsi", "%rdx", "%rcx", "%r8", "%r9"};
            for (int i = 0; i < n->nkids; i++) {
                gen_expr(n->kids[i]);
                emit_push("%rax");
            }
            for (int i = n->nkids - 1; i >= 0; i--) emit_pop(areg[i]);
            char sym[128];
            snprintf(sym, sizeof(sym), "rexfn_%s", n->name);
            emit_call(sym);
            return;
        }
        case N_IF:
            if (n->num) {
                int els = newlbl();
                int end = newlbl();
                gen_expr(n->a);
                emit("    cmp $0, %%rax");
                emit("    je .L%d", els);
                gen_expr(n->b);
                emit("    jmp .L%d", end);
                emit(".L%d:", els);
                gen_expr(n->c);
                emit(".L%d:", end);
                return;
            }
            die("line %d: not an expression", n->line);
            return;
        case N_UNARY:
            if (n->op == T_INC || n->op == T_DEC) {
                if (!n->a || n->a->kind != N_VAR) die("line %d: ++ and -- want a name", n->line);
                require_declared(g_fn, n->a->name, n->line);
                int i = local_find(g_fn, n->a->name);
                if (g_fn->locals[i].len != 0) die("line %d: ++ wants an integer", n->line);
                if (n->num) emit("    mov -%d(%%rbp), %%rax", g_fn->locals[i].offset);
                emit("    mov -%d(%%rbp), %%rcx", g_fn->locals[i].offset);
                if (n->op == T_INC) emit("    add $1, %%rcx");
                else emit("    sub $1, %%rcx");
                emit("    mov %%rcx, -%d(%%rbp)", g_fn->locals[i].offset);
                if (!n->num) emit("    mov %%rcx, %%rax");
                return;
            }
            if (expr_is_str(n->a)) die("line %d: string is not a number", n->line);
            gen_expr(n->a);
            if (n->op == T_STAR) {
                emit("    mov (%%rax), %%rax");
            } else if (n->op == T_BANG) {
                emit("    cmp $0, %%rax");
                emit("    sete %%al");
                emit("    movzx %%al, %%eax");
            } else if (n->op == T_TILDE) {
                emit("    not %%rax");
            } else {
                emit("    neg %%rax");
            }
            return;
        case N_BIN:
            if ((n->op == T_EQEQ || n->op == T_NE) && (expr_is_str(n->a) || expr_is_str(n->b))) {
                gen_expr(n->a);
                emit("    mov %%rax, %%rdi");
                emit_push("%rdi");
                gen_expr(n->b);
                emit("    mov %%rax, %%rsi");
                emit_pop("%rdi");
                emit_call("rex_strcmp");
                emit("    cmp $0, %%rax");
                if (n->op == T_EQEQ) emit("    sete %%al");
                else emit("    setne %%al");
                emit("    movzx %%al, %%eax");
                return;
            }
            if (expr_is_str(n->a) || expr_is_str(n->b))
                die("line %d: string is not a number", n->line);
            if (n->op == T_ANDAND || n->op == T_OROR) {
                int skip = newlbl();
                int end = newlbl();
                gen_expr(n->a);
                emit("    cmp $0, %%rax");
                if (n->op == T_ANDAND) {
                    emit("    je .L%d", end);
                    gen_expr(n->b);
                    emit(".L%d:", end);
                    emit("    cmp $0, %%rax");
                    emit("    setne %%al");
                    emit("    movzx %%al, %%eax");
                } else {
                    emit("    jne .L%d", skip);
                    gen_expr(n->b);
                    emit("    cmp $0, %%rax");
                    emit("    je .L%d", end);
                    emit(".L%d:", skip);
                    emit("    mov $1, %%rax");
                    emit(".L%d:", end);
                }
                return;
            }
            gen_expr(n->a);
            emit_push("%rax");
            gen_expr(n->b);
            emit("    mov %%rax, %%rcx");
            emit_pop("%rax");
            if ((n->op == T_PLUS || n->op == T_MINUS) && (expr_is_ptr(n->a) || expr_is_ptr(n->b) || expr_is_str(n->a) || expr_is_str(n->b))) {
                int scale = (expr_is_str(n->a) || expr_is_str(n->b)) && !(expr_is_ptr(n->a) || expr_is_ptr(n->b)) ? 1 : 8;
                if (n->op == T_MINUS && (expr_is_ptr(n->a) || expr_is_str(n->a)) && (expr_is_ptr(n->b) || expr_is_str(n->b))) {
                    emit("    sub %%rcx, %%rax");
                    if (scale == 8) emit("    sar $3, %%rax");
                    return;
                }
                if (expr_is_ptr(n->b) || expr_is_str(n->b)) {
                    emit("    mov %%rax, %%rdx");
                    emit("    mov %%rcx, %%rax");
                    emit("    mov %%rdx, %%rcx");
                }
                if (scale == 8) emit("    imul $8, %%rcx");
                if (n->op == T_PLUS) emit("    add %%rcx, %%rax");
                else emit("    sub %%rcx, %%rax");
                return;
            }
            switch (n->op) {
                case T_PLUS: emit("    add %%rcx, %%rax"); break;
                case T_MINUS: emit("    sub %%rcx, %%rax"); break;
                case T_AMP: emit("    and %%rcx, %%rax"); break;
                case T_PIPE: emit("    or %%rcx, %%rax"); break;
                case T_CARET: emit("    xor %%rcx, %%rax"); break;
                case T_SHL: emit("    shl %%cl, %%rax"); break;
                case T_SHR: emit("    sar %%cl, %%rax"); break;
                case T_STAR: emit("    imul %%rcx, %%rax"); break;
                case T_SLASH:
                case T_PERCENT: {
                    int ok = newlbl();
                    int bad = newlbl();
                    int id0 = str_id++;
                    int id1 = str_id++;
                    remember_str(id0, "division by zero");
                    remember_str(id1, "division overflow");
                    emit("    cmp $0, %%rcx");
                    emit("    je .L%d", bad);
                    emit("    cmp $-1, %%rcx");
                    emit("    jne .L%d", ok);
                    emit("    mov $0x8000000000000000, %%rdx");
                    emit("    cmp %%rdx, %%rax");
                    emit("    jne .L%d", ok);
                    emit("    lea .LS%d(%%rip), %%rdi", id1);
                    emit_call("rex_fail");
                    emit("    jmp .L%d", ok);
                    emit(".L%d:", bad);
                    emit("    lea .LS%d(%%rip), %%rdi", id0);
                    emit_call("rex_fail");
                    emit(".L%d:", ok);
                    emit("    cqo");
                    emit("    idiv %%rcx");
                    if (n->op == T_PERCENT) emit("    mov %%rdx, %%rax");
                    break;
                }
                default:
                    gen_cmp(n->op, 0);
                    break;
            }
            return;
        case N_STR: {
            int id = str_id++;
            remember_str(id, n->str);
            emit("    lea .LS%d(%%rip), %%rax", id);
            return;
        }
        default:
            die("line %d: not an expression", n->line);
    }
}

static void emit_string_arg(Node *n, const char *regnote) {
    (void)regnote;
    if (n->kind != N_STR) {
        gen_expr(n);
        emit("    mov %%rax, %%rdi");
        return;
    }
    int id = str_id++;
    emit("    lea .LS%d(%%rip), %%rdi", id);
    /* stash id on the node via num for later rodata — use parallel table */
    n->num = id;
}

static void remember_str(int id, const char *s) {
    if (g_nstr == g_strcap) {
        g_strcap = g_strcap ? g_strcap * 2 : 16;
        g_strs = realloc(g_strs, (size_t)g_strcap * sizeof(StrEnt));
        if (!g_strs) die("out of memory");
    }
    g_strs[g_nstr].id = id;
    g_strs[g_nstr].s = xstrdup(s);
    g_nstr++;
}

static void gen_stmt(Node *n) {
    switch (n->kind) {
        case N_BLOCK:
            for (int i = 0; i < n->nkids; i++) gen_stmt(n->kids[i]);
            return;
        case N_LET: {
            int i = local_find(g_fn, n->name);
            if (n->num > 0) {
                for (int k = 0; k < n->num; k++)
                    emit("    movq $0, -%d(%%rbp)", g_fn->locals[i].offset + k * 8);
                g_fn->locals[i].declared = 1;
                return;
            }
            if (g_fn->locals[i].len == -3) {
                for (int k = 0; k < g_sd[g_fn->locals[i].aux].nfields; k++)
                    emit("    movq $0, -%d(%%rbp)", g_fn->locals[i].offset + k * 8);
                g_fn->locals[i].declared = 1;
                return;
            }
            if (g_fn->locals[i].len == -1 && !expr_is_str(n->a))
                die("line %d: '%s' is a string", n->line, n->name);
            if (g_fn->locals[i].len == -2 && !expr_is_ptr(n->a))
                die("line %d: '%s' is a pointer", n->line, n->name);
            if (g_fn->locals[i].len == 0 && (expr_is_str(n->a) || expr_is_ptr(n->a)))
                die("line %d: '%s' is an integer", n->line, n->name);
            gen_expr(n->a);
            g_fn->locals[i].declared = 1;
            emit("    mov %%rax, -%d(%%rbp)", g_fn->locals[i].offset);
            return;
        }
        case N_ASSIGN: {
            int i = local_find(g_fn, n->name);
            if (i < 0) {
                int g = glob_find(n->name);
                if (g < 0) die("line %d: unknown name '%s'", n->line, n->name);
                if (n->b) {
                    gen_expr(n->b);
                    emit_push("%rax");
                    gen_expr(n->a);
                    emit_push("%rax");
                    emit("    mov rex_g_%s(%%rip), %%rax", n->name);
                    emit("    mov -8(%%rax), %%rdx");
                    emit_pop("%rcx");
                    int bad = newlbl();
                    int ok = newlbl();
                    int id = str_id++;
                    remember_str(id, "index out of range");
                    emit("    cmp $0, %%rcx");
                    emit("    jl .L%d", bad);
                    emit("    cmp %%rdx, %%rcx");
                    emit("    jl .L%d", ok);
                    emit(".L%d:", bad);
                    emit("    lea .LS%d(%%rip), %%rdi", id);
                    emit_call("rex_fail");
                    emit(".L%d:", ok);
                    emit("    mov rex_g_%s(%%rip), %%rax", n->name);
                    emit_pop("%rdx");
                    emit("    mov %%rdx, (%%rax,%%rcx,8)");
                    return;
                }
                gen_expr(n->a);
                if (n->a && n->a->kind == N_CALL && n->a->name && !strcmp(n->a->name, "load")) g_globs[g].kind = 1;
                if (n->a && n->a->kind == N_CALL && n->a->name && !strcmp(n->a->name, "alloc")) g_globs[g].kind = 2;
                emit("    mov %%rax, rex_g_%s(%%rip)", n->name);
                return;
            }
            require_declared(g_fn, n->name, n->line);
            if (n->str) {
                int fi;
                if (n->num) {
                    if (g_fn->locals[i].len != -2 || g_fn->locals[i].aux < 0)
                        die("line %d: '%s' is not a struct pointer", n->line, n->name);
                    fi = field_find(g_fn->locals[i].aux, n->str);
                    if (fi < 0) die("line %d: no field '%s'", n->line, n->str);
                    gen_expr(n->a);
                    emit_push("%rax");
                    emit("    mov -%d(%%rbp), %%rax", g_fn->locals[i].offset);
                    emit_pop("%rcx");
                    if (fi == 0) emit("    mov %%rcx, (%%rax)");
                    else emit("    mov %%rcx, -%d(%%rax)", fi * 8);
                    return;
                }
                if (g_fn->locals[i].len != -3) die("line %d: '%s' is not a struct", n->line, n->name);
                fi = field_find(g_fn->locals[i].aux, n->str);
                if (fi < 0) die("line %d: no field '%s'", n->line, n->str);
                gen_expr(n->a);
                emit("    mov %%rax, -%d(%%rbp)", g_fn->locals[i].offset + fi * 8);
                return;
            }
            if (n->b) {
                if (g_fn->locals[i].len == -2 || !strcmp(n->name, "names") || !strcmp(n->name, "lens") || !strcmp(n->name, "offs") || !strcmp(n->name, "firsts") || glob_find(n->name) >= 0 && (!strcmp(n->name, "names") || !strcmp(n->name, "lens") || !strcmp(n->name, "offs") || !strcmp(n->name, "firsts"))) {
                    gen_expr(n->b);
                    emit_push("%rax");
                    gen_expr(n->a);
                    emit_push("%rax");
                    emit("    mov -%d(%%rbp), %%rax", g_fn->locals[i].offset);
                    emit("    mov -8(%%rax), %%rdx");
                    emit_pop("%rcx");
                    int bad = newlbl();
                    int ok = newlbl();
                    int id = str_id++;
                    remember_str(id, "index out of range");
                    emit("    cmp $0, %%rcx");
                    emit("    jl .L%d", bad);
                    emit("    cmp %%rdx, %%rcx");
                    emit("    jl .L%d", ok);
                    emit(".L%d:", bad);
                    emit("    lea .LS%d(%%rip), %%rdi", id);
                    emit_call("rex_fail");
                    emit(".L%d:", ok);
                    emit("    mov -%d(%%rbp), %%rax", g_fn->locals[i].offset);
                    emit_pop("%rdx");
                    emit("    mov %%rdx, (%%rax,%%rcx,8)");
                    return;
                }
                if (g_fn->locals[i].len <= 0)
                    die("line %d: '%s' is not an array", n->line, n->name);
                gen_expr(n->b);
                emit_push("%rax");
                gen_expr(n->a);
                int bad = newlbl();
                int ok = newlbl();
                int id = str_id++;
                remember_str(id, "index out of range");
                emit("    cmp $0, %%rax");
                emit("    jl .L%d", bad);
                emit("    cmp $%d, %%rax", g_fn->locals[i].len);
                emit("    jl .L%d", ok);
                emit(".L%d:", bad);
                emit("    lea .LS%d(%%rip), %%rdi", id);
                emit_call("rex_fail");
                emit(".L%d:", ok);
                emit("    imul $8, %%rax");
                emit("    neg %%rax");
                emit_pop("%rcx");
                emit("    mov %%rcx, -%d(%%rbp, %%rax)", g_fn->locals[i].offset);
                return;
            }
            if (g_fn->locals[i].len == -3)
                die("line %d: struct '%s' is not an integer", n->line, n->name);
            if (g_fn->locals[i].len == -1 && !expr_is_str(n->a))
                die("line %d: '%s' is a string", n->line, n->name);
            if (g_fn->locals[i].len == -2 && !expr_is_ptr(n->a))
                die("line %d: '%s' is a pointer", n->line, n->name);
            if (g_fn->locals[i].len == 0 && (expr_is_str(n->a) || expr_is_ptr(n->a)))
                die("line %d: '%s' is an integer", n->line, n->name);
            if (n->op == T_PLUSEQ || n->op == T_MINUSEQ || n->op == T_STAREQ) {
                emit("    mov -%d(%%rbp), %%rax", g_fn->locals[i].offset);
                emit_push("%rax");
                gen_expr(n->a);
                emit("    mov %%rax, %%rcx");
                emit_pop("%rax");
                if (n->op == T_PLUSEQ) emit("    add %%rcx, %%rax");
                else if (n->op == T_MINUSEQ) emit("    sub %%rcx, %%rax");
                else emit("    imul %%rcx, %%rax");
                emit("    mov %%rax, -%d(%%rbp)", g_fn->locals[i].offset);
                return;
            }
            gen_expr(n->a);
            emit("    mov %%rax, -%d(%%rbp)", g_fn->locals[i].offset);
            return;
        }
        case N_STORE:
            if (!n->a || n->a->kind != N_UNARY || n->a->op != T_STAR)
                die("line %d: store wants *pointer", n->line);
            gen_expr(n->b);
            emit_push("%rax");
            gen_expr(n->a->a);
            emit_pop("%rcx");
            emit("    mov %%rcx, (%%rax)");
            return;
        case N_PRINT:
            if (expr_is_str(n->a)) {
                gen_expr(n->a);
                emit("    mov %%rax, %%rdi");
                emit_call("rex_print_str");
            } else {
                gen_expr(n->a);
                emit("    mov %%rax, %%rdi");
                emit_call("rex_print_int");
            }
            return;
        case N_EXEC:
            if (!expr_is_str(n->a)) die("line %d: exec() wants a string", n->line);
            gen_expr(n->a);
            emit("    mov %%rax, %%rdi");
            emit_call("rex_exec");
            return;
        case N_RETURN:
            gen_expr(n->a);
            emit("    jmp .Lret_%s", g_fn->name);
            return;
        case N_EXPRSTMT:
            gen_expr(n->a);
            return;
        case N_IF: {
            int el = newlbl();
            int end = newlbl();
            gen_expr(n->a);
            emit("    cmp $0, %%rax");
            emit("    je .L%d", n->c ? el : end);
            gen_stmt(n->b);
            if (n->c) {
                emit("    jmp .L%d", end);
                emit(".L%d:", el);
                gen_stmt(n->c);
            }
            emit(".L%d:", end);
            return;
        }
        case N_WHILE: {
            int start = newlbl();
            int end = newlbl();
            int cont = newlbl();
            int savedb = g_break;
            int savedc = g_cont;
            g_break = end;
            g_cont = n->num ? cont : start;
            emit(".L%d:", start);
            if (!n->num) {
                gen_expr(n->a);
                emit("    cmp $0, %%rax");
                emit("    je .L%d", end);
            }
            gen_stmt(n->b);
            if (n->num) {
                emit(".L%d:", cont);
                gen_expr(n->a);
                emit("    cmp $0, %%rax");
                emit("    jne .L%d", start);
            } else {
                emit("    jmp .L%d", start);
            }
            emit(".L%d:", end);
            g_break = savedb;
            g_cont = savedc;
            return;
        }
        case N_FOR: {
            int start = newlbl();
            int end = newlbl();
            int cont = newlbl();
            int savedb = g_break;
            int savedc = g_cont;
            g_break = end;
            g_cont = cont;
            gen_stmt(n->a);
            emit(".L%d:", start);
            gen_expr(n->b);
            emit("    cmp $0, %%rax");
            emit("    je .L%d", end);
            if (n->nkids) gen_stmt(n->kids[0]);
            emit(".L%d:", cont);
            gen_stmt(n->c);
            emit("    jmp .L%d", start);
            emit(".L%d:", end);
            g_break = savedb;
            g_cont = savedc;
            return;
        }
        case N_BREAK:
            if (g_break < 0) die("line %d: break outside a loop", n->line);
            emit("    jmp .L%d", g_break);
            return;
        case N_CONTINUE:
            if (g_cont < 0) die("line %d: continue outside a loop", n->line);
            emit("    jmp .L%d", g_cont);
            return;
        case N_SWITCH: {
            int end = newlbl();
            gen_expr(n->a);
            emit_push("%rax");
            int def = -1;
            for (int i = 0; i < n->nkids; i++) {
                if (n->kids[i]->num == LONG_MIN) { def = i; continue; }
                int next = newlbl();
                emit("    mov (%%rsp), %%rax");
                emit("    cmp $%ld, %%rax", n->kids[i]->num);
                emit("    jne .L%d", next);
                gen_stmt(n->kids[i]->a);
                emit("    jmp .L%d", end);
                emit(".L%d:", next);
            }
            if (def >= 0) gen_stmt(n->kids[def]->a);
            emit(".L%d:", end);
            emit_pop("%rax");
            return;
        }
        default:
            die("line %d: not a statement", n->line);
    }
}

static int ty_of(Node *n) {
    if (!n) return 0;
    if (n->kind == N_STR) return -1;
    if (n->kind == N_NUM || n->kind == N_READ) return 0;
    if (n->kind == N_ADDR) return -2;
    if (n->kind == N_CALL && n->name && !strcmp(n->name, "alloc")) return -2;
    if (n->kind == N_CALL && n->name && !strcmp(n->name, "load")) return -1;
    if (n->kind == N_VAR && n->name) {
        int i = local_find(g_fn, n->name);
        if (i >= 0) return g_fn->locals[i].len > 0 ? 1 : g_fn->locals[i].len;
        if (fn_arity(n->name) >= 0) return -4;
        return 0;
    }
    if (n->kind == N_INDEX) return 0;
    if (n->kind == N_BIN && (n->op == T_PLUS || n->op == T_MINUS)) {
        int a = ty_of(n->a);
        int b = ty_of(n->b);
        if (a == -1 || a == -2 || b == -1 || b == -2) return a == -1 || b == -1 ? -1 : -2;
    }
    return 0;
}

static void check_node(Node *n);

static void need_num(Node *n, const char *what) {
    int t = ty_of(n);
    if (t == -1) error_at(n ? n->line : 1, col_of(n ? n->line : 1, n && n->name ? n->name : what), "string is not a number");
    else if (t == 1) error_at(n ? n->line : 1, col_of(n ? n->line : 1, n && n->name ? n->name : what), "array is not an integer");
    else if (t == -3) error_at(n ? n->line : 1, col_of(n ? n->line : 1, n && n->name ? n->name : what), "struct is not an integer");
    else if (t == -4) error_at(n ? n->line : 1, col_of(n ? n->line : 1, n && n->name ? n->name : what), "function is not an integer");
}

static void check_node(Node *n) {
    if (!n) return;
    if (n->kind == N_BIN && n->op != T_EQEQ && n->op != T_NE && n->op != T_PLUS && n->op != T_MINUS && n->op != T_ANDAND && n->op != T_OROR) {
        need_num(n->a, "left");
        need_num(n->b, "right");
    }
    if (n->kind == N_BIN && (n->op == T_PLUS || n->op == T_MINUS)) {
        int a = ty_of(n->a);
        int b = ty_of(n->b);
        if ((a == -1 || a == -2) && (b == -1 || b == -2) && n->op == T_PLUS)
            error_at(n->line, 1, "cannot add two pointers");
        if (a != -1 && a != -2 && b != -1 && b != -2) {
            need_num(n->a, "left");
            need_num(n->b, "right");
        }
    }
    if (n->kind == N_RETURN && g_fn && g_fn->ret_ty) {
        int src = n->a ? ty_of(n->a) : 0;
        if (g_fn->ret_ty == 1 && src != 0)
            error_at(n->line, col_of(n->line, "return"), "return is not an int");
        if (g_fn->ret_ty == -1 && src != -1)
            error_at(n->line, col_of(n->line, "return"), "return is not a string");
        if (g_fn->ret_ty == -2 && src != -2)
            error_at(n->line, col_of(n->line, "return"), "return is not a pointer");
    }
    if (n->kind == N_LET && n->op && n->a && n->a->kind != N_VAR) {
        int src = ty_of(n->a);
        if (n->op == 1 && src != 0)
            error_at(n->line, col_of(n->line, n->name), "'%s' is int, initializer is not", n->name);
        if (n->op == -1 && src != -1)
            error_at(n->line, col_of(n->line, n->name), "'%s' is str, initializer is not", n->name);
        if (n->op == -2 && src != -2)
            error_at(n->line, col_of(n->line, n->name), "'%s' is ptr, initializer is not", n->name);
    }
    if (n->kind == N_LET && n->num == 0 && n->a && n->a->kind != N_VAR) {
        int dest = 0;
        int slot = local_find(g_fn, n->name);
        if (slot >= 0) dest = g_fn->locals[slot].len;
        int src = ty_of(n->a);
        if (dest == 0 && (src == -1 || src == -2))
            error_at(n->line, col_of(n->line, n->name), "integer '%s' cannot hold a %s", n->name, src == -1 ? "string" : "pointer");
        if (dest == -1 && src != -1 && n->a->kind != N_STR)
            error_at(n->line, col_of(n->line, n->name), "string '%s' needs a string", n->name);
    }
    if (n->kind == N_ASSIGN && n->name && !n->b && !n->str) {
        int slot = local_find(g_fn, n->name);
        if (slot >= 0 && g_fn->locals[slot].len == 0 && n->a && (ty_of(n->a) == -1 || ty_of(n->a) == 1 || ty_of(n->a) == -3))
            error_at(n->line, col_of(n->line, n->name), "integer '%s' cannot hold that value", n->name);
    }
    if (n->kind == N_CALL && n->name && strcmp(n->name, "put") && strcmp(n->name, "print") && strcmp(n->name, "alloc") && strcmp(n->name, "load") && strcmp(n->name, "free") && strcmp(n->name, "len")) {
        for (int fi = 0; fi < g_nfn; fi++) {
            if (strcmp(g_fns[fi], n->name)) continue;
            for (int a = 0; a < n->nkids && a < 6; a++) {
                int want = g_pty[fi * 6 + a];
                if (!want) continue;
                int got = ty_of(n->kids[a]);
                int ok = (want == 1 && got == 0) || (want == -1 && got == -1) || (want == -2 && got == -2);
                if (!ok) error_at(n->line, col_of(n->line, n->name), "%s() argument %d has the wrong type", n->name, a + 1);
            }
        }
    }
    if (n->kind == N_CALL && n->name && !strcmp(n->name, "put") && n->nkids == 1 && ty_of(n->kids[0]) != -1)
        error_at(n->line, col_of(n->line, "put"), "put() wants a string");
    if (n->kind == N_PRINT && n->a) {
        int t = ty_of(n->a);
        if (t == 1 || t == -3 || t == -4)
            error_at(n->line, col_of(n->line, n->a->name ? n->a->name : "print"), "%s is not printable", t == 1 ? "array" : t == -3 ? "struct" : "function");
    }
    check_node(n->a);
    check_node(n->b);
    check_node(n->c);
    for (int i = 0; i < n->nkids; i++) check_node(n->kids[i]);
}

static void gen_fn2(Node *fn) {
    FnCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.name = fn->name;
    ctx.is_main = strcmp(fn->name, "main") == 0;
    ctx.ret_ty = fn->op;
    for (int i = 0; i < fn->nkids; i++) {
        int slot = local_add(&ctx, fn->kids[i]->name, fn->kids[i]->line);
        ctx.locals[slot].declared = 1;
        if (fn->kids[i]->op) ctx.locals[slot].len = fn->kids[i]->op == 1 ? 0 : fn->kids[i]->op;
    }
    scan_locals(&ctx, fn->a);
    g_fn = &ctx;
    check_node(fn->a);
    if (g_err) die("aborting after %d error%s", g_err, g_err == 1 ? "" : "s");
    g_depth = 0;
    if (ctx.is_main) {
        emit(".globl main");
        emit("main:");
    } else {
        emit(".globl rexfn_%s", fn->name);
        emit("rexfn_%s:", fn->name);
    }
    emit("    push %%rbp");
    emit("    mov %%rsp, %%rbp");
    if (ctx.stack) emit("    sub $%d, %%rsp", ctx.stack);
    {
        static const char *areg[] = {"%rdi", "%rsi", "%rdx", "%rcx", "%r8", "%r9"};
        for (int i = 0; i < fn->nkids; i++)
            emit("    mov %s, -%d(%%rbp)", areg[i], ctx.locals[i].offset);
    }
    gen_stmt(fn->a);
    if (ctx.is_main) emit("    xor %%eax, %%eax");
    else emit("    xor %%eax, %%eax");
    emit(".Lret_%s:", fn->name);
    emit("    mov %%rbp, %%rsp");
    emit("    pop %%rbp");
    emit("    ret");
    emit("");
}

static void asm_escape(FILE *f, const char *s) {
    fputc('"', f);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p == '\\' || *p == '"') fprintf(f, "\\%c", *p);
        else if (*p == '\n') fputs("\\n", f);
        else if (*p == '\t') fputs("\\t", f);
        else if (*p < 32 || *p > 126) fprintf(f, "\\%03o", *p);
        else fputc(*p, f);
    }
    fputc('"', f);
}

static void gen_program(Node *p, FILE *out) {
    g_out = out;
    g_lbl = 1;
    str_id = 0;
    g_nstr = 0;
    collect_fns(p);
    emit("    .text");
    for (int i = 0; i < p->nkids; i++) gen_fn2(p->kids[i]);
    if (g_nstr) {
        emit("    .section .rodata");
        for (int i = 0; i < g_nstr; i++) {
            emit(".LS%d:", g_strs[i].id);
            fputs("    .asciz ", out);
            asm_escape(out, g_strs[i].s);
            fputc('\n', out);
        }
    }
    if (g_nglobs) {
        emit("    .data");
        for (int i = 0; i < g_nglobs; i++) {
            emit("rex_g_%s:", g_globs[i].name);
            emit("    .quad %ld", g_globs[i].init);
        }
    }
    emit("    .section .note.GNU-stack,\"\",@progbits");
}

static char *read_file(const char *path, int *len) {
    FILE *f = fopen(path, "rb");
    if (!f) die("cannot read %s: %s", path, strerror(errno));
    /* Seekable files can be sized. Pipes and /dev/stdin cannot: ftell returns -1. */
    if (fseek(f, 0, SEEK_END) == 0) {
        long n = ftell(f);
        if (n >= 0 && fseek(f, 0, SEEK_SET) == 0) {
            if (n > INT_MAX - 1) die("%s: file too large", path);
            char *buf = malloc((size_t)n + 1);
            if (!buf) die("out of memory");
            size_t got = fread(buf, 1, (size_t)n, f);
            if (ferror(f)) die("cannot read %s: %s", path, strerror(errno));
            fclose(f);
            buf[got] = 0;
            *len = (int)got;
            return buf;
        }
    }
    clearerr(f);
    size_t cap = 4096, n = 0;
    char *buf = malloc(cap);
    if (!buf) die("out of memory");
    for (;;) {
        if (n + 1 >= cap) {
            if (cap > (size_t)INT_MAX / 2) die("%s: file too large", path);
            cap *= 2;
            char *nb = realloc(buf, cap);
            if (!nb) die("out of memory");
            buf = nb;
        }
        size_t got = fread(buf + n, 1, cap - n - 1, f);
        n += got;
        if (got == 0) break;
    }
    if (ferror(f)) die("cannot read %s: %s", path, strerror(errno));
    fclose(f);
    buf[n] = 0;
    *len = (int)n;
    return buf;
}

static void usage(void) {
    fprintf(stderr,
        "REX %s — native compiler for Arch\n"
        "usage:\n"
        "  rex run <file.rex>           compile and execute\n"
        "  rex build <file.rex> -o bin  emit a binary\n"
        "  rex check <file.rex>         parse and type-check only\n"
        "  rex asm <file.rex>           write assembly to stdout\n"
        "  rex elf <file.s> -o bin    assemble emitted assembly\n"
        "  rex inspect <elf>            show ELF64 headers and segments\n"
        "  rex disasm <elf>             disassemble executable segments\n"
        "  rex disasm --cfg <elf>       functions and basic blocks\n"
        "  rex disasm --function F <elf> one function (start, main, fn_ADDR, ADDR)\n"
        "  rex ir [--function F] <elf>  lift to machine IR and print it\n"
        "  rex version\n",
        REX_VERSION);
    exit(2);
}

static char *rt_path(void) {
    const char *env = getenv("REX_RUNTIME");
    if (env && *env) return xstrdup(env);
    static char buf[512];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = 0;
        char *slash = strrchr(buf, '/');
        if (slash) {
            slash[1] = 0;
            char *p = malloc(strlen(buf) + 16);
            if (!p) die("out of memory");
            sprintf(p, "%srexrt.c", buf);
            if (access(p, R_OK) == 0) return p;
            free(p);
        }
    }
    snprintf(buf, sizeof(buf), "%s/share/rex/rexrt.c", REX_PREFIX);
    if (access(buf, R_OK) == 0) return xstrdup(buf);
    if (access("src/rexrt.c", R_OK) == 0) return xstrdup("src/rexrt.c");
    if (access("rexrt.c", R_OK) == 0) return xstrdup("rexrt.c");
    die("runtime not found (looked in $REX_RUNTIME, beside the binary, %s/share/rex/rexrt.c, src/rexrt.c)", REX_PREFIX);
    return NULL;
}

int rex_write_elf(const char *asm_text, const char *outpath);

static int compile_to(const char *srcpath, const char *outbin) {
    int len = 0;
    char *src = read_file(srcpath, &len);
    g_src = src;
    g_path = (char *)srcpath;
    Lexer L = {0};
    L.src = src;
    L.len = len;
    L.line = 1;
    L.col = 1;
    L.path = (char *)srcpath;
    lex_next(&L);
    Node *prog = parse_program(&L);
    if (g_err) die("aborting after %d error%s", g_err, g_err == 1 ? "" : "s");
    char asmpath[] = "/tmp/rexXXXXXX.s";
    int fd = mkstemps(asmpath, 2);
    if (fd < 0) die("mkstemps: %s", strerror(errno));
    snprintf(g_tmpasm, sizeof(g_tmpasm), "%s", asmpath);
    FILE *af = fdopen(fd, "w");
    if (!af) die("fdopen");
    gen_program(prog, af);
    fclose(af);
    if (!outbin) {
        FILE *in = fopen(asmpath, "r");
        if (!in) die("cannot read assembly %s", asmpath);
        char buf[1024];
        size_t nread;
        while ((nread = fread(buf, 1, sizeof(buf), in)) > 0) fwrite(buf, 1, nread, stdout);
        fclose(in);
        cleanup_tmp();
        return 0;
    }
    FILE *in = fopen(asmpath, "r");
    if (!in) die("cannot read assembly %s", asmpath);
    fseek(in, 0, SEEK_END);
    long n = ftell(in);
    fseek(in, 0, SEEK_SET);
    char *asm_text = malloc((size_t)n + 1);
    if (!asm_text) die("out of memory");
    size_t got = fread(asm_text, 1, (size_t)n, in);
    fclose(in);
    asm_text[got] = 0;
    cleanup_tmp();
    if (rex_write_elf(asm_text, outbin) != 0) die("elf emission failed");
    free(asm_text);
    return 0;
}

int rex_cmd_inspect(const char *path);
int rex_cmd_disasm(const char *path);
int rex_cmd_disasm_func(const char *path, const char *fname);
int rex_cmd_ir(const char *path, const char *fname);

int main(int argc, char **argv) {
    if (argc < 2) usage();
    if (strcmp(argv[1], "inspect") == 0) {
        if (argc < 3) usage();
        return rex_cmd_inspect(argv[2]);
    }
    if (strcmp(argv[1], "ir") == 0) {
        if (argc >= 5 && strcmp(argv[2], "--function") == 0) return rex_cmd_ir(argv[4], argv[3]);
        if (argc < 3) usage();
        return rex_cmd_ir(argv[2], NULL);
    }
    if (strcmp(argv[1], "disasm") == 0) {
        if (argc >= 4 && strcmp(argv[2], "--cfg") == 0) return rex_cmd_disasm_func(argv[3], NULL);
        if (argc >= 5 && strcmp(argv[2], "--function") == 0) return rex_cmd_disasm_func(argv[4], argv[3]);
        if (argc < 3) usage();
        return rex_cmd_disasm(argv[2]);
    }
    if (strcmp(argv[1], "version") == 0 || strcmp(argv[1], "--version") == 0) {
        printf("REX %s\n", REX_VERSION);
        return 0;
    }
    if (strcmp(argv[1], "asm") == 0) {
        if (argc < 3) usage();
        return compile_to(argv[2], NULL);
    }
    if (strcmp(argv[1], "elf") == 0) {
        if (argc < 3) usage();
        const char *out = "a.out";
        if (argc >= 5 && strcmp(argv[3], "-o") == 0) out = argv[4];
        int len = 0;
        char *src = read_file(argv[2], &len);
        if (rex_write_elf(src, out) != 0) die("elf emission failed");
        free(src);
        return 0;
    }
    if (strcmp(argv[1], "check") == 0) {
        if (argc < 3) usage();
        compile_to(argv[2], "/tmp/rexcheck.bin");
        unlink("/tmp/rexcheck.bin");
        return 0;
    }
    if (strcmp(argv[1], "build") == 0) {
        if (argc < 3) usage();
        const char *out = "a.out";
        if (argc >= 5 && strcmp(argv[3], "-o") == 0) out = argv[4];
        compile_to(argv[2], out);
        return 0;
    }
    if (strcmp(argv[1], "run") == 0) {
        if (argc < 3) usage();
        char tmpl[] = "/tmp/rexbinXXXXXX";
        int fd = mkstemp(tmpl);
        if (fd < 0) die("mkstemp");
        close(fd);
        unlink(tmpl);
        compile_to(argv[2], tmpl);
        pid_t pid = fork();
        if (pid == 0) {
            execl(tmpl, tmpl, (char *)NULL);
            perror(tmpl);
            _exit(127);
        }
        int st = 0;
        waitpid(pid, &st, 0);
        unlink(tmpl);
        if (WIFEXITED(st)) return WEXITSTATUS(st);
        if (WIFSIGNALED(st)) {
            int sig = WTERMSIG(st);
            fprintf(stderr, "rex: program killed by signal %d (%s)\n", sig, strsignal(sig));
            return 128 + sig;
        }
        fprintf(stderr, "rex: program did not exit normally\n");
        return 1;
    }
    usage();
    return 2;
}
