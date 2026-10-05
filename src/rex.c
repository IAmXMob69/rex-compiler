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

#define REX_VERSION "0.1.1"

#ifndef REX_PREFIX
#define REX_PREFIX "/usr/local"
#endif

typedef enum {
    T_EOF = 0, T_FN, T_LET, T_IF, T_ELSE, T_WHILE, T_PRINT, T_EXEC,
    T_RETURN, T_READ, T_IDENT, T_NUM, T_STR,
    T_LPAREN, T_RPAREN, T_LBRACE, T_RBRACE, T_SEMI, T_COMMA, T_EQ,
    T_PLUS, T_MINUS, T_STAR, T_SLASH, T_PERCENT,
    T_EQEQ, T_NE, T_LT, T_GT, T_LE, T_GE
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
    N_RETURN, N_IF, N_WHILE, N_EXPRSTMT, N_BIN, N_UNARY, N_NUM,
    N_STR, N_VAR, N_CALL, N_READ
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
    int offset; /* negative rbp offset */
    int declared; /* set when the let is reached in source order */
} Local;

typedef struct {
    char *name;
    Local locals[64];
    int nlocals;
    int stack;
    int is_main;
} FnCtx;

static FILE *g_out;
static int g_lbl;
static int g_depth;
static FnCtx *g_fn;
static char **g_fns;
static int g_nfn;
static int g_err;
static char g_tmpasm[64];

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

static void error_at(int line, int col, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "rex:%d:%d: error: ", line, col);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    g_err++;
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
            if (i + 1 >= L->len) die("%s:%d: unterminated block comment", L->path, L->line);
            i += 2; L->col += 2;
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
        else if (startswith_kw(t.text, "print", n)) t.kind = T_PRINT;
        else if (startswith_kw(t.text, "exec", n)) t.kind = T_EXEC;
        else if (startswith_kw(t.text, "return", n)) t.kind = T_RETURN;
        else if (startswith_kw(t.text, "read", n)) t.kind = T_READ;
        else t.kind = T_IDENT;
        L->col += n;
        L->pos = i;
        L->tok = t;
        return;
    }
    if (isdigit((unsigned char)c)) {
        int col = L->col;
        unsigned long long v = 0;
        int overflow = 0;
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
            if (ch == '\n') die("%s:%d: unterminated string", L->path, L->line);
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
        if (i >= L->len || s[i] != '"') die("%s:%d: unterminated string", L->path, t.line);
        i++; L->col++;
        buf[n] = 0;
        t.kind = T_STR;
        t.text = buf;
        t.col = col;
        L->pos = i;
        L->tok = t;
        return;
    }
    int col = L->col;
    if (i + 1 < L->len) {
        if (s[i] == '=' && s[i + 1] == '=') { t.kind = T_EQEQ; L->pos = i + 2; L->col += 2; t.col = col; L->tok = t; return; }
        if (s[i] == '!' && s[i + 1] == '=') { t.kind = T_NE; L->pos = i + 2; L->col += 2; t.col = col; L->tok = t; return; }
        if (s[i] == '<' && s[i + 1] == '=') { t.kind = T_LE; L->pos = i + 2; L->col += 2; t.col = col; L->tok = t; return; }
        if (s[i] == '>' && s[i + 1] == '=') { t.kind = T_GE; L->pos = i + 2; L->col += 2; t.col = col; L->tok = t; return; }
    }
    TokKind k = T_EOF;
    switch (c) {
        case '(': k = T_LPAREN; break;
        case ')': k = T_RPAREN; break;
        case '{': k = T_LBRACE; break;
        case '}': k = T_RBRACE; break;
        case ';': k = T_SEMI; break;
        case ',': k = T_COMMA; break;
        case '=': k = T_EQ; break;
        case '+': k = T_PLUS; break;
        case '-': k = T_MINUS; break;
        case '*': k = T_STAR; break;
        case '/': k = T_SLASH; break;
        case '%': k = T_PERCENT; break;
        case '<': k = T_LT; break;
        case '>': k = T_GT; break;
        default:
            die("%s:%d:%d: stray character '%c'", L->path, L->line, L->col, c);
    }
    t.kind = k;
    t.col = col;
    L->pos = i + 1;
    L->col++;
    L->tok = t;
}

static void expect(Lexer *L, TokKind k, const char *what) {
    if (L->tok.kind != k) {
        error_at(L->tok.line, L->tok.col, "expected %s", what);
        die("aborting after parse error");
    }
    lex_next(L);
}

static Node *parse_expr(Lexer *L);

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
            lex_next(L);
            expect(L, T_RPAREN, "')'");
            Node *n = node_new(N_CALL, t.line);
            n->name = name;
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
    die("aborting after parse error");
    return NULL;
}

static Node *parse_unary(Lexer *L) {
    if (L->tok.kind == T_MINUS) {
        int line = L->tok.line;
        lex_next(L);
        Node *n = node_new(N_UNARY, line);
        n->op = T_MINUS;
        n->a = parse_unary(L);
        return n;
    }
    return parse_primary(L);
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

static Node *parse_cmp(Lexer *L) {
    Node *n = parse_term(L);
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

static Node *parse_expr(Lexer *L) {
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

static Node *parse_block(Lexer *L);

static Node *parse_stmt(Lexer *L) {
    Token t = L->tok;
    if (t.kind == T_LET) {
        lex_next(L);
        if (L->tok.kind != T_IDENT) die("%s: expected name after let", L->path);
        Node *n = node_new(N_LET, t.line);
        n->name = xstrdup(L->tok.text);
        lex_next(L);
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
    if (t.kind == T_WHILE) {
        lex_next(L);
        expect(L, T_LPAREN, "'('");
        Node *n = node_new(N_WHILE, t.line);
        n->a = parse_expr(L);
        expect(L, T_RPAREN, "')'");
        n->b = parse_block(L);
        return n;
    }
    if (t.kind == T_LBRACE) return parse_block(L);
    if (t.kind == T_IDENT) {
        char *name = xstrdup(t.text);
        int line = t.line;
        lex_next(L);
        if (L->tok.kind == T_EQ) {
            lex_next(L);
            Node *n = node_new(N_ASSIGN, line);
            n->name = name;
            n->a = parse_expr(L);
            expect(L, T_SEMI, "';'");
            return n;
        }
        if (L->tok.kind == T_LPAREN) {
            lex_next(L);
            expect(L, T_RPAREN, "')'");
            expect(L, T_SEMI, "';'");
            Node *n = node_new(N_EXPRSTMT, line);
            Node *c = node_new(N_CALL, line);
            c->name = name;
            n->a = c;
            return n;
        }
        error_at(line, t.col, "expected '=' or '(' after name");
        die("aborting after parse error");
    }
    error_at(t.line, t.col, "expected statement");
    die("aborting after parse error");
    return NULL;
}

static Node *parse_block(Lexer *L) {
    int line = L->tok.line;
    expect(L, T_LBRACE, "'{'");
    Node *n = node_new(N_BLOCK, line);
    while (L->tok.kind != T_RBRACE && L->tok.kind != T_EOF) {
        node_add(n, parse_stmt(L));
    }
    expect(L, T_RBRACE, "'}'");
    return n;
}

static Node *parse_program(Lexer *L) {
    Node *p = node_new(N_PROGRAM, 1);
    while (L->tok.kind != T_EOF) {
        int line = L->tok.line;
        expect(L, T_FN, "'fn'");
        if (L->tok.kind != T_IDENT) die("expected function name");
        Node *fn = node_new(N_FN, line);
        fn->name = xstrdup(L->tok.text);
        lex_next(L);
        expect(L, T_LPAREN, "'('");
        expect(L, T_RPAREN, "')'");
        fn->a = parse_block(L);
        node_add(p, fn);
    }
    return p;
}

static int fn_known(const char *name) {
    for (int i = 0; i < g_nfn; i++) if (strcmp(g_fns[i], name) == 0) return 1;
    return 0;
}

static void collect_fns(Node *p) {
    g_nfn = p->nkids;
    g_fns = calloc((size_t)g_nfn, sizeof(char *));
    int saw_main = 0;
    for (int i = 0; i < p->nkids; i++) {
        g_fns[i] = p->kids[i]->name;
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

static int local_add(FnCtx *fn, const char *name, int line) {
    if (local_find(fn, name) >= 0) die("line %d: '%s' already declared", line, name);
    if (fn->nlocals >= 64) die("line %d: too many locals (limit 64)", line);
    int off = (fn->nlocals + 1) * 8;
    fn->locals[fn->nlocals].name = xstrdup(name);
    fn->locals[fn->nlocals].offset = off;
    fn->locals[fn->nlocals].declared = 0;
    fn->nlocals++;
    fn->stack = (fn->nlocals * 8 + 15) & ~15;
    return fn->nlocals - 1;
}

static void require_declared(FnCtx *fn, const char *name, int line) {
    int i = local_find(fn, name);
    if (i < 0) die("line %d: unknown name '%s'", line, name);
    if (!fn->locals[i].declared)
        die("line %d: '%s' used before declaration", line, name);
}

static void scan_locals(FnCtx *fn, Node *n) {
    if (!n) return;
    if (n->kind == N_LET) local_add(fn, n->name, n->line);
    if (n->kind == N_BLOCK) {
        for (int i = 0; i < n->nkids; i++) scan_locals(fn, n->kids[i]);
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
            require_declared(g_fn, n->name, n->line);
            int i = local_find(g_fn, n->name);
            emit("    mov -%d(%%rbp), %%rax", g_fn->locals[i].offset);
            return;
        }
        case N_READ:
            emit_call("rex_read_int");
            return;
        case N_CALL:
            if (!fn_known(n->name)) die("line %d: unknown function '%s'", n->line, n->name);
            if (strcmp(n->name, "main") == 0) die("line %d: do not call main", n->line);
            {
                char sym[128];
                snprintf(sym, sizeof(sym), "rexfn_%s", n->name);
                emit_call(sym);
            }
            return;
        case N_UNARY:
            gen_expr(n->a);
            emit("    neg %%rax");
            return;
        case N_BIN:
            gen_expr(n->a);
            emit_push("%rax");
            gen_expr(n->b);
            emit("    mov %%rax, %%rcx");
            emit_pop("%rax");
            switch (n->op) {
                case T_PLUS: emit("    add %%rcx, %%rax"); break;
                case T_MINUS: emit("    sub %%rcx, %%rax"); break;
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
        case N_STR:
            die("line %d: string is only legal as print/exec argument", n->line);
            return;
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
            /* Initializer runs before the name is visible. let x = x is an error. */
            gen_expr(n->a);
            g_fn->locals[i].declared = 1;
            emit("    mov %%rax, -%d(%%rbp)", g_fn->locals[i].offset);
            return;
        }
        case N_ASSIGN: {
            require_declared(g_fn, n->name, n->line);
            int i = local_find(g_fn, n->name);
            gen_expr(n->a);
            emit("    mov %%rax, -%d(%%rbp)", g_fn->locals[i].offset);
            return;
        }
        case N_PRINT:
            if (n->a->kind == N_STR) {
                int id = str_id++;
                remember_str(id, n->a->str);
                emit("    lea .LS%d(%%rip), %%rdi", id);
                emit_call("rex_print_str");
            } else {
                gen_expr(n->a);
                emit("    mov %%rax, %%rdi");
                emit_call("rex_print_int");
            }
            return;
        case N_EXEC:
            if (n->a->kind != N_STR) die("line %d: exec() wants a string literal", n->line);
            {
                int id = str_id++;
                remember_str(id, n->a->str);
                emit("    lea .LS%d(%%rip), %%rdi", id);
                emit_call("rex_exec");
            }
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
            emit(".L%d:", start);
            gen_expr(n->a);
            emit("    cmp $0, %%rax");
            emit("    je .L%d", end);
            gen_stmt(n->b);
            emit("    jmp .L%d", start);
            emit(".L%d:", end);
            return;
        }
        default:
            die("line %d: not a statement", n->line);
    }
}

static void gen_fn2(Node *fn) {
    FnCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.name = fn->name;
    ctx.is_main = strcmp(fn->name, "main") == 0;
    scan_locals(&ctx, fn->a);
    g_fn = &ctx;
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
        "  rex asm <file.rex>           write assembly to stdout\n"
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

static int compile_to(const char *srcpath, const char *outbin) {
    int len = 0;
    char *src = read_file(srcpath, &len);
    Lexer L = {0};
    L.src = src;
    L.len = len;
    L.line = 1;
    L.col = 1;
    L.path = (char *)srcpath;
    lex_next(&L);
    Node *prog = parse_program(&L);
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
    char *rt = rt_path();
    if (access(rt, R_OK) != 0) die("runtime not found (%s). Set REX_RUNTIME.", rt);
    pid_t pid = fork();
    if (pid < 0) die("fork");
    if (pid == 0) {
        execlp("gcc", "gcc", "-O2", "-no-pie", "-Wl,-z,noexecstack", "-o", outbin, asmpath, rt, (char *)NULL);
        perror("gcc");
        _exit(127);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    cleanup_tmp();
    free(rt);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) die("gcc failed (is base-devel installed?)");
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) usage();
    if (strcmp(argv[1], "version") == 0 || strcmp(argv[1], "--version") == 0) {
        printf("REX %s\n", REX_VERSION);
        return 0;
    }
    if (strcmp(argv[1], "asm") == 0) {
        if (argc < 3) usage();
        return compile_to(argv[2], NULL);
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
