#define _GNU_SOURCE
#include "verify.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "rex_err.h"
#include "loader.h"
#include "cfg.h"
#include "x86_lift.h"
#include "ir.h"

/* Each program gets this long: a rebuilt program that loops must not hang match. */
enum { RUN_LIMIT_S = 20, RUN_TIMEOUT = -2, RUN_SIGNAL = 1000 };

/* What a run did: exit status (or RUN_TIMEOUT, or RUN_SIGNAL + signal) and
 * everything it wrote to stdout and to stderr, byte for byte. */
typedef struct { int status; char *out, *errb; size_t nout, nerr; } Run;
static void run_free(Run *r) { free(r->out); free(r->errb); memset(r, 0, sizeof *r); }

static int slurp(int fd, char **buf, size_t *n) {
    size_t cap = 4096, len = 0;
    char *b = malloc(cap);
    if (!b) return -1;
    if (lseek(fd, 0, SEEK_SET) < 0) { free(b); return -1; }
    for (;;) {
        if (len == cap) { char *nb = realloc(b, cap * 2); if (!nb) { free(b); return -1; } b = nb; cap *= 2; }
        ssize_t r = read(fd, b + len, cap - len);
        if (r < 0) { free(b); return -1; }
        if (r == 0) break;
        len += (size_t)r;
    }
    *buf = b; *n = len;
    return 0;
}
static int tmpfd(void) {
    char t[] = "/tmp/rexrunXXXXXX";
    int fd = mkstemp(t);
    if (fd >= 0) unlink(t);
    return fd;
}

/* The inputs a program is run with. Both programs see argv[0] "prog", so a
 * path never makes them differ. Input 0 (no arguments, empty stdin) is the
 * one every program gets; the others count only where the original gives the
 * same result twice and finishes in time. */
typedef struct { const char *args[4]; const char *in; size_t nin; } Input;
static char g_bigin[8192];
static Input g_inputs[] = {
    { { NULL }, "", 0 },
    { { "7", NULL }, "3\n", 2 },
    { { "hello", "-x", "12345", NULL }, "hello world\n42 -7\nzz\n", 21 },
    { { "0", NULL }, g_bigin, 0 },
};
enum { N_INPUTS = sizeof g_inputs / sizeof g_inputs[0] };
static void inputs_init(void) {
    if (g_inputs[3].nin) return;
    size_t n = 0;
    for (int k = 0; n + 16 < sizeof g_bigin; k++) n += (size_t)snprintf(g_bigin + n, sizeof g_bigin - n, "%d\n", k * 7919 % 10007 - 5000);
    g_inputs[3].nin = n;
}

static int run_one(const char *bin, const Input *in, Run *r) {
    memset(r, 0, sizeof *r);
    int fi = tmpfd(), fo = tmpfd(), fe = tmpfd();
    if (fi < 0 || fo < 0 || fe < 0) goto fail;
    if (in->nin && write(fi, in->in, in->nin) != (ssize_t)in->nin) goto fail;
    if (lseek(fi, 0, SEEK_SET) < 0) goto fail;
    char *argv[6] = { "prog" };
    int na = 1;
    for (int k = 0; k < 4 && in->args[k]; k++) argv[na++] = (char *)in->args[k];
    argv[na] = NULL;
    pid_t pid = fork();
    if (pid < 0) goto fail;
    if (pid == 0) {
        dup2(fi, 0); dup2(fo, 1); dup2(fe, 2);
        close(fi); close(fo); close(fe);
        alarm(RUN_LIMIT_S);                 /* a pending alarm survives exec */
        execv(bin, argv);
        _exit(127);
    }
    int st = 0;
    if (waitpid(pid, &st, 0) < 0) goto fail;
    r->status = WIFEXITED(st) ? WEXITSTATUS(st) : WIFSIGNALED(st) && WTERMSIG(st) == SIGALRM ? RUN_TIMEOUT
              : WIFSIGNALED(st) ? RUN_SIGNAL + WTERMSIG(st) : -1;
    if (slurp(fo, &r->out, &r->nout) || slurp(fe, &r->errb, &r->nerr)) { run_free(r); goto fail; }
    close(fi); close(fo); close(fe);
    return 0;
fail:
    if (fi >= 0) close(fi);
    if (fo >= 0) close(fo);
    if (fe >= 0) close(fe);
    return -1;
}

static int same_run(const Run *x, const Run *y) {
    return x->status == y->status && x->nout == y->nout && x->nerr == y->nerr &&
           !memcmp(x->out, y->out, x->nout) && !memcmp(x->errb, y->errb, x->nerr);
}
static void status_str(int st, char *b, size_t n) {
    if (st >= RUN_SIGNAL) snprintf(b, n, "killed by signal %d", st - RUN_SIGNAL);
    else snprintf(b, n, "exit %d", st);
}
static void input_str(const Input *in, char *b, size_t n) {
    size_t k = (size_t)snprintf(b, n, "args:");
    if (!in->args[0] && k < n) k += (size_t)snprintf(b + k, n - k, " none");
    for (int i = 0; i < 4 && in->args[i] && k < n; i++) k += (size_t)snprintf(b + k, n - k, " %s", in->args[i]);
    if (k < n) snprintf(b + k, n - k, ", stdin: %zu bytes", in->nin);
}
static size_t first_diff(const char *x, size_t nx, const char *y, size_t ny) {
    size_t i = 0;
    while (i < nx && i < ny && x[i] == y[i]) i++;
    return i;
}

int rex_verify_bins(const char *a, const char *b, char *err, size_t errlen, int code) {
    inputs_init();
    for (int k = 0; k < N_INPUTS; k++) {
        const Input *in = &g_inputs[k];
        Run ra, rb;
        if (run_one(a, in, &ra)) return rex_errf(err, errlen, code, "could not run binaries");
        if (ra.status == RUN_TIMEOUT) {
            run_free(&ra);
            if (k == 0)   /* not a mismatch: nothing was compared */
                return rex_errf(err, errlen, REX_E604_NO_FINISH, "%s ran past %d s without exiting; the rebuilt program was not run", a, RUN_LIMIT_S);
            continue;     /* this input is not one the sample allows */
        }
        if (k > 0) {
            /* only an input the original answers the same way twice is compared */
            Run r2;
            if (run_one(a, in, &r2)) { run_free(&ra); return rex_errf(err, errlen, code, "could not run binaries"); }
            int same = same_run(&ra, &r2);
            run_free(&r2);
            if (!same) { run_free(&ra); continue; }
        }
        if (run_one(b, in, &rb)) { run_free(&ra); return rex_errf(err, errlen, code, "could not run binaries"); }
        char ib[96], sa[32], sb[32];
        input_str(in, ib, sizeof ib);
        status_str(ra.status, sa, sizeof sa);
        int rc = 0;
        if (rb.status == RUN_TIMEOUT)
            rc = rex_errf(err, errlen, code, "the rebuilt program did not finish in %d s (%s; the original: %s)", RUN_LIMIT_S, ib, sa);
        else if (ra.status != rb.status) {
            status_str(rb.status, sb, sizeof sb);
            rc = rex_errf(err, errlen, code, "%s vs %s (%s)", sa, sb, ib);
        } else if (ra.nout != rb.nout || memcmp(ra.out, rb.out, ra.nout))
            rc = rex_errf(err, errlen, code, "stdout differs at byte %zu (%zu vs %zu bytes; %s)",
                          first_diff(ra.out, ra.nout, rb.out, rb.nout), ra.nout, rb.nout, ib);
        else if (ra.nerr != rb.nerr || memcmp(ra.errb, rb.errb, ra.nerr))
            rc = rex_errf(err, errlen, code, "stderr differs at byte %zu (%zu vs %zu bytes; %s)",
                          first_diff(ra.errb, ra.nerr, rb.errb, rb.nerr), ra.nerr, rb.nerr, ib);
        run_free(&ra); run_free(&rb);
        if (rc) return rc;
    }
    return 0;
}


static void norm_op(FILE *out, const IrModule *m, const IrOperand *o, uint64_t *faddrs, int nfuncs) {
    switch (o->kind) {
    case IR_O_NONE: break;
    case IR_O_REG:
        if (m->reg_name && m->reg_name(o->reg)) fprintf(out, "%s", m->reg_name(o->reg));
        else fprintf(out, "r%d", o->reg);
        fprintf(out, ":%d", o->width);
        break;
    case IR_O_IMM: fprintf(out, "%lld", (long long)o->imm); break;
    case IR_O_BLOCK: fprintf(out, "b%d", o->block); break;
    case IR_O_ADDR: {
        int fi = -1;
        for (int i = 0; i < nfuncs; i++) if (faddrs[i] == o->addr) { fi = i; break; }
        if (fi >= 0) fprintf(out, "F%d", fi);
        else fprintf(out, "EXT");
        break;
    }
    case IR_O_MEM: {
        fputc('[', out);
        int any = 0;
        if (o->base == IR_PC) { fputs("rip", out); any = 1; }
        else if (o->base != IR_NOREG) {
            if (m->reg_name && m->reg_name(o->base)) fprintf(out, "%s", m->reg_name(o->base));
            else fprintf(out, "r%d", o->base);
            any = 1;
        }
        if (o->index != IR_NOREG) {
            if (any) fputs("+", out);
            if (m->reg_name && m->reg_name(o->index)) fprintf(out, "%s", m->reg_name(o->index));
            else fprintf(out, "r%d", o->index);
            fprintf(out, "*%d", o->scale); any = 1;
        }
        /* Drop absolute rip displacement; keep shape only for rip-relative. */
        if (o->base == IR_PC) { if (any) fputs("+", out); fputs("OFF", out); }
        else if (o->disp || !any) {
            if (any && o->disp >= 0) fputc('+', out);
            fprintf(out, "%lld", (long long)o->disp);
        }
        fprintf(out, "]:%d", o->width);
        break;
    }
    }
}

static const IrFunc *pick_main(const IrModule *m, const CfgProgram *cfg) {
    for (int i = 0; i < m->nfuncs; i++)
        if (!strcmp(m->funcs[i].name, "main")) return &m->funcs[i];
    if (cfg && cfg->main_addr)
        for (int i = 0; i < m->nfuncs; i++)
            if (m->funcs[i].addr == cfg->main_addr) return &m->funcs[i];
    /* Fallback: largest non-start function. */
    const IrFunc *best = NULL; int bestn = -1;
    for (int i = 0; i < m->nfuncs; i++) {
        if (!strcmp(m->funcs[i].name, "start")) continue;
        int ni = 0;
        for (int b = 0; b < m->funcs[i].nblocks; b++) ni += m->funcs[i].blocks[b].ninsns;
        if (ni > bestn) { bestn = ni; best = &m->funcs[i]; }
    }
    return best;
}

static int dump_func(const IrModule *m, const IrFunc *f, char **out, size_t *outn, char *err, size_t errlen) {
    uint64_t *faddrs = calloc((size_t)m->nfuncs, sizeof(uint64_t));
    if (!faddrs) return rex_errf(err, errlen, REX_E501_VERIFY, "out of memory");
    for (int i = 0; i < m->nfuncs; i++) faddrs[i] = m->funcs[i].addr;
    FILE *mem = open_memstream(out, outn);
    if (!mem) { free(faddrs); return rex_errf(err, errlen, REX_E501_VERIFY, "out of memory"); }
    fprintf(mem, "main\n");
    for (int b = 0; b < f->nblocks; b++) {
        const IrBlock *bl = &f->blocks[b];
        fprintf(mem, "  b%d\n", b);
        for (int k = 0; k < bl->ninsns; k++) {
            const IrInsn *in = &bl->insns[k];
            if (in->op == IR_NOP || in->op == IR_TRAP) continue;
            /* Identity mov r,r is a no-op for compare (often a 32-bit zext artifact). */
            if (in->op == IR_MOV && in->dst.kind == IR_O_REG && in->a.kind == IR_O_REG
                && in->dst.reg == in->a.reg && in->dst.width == in->a.width) continue;
            /* Drop zext r:8,r:4 when the previous kept insn already zero-extended that reg. */
            if (in->op == IR_ZEXT && in->dst.kind == IR_O_REG && in->a.kind == IR_O_REG
                && in->dst.reg == in->a.reg && in->dst.width == 8 && in->a.width == 4) {
                int skip = 0;
                for (int j = k - 1; j >= 0; j--) {
                    const IrInsn *p = &bl->insns[j];
                    if (p->op == IR_NOP || p->op == IR_TRAP) continue;
                    if (p->op == IR_MOV && p->dst.kind == IR_O_REG && p->a.kind == IR_O_REG
                        && p->dst.reg == p->a.reg && p->dst.width == p->a.width) continue;
                    if ((p->op == IR_ZEXT || p->op == IR_MOV) && p->dst.kind == IR_O_REG
                        && p->dst.reg == in->dst.reg && p->dst.width >= 4) skip = 1;
                    break;
                }
                if (skip) continue;
            }
            fprintf(mem, "    %s", ir_op_name(in->op));
            if (in->cc != IR_CC_NONE) fprintf(mem, ".%s", ir_cc_name(in->cc));
            const IrOperand *ops[3] = { &in->dst, &in->a, &in->b };
            int first = 1;
            for (int j = 0; j < 3; j++) {
                if (ops[j]->kind == IR_O_NONE) continue;
                /* Skip call return-address imm (operand b of CALL). */
                if (in->op == IR_CALL && j == 2) continue;
                fputs(first ? " " : ", ", mem);
                norm_op(mem, m, ops[j], faddrs, m->nfuncs);
                first = 0;
            }
            fputc('\n', mem);
        }
    }
    fclose(mem);
    free(faddrs);
    return 0;
}

static int lift_path(const char *path, IrModule **outm, CfgProgram *outcfg, char *err, size_t errlen) {
    RexElf e;
    CfgProgram p;
    int rc = rex_bin_open(path, &e, err, errlen);
    if (rc) return rc;
    rc = cfg_build(&e, &p, err, errlen);
    if (rc) { rex_elf_free(&e); return rc; }
    IrModule *m = x86_lift(&p, err, errlen);
    if (!m) { cfg_free(&p); rex_elf_free(&e); return REX_E300_LIFT; }
    rex_elf_free(&e);
    *outm = m;
    *outcfg = p; /* caller frees */
    return 0;
}

int rex_verify_ir(const char *a, const char *b, char *err, size_t errlen, int code) {
    IrModule *ma = NULL, *mb = NULL;
    CfgProgram ca = {0}, cb = {0};
    int rc = lift_path(a, &ma, &ca, err, errlen);
    if (rc) return rc;
    rc = lift_path(b, &mb, &cb, err, errlen);
    if (rc) { ir_module_free(ma); cfg_free(&ca); return rc; }
    const IrFunc *fa = pick_main(ma, &ca), *fb = pick_main(mb, &cb);
    if (!fa || !fb) {
        ir_module_free(ma); ir_module_free(mb); cfg_free(&ca); cfg_free(&cb);
        return rex_errf(err, errlen, code, "could not find main to compare");
    }
    char *sa = NULL, *sb = NULL; size_t na = 0, nb = 0;
    rc = dump_func(ma, fa, &sa, &na, err, errlen);
    if (rc) { ir_module_free(ma); ir_module_free(mb); cfg_free(&ca); cfg_free(&cb); return rc; }
    rc = dump_func(mb, fb, &sb, &nb, err, errlen);
    if (rc) { free(sa); ir_module_free(ma); ir_module_free(mb); cfg_free(&ca); cfg_free(&cb); return rc; }
    if (!strcmp(sa, sb)) {
        free(sa); free(sb); ir_module_free(ma); ir_module_free(mb); cfg_free(&ca); cfg_free(&cb);
        return 0;
    }
    const char *pa = sa, *pb = sb;
    int line = 1;
    rc = rex_errf(err, errlen, code, "IR differs in main");
    for (;;) {
        const char *ea = strchr(pa, '\n'), *eb = strchr(pb, '\n');
        size_t la = ea ? (size_t)(ea - pa) : strlen(pa);
        size_t lb = eb ? (size_t)(eb - pb) : strlen(pb);
        if (la != lb || memcmp(pa, pb, la)) {
            char da[80], db[80];
            snprintf(da, sizeof(da), "%.*s", (int)(la < 70 ? la : 70), pa);
            snprintf(db, sizeof(db), "%.*s", (int)(lb < 70 ? lb : 70), pb);
            rc = rex_errf(err, errlen, code,
                          "IR differs at line %d: got \"%s\" vs \"%s\"", line, da, db);
            break;
        }
        if (!ea && !eb) break;
        if (!ea || !eb) {
            rc = rex_errf(err, errlen, code, "IR length differs after line %d", line);
            break;
        }
        pa = ea + 1; pb = eb + 1; line++;
    }
    free(sa); free(sb); ir_module_free(ma); ir_module_free(mb); cfg_free(&ca); cfg_free(&cb);
    return rc;
}
