#define _GNU_SOURCE
#include "verify.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include "rex_err.h"
#include "loader.h"
#include "cfg.h"
#include "x86_lift.h"
#include "ir.h"

static int run_capture(const char *bin, char *out, size_t outn, int *status) {
    int p[2];
    if (pipe(p)) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(p[0]); close(p[1]); return -1; }
    if (pid == 0) {
        dup2(p[1], 1); dup2(p[1], 2); close(p[0]); close(p[1]);
        execl(bin, bin, (char *)NULL);
        _exit(127);
    }
    close(p[1]);
    size_t n = 0;
    for (;;) {
        if (n + 1 >= outn) { char sink[256]; if (read(p[0], sink, sizeof(sink)) <= 0) break; continue; }
        ssize_t r = read(p[0], out + n, outn - 1 - n);
        if (r <= 0) break;
        n += (size_t)r;
    }
    out[n] = 0;
    close(p[0]);
    int st = 0; waitpid(pid, &st, 0);
    *status = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    return 0;
}

int rex_verify_bins(const char *a, const char *b, char *err, size_t errlen) {
    char oa[1 << 16], ob[1 << 16];
    int sa, sb;
    if (run_capture(a, oa, sizeof(oa), &sa) || run_capture(b, ob, sizeof(ob), &sb))
        return rex_errf(err, errlen, REX_E501_VERIFY, "could not run binaries");
    if (sa != sb)
        return rex_errf(err, errlen, REX_E501_VERIFY, "exit %d vs %d", sa, sb);
    if (strcmp(oa, ob))
        return rex_errf(err, errlen, REX_E501_VERIFY, "stdout/stderr differ");
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

int rex_verify_ir(const char *a, const char *b, char *err, size_t errlen) {
    IrModule *ma = NULL, *mb = NULL;
    CfgProgram ca = {0}, cb = {0};
    int rc = lift_path(a, &ma, &ca, err, errlen);
    if (rc) return rc;
    rc = lift_path(b, &mb, &cb, err, errlen);
    if (rc) { ir_module_free(ma); cfg_free(&ca); return rc; }
    const IrFunc *fa = pick_main(ma, &ca), *fb = pick_main(mb, &cb);
    if (!fa || !fb) {
        ir_module_free(ma); ir_module_free(mb); cfg_free(&ca); cfg_free(&cb);
        return rex_errf(err, errlen, REX_E501_VERIFY, "could not find main to compare");
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
    rc = rex_errf(err, errlen, REX_E501_VERIFY, "IR differs in main");
    for (;;) {
        const char *ea = strchr(pa, '\n'), *eb = strchr(pb, '\n');
        size_t la = ea ? (size_t)(ea - pa) : strlen(pa);
        size_t lb = eb ? (size_t)(eb - pb) : strlen(pb);
        if (la != lb || memcmp(pa, pb, la)) {
            char da[80], db[80];
            snprintf(da, sizeof(da), "%.*s", (int)(la < 70 ? la : 70), pa);
            snprintf(db, sizeof(db), "%.*s", (int)(lb < 70 ? lb : 70), pb);
            rc = rex_errf(err, errlen, REX_E501_VERIFY,
                          "IR differs at line %d: got \"%s\" vs \"%s\"", line, da, db);
            break;
        }
        if (!ea && !eb) break;
        if (!ea || !eb) {
            rc = rex_errf(err, errlen, REX_E501_VERIFY, "IR length differs after line %d", line);
            break;
        }
        pa = ea + 1; pb = eb + 1; line++;
    }
    free(sa); free(sb); ir_module_free(ma); ir_module_free(mb); cfg_free(&ca); cfg_free(&cb);
    return rc;
}
