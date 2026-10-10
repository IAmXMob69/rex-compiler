/* Differential tests: IR/x86 semantics vs host CPU (inline asm). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include "../src/ir.h"
#include "../src/x86_decode.h"

static int g_fail, g_ok, g_cases;
enum { F_CF = 1u, F_PF = 4u, F_ZF = 64u, F_SF = 128u, F_OF = 2048u };
enum { M_FLAGS = F_CF | F_PF | F_ZF | F_SF | F_OF };

static unsigned parity8(uint64_t v) {
    v &= 0xff; v ^= v >> 4; v ^= v >> 2; v ^= v >> 1;
    return (v & 1) ? 0 : F_PF;
}
static uint64_t mask_w(int w) { return w >= 8 ? ~0ull : (1ull << (w * 8)) - 1ull; }
static int64_t sext_w(uint64_t v, int w) {
    int bits = w * 8;
    if (bits >= 64) return (int64_t)v;
    uint64_t m = 1ull << (bits - 1);
    v &= (m << 1) - 1;
    return (int64_t)((v ^ m) - m);
}
typedef struct { uint64_t res; unsigned fl; } RF;

static RF eval_add(uint64_t a, uint64_t b, int w) {
    uint64_t m = mask_w(w); a &= m; b &= m;
    uint64_t r = (a + b) & m;
    unsigned fl = 0;
    if (r < a) fl |= F_CF;
    if (!r) fl |= F_ZF;
    if (r & (1ull << (w * 8 - 1))) fl |= F_SF;
    int64_t sa = sext_w(a, w), sb = sext_w(b, w), sr = sext_w(r, w);
    if ((sa >= 0 && sb >= 0 && sr < 0) || (sa < 0 && sb < 0 && sr >= 0)) fl |= F_OF;
    return (RF){ r, fl | parity8(r) };
}
static RF eval_sub(uint64_t a, uint64_t b, int w) {
    uint64_t m = mask_w(w); a &= m; b &= m;
    uint64_t r = (a - b) & m;
    unsigned fl = 0;
    if (a < b) fl |= F_CF;
    if (!r) fl |= F_ZF;
    if (r & (1ull << (w * 8 - 1))) fl |= F_SF;
    int64_t sa = sext_w(a, w), sb = sext_w(b, w), sr = sext_w(r, w);
    if ((sa >= 0 && sb < 0 && sr < 0) || (sa < 0 && sb >= 0 && sr >= 0)) fl |= F_OF;
    return (RF){ r, fl | parity8(r) };
}
static RF eval_logic(uint64_t a, uint64_t b, int w, char op) {
    uint64_t m = mask_w(w); a &= m; b &= m;
    uint64_t r = op == '&' ? (a & b) : op == '|' ? (a | b) : (a ^ b);
    r &= m;
    unsigned fl = (!r ? F_ZF : 0) | (r & (1ull << (w * 8 - 1)) ? F_SF : 0) | parity8(r);
    return (RF){ r, fl };
}
static RF eval_mul(uint64_t a, uint64_t b, int w) {
    uint64_t m = mask_w(w); a &= m; b &= m;
    __int128 prod = (__int128)sext_w(a, w) * (__int128)sext_w(b, w);
    uint64_t r = (uint64_t)prod & m;
    unsigned fl = parity8(r);
    if (!r) fl |= F_ZF;
    if (r & (1ull << (w * 8 - 1))) fl |= F_SF;
    if (prod != (__int128)sext_w(r, w)) fl |= F_CF | F_OF;
    return (RF){ r, fl };
}
static RF eval_shl(uint64_t a, uint64_t cnt, int w) {
    uint64_t m = mask_w(w); int bits = w * 8; a &= m;
    unsigned c = w < 8 ? (unsigned)(cnt & 31) : (unsigned)(cnt & 63);
    unsigned fl = 0;
    if (!c) return (RF){ a, 0xffffffffu };
    uint64_t r;
    if (c < (unsigned)bits) { if ((a >> ((unsigned)bits - c)) & 1) fl |= F_CF; r = (a << c) & m; }
    else if (c == (unsigned)bits) { if (a & 1) fl |= F_CF; r = 0; }
    else r = 0;
    if (!r) fl |= F_ZF;
    if (r & (1ull << (bits - 1))) fl |= F_SF;
    fl |= parity8(r);
    if (c == 1) { unsigned sb = (unsigned)((r >> (bits - 1)) & 1), cf = !!(fl & F_CF); if (sb ^ cf) fl |= F_OF; }
    return (RF){ r, fl };
}
static RF eval_shr(uint64_t a, uint64_t cnt, int w) {
    uint64_t m = mask_w(w); int bits = w * 8; a &= m;
    unsigned c = w < 8 ? (unsigned)(cnt & 31) : (unsigned)(cnt & 63);
    unsigned fl = 0;
    if (!c) return (RF){ a, 0xffffffffu };
    uint64_t r;
    if (c < (unsigned)bits) { if ((a >> (c - 1)) & 1) fl |= F_CF; r = (a >> c) & m; }
    else if (c == (unsigned)bits) { if ((a >> (bits - 1)) & 1) fl |= F_CF; r = 0; }
    else r = 0;
    if (!r) fl |= F_ZF;
    if (r & (1ull << (bits - 1))) fl |= F_SF;
    fl |= parity8(r);
    if (c == 1 && (a & (1ull << (bits - 1)))) fl |= F_OF;
    return (RF){ r, fl };
}
static RF eval_sar(uint64_t a, uint64_t cnt, int w) {
    uint64_t m = mask_w(w); int bits = w * 8; a &= m;
    unsigned c = w < 8 ? (unsigned)(cnt & 31) : (unsigned)(cnt & 63);
    unsigned fl = 0;
    if (!c) return (RF){ a, 0xffffffffu };
    int64_t sa = sext_w(a, w);
    uint64_t r;
    if (c >= (unsigned)bits) { r = sa < 0 ? m : 0; if (sa < 0) fl |= F_CF; }
    else { if ((sa >> (c - 1)) & 1) fl |= F_CF; r = (uint64_t)(sa >> c) & m; }
    if (!r) fl |= F_ZF;
    if (r & (1ull << (bits - 1))) fl |= F_SF;
    return (RF){ r, fl | parity8(r) };
}

#if defined(__x86_64__)
#define HAS_ASM 1
static RF host64(const char *op, uint64_t a, uint64_t b) {
    uint64_t r = a; unsigned long fl;
    if (!strcmp(op,"add")) __asm__ volatile("add %2,%0\n\tpushfq\n\tpop %1":"+r"(r),"=r"(fl):"r"(b):"cc");
    else if (!strcmp(op,"sub")) __asm__ volatile("sub %2,%0\n\tpushfq\n\tpop %1":"+r"(r),"=r"(fl):"r"(b):"cc");
    else if (!strcmp(op,"and")) __asm__ volatile("and %2,%0\n\tpushfq\n\tpop %1":"+r"(r),"=r"(fl):"r"(b):"cc");
    else if (!strcmp(op,"or")) __asm__ volatile("or %2,%0\n\tpushfq\n\tpop %1":"+r"(r),"=r"(fl):"r"(b):"cc");
    else if (!strcmp(op,"xor")) __asm__ volatile("xor %2,%0\n\tpushfq\n\tpop %1":"+r"(r),"=r"(fl):"r"(b):"cc");
    else if (!strcmp(op,"imul")) __asm__ volatile("imul %2,%0\n\tpushfq\n\tpop %1":"+r"(r),"=r"(fl):"r"(b):"cc");
    else if (!strcmp(op,"cmp")) { __asm__ volatile("cmp %2,%0\n\tpushfq\n\tpop %1":"+r"(r),"=r"(fl):"r"(b):"cc"); r=a; }
    else if (!strcmp(op,"test")) { __asm__ volatile("test %2,%0\n\tpushfq\n\tpop %1":"+r"(r),"=r"(fl):"r"(b):"cc"); r=a; }
    else return (RF){0,0};
    return (RF){r,(unsigned)(fl&M_FLAGS)};
}
static RF host32(const char *op, uint64_t a, uint64_t b) {
    uint32_t r=(uint32_t)a, bb=(uint32_t)b; unsigned long fl;
    if (!strcmp(op,"add")) __asm__ volatile("add %2,%0\n\tpushfq\n\tpop %1":"+r"(r),"=r"(fl):"r"(bb):"cc");
    else if (!strcmp(op,"sub")) __asm__ volatile("sub %2,%0\n\tpushfq\n\tpop %1":"+r"(r),"=r"(fl):"r"(bb):"cc");
    else if (!strcmp(op,"and")) __asm__ volatile("and %2,%0\n\tpushfq\n\tpop %1":"+r"(r),"=r"(fl):"r"(bb):"cc");
    else if (!strcmp(op,"or")) __asm__ volatile("or %2,%0\n\tpushfq\n\tpop %1":"+r"(r),"=r"(fl):"r"(bb):"cc");
    else if (!strcmp(op,"xor")) __asm__ volatile("xor %2,%0\n\tpushfq\n\tpop %1":"+r"(r),"=r"(fl):"r"(bb):"cc");
    else if (!strcmp(op,"imul")) __asm__ volatile("imul %2,%0\n\tpushfq\n\tpop %1":"+r"(r),"=r"(fl):"r"(bb):"cc");
    else if (!strcmp(op,"cmp")) { __asm__ volatile("cmp %2,%0\n\tpushfq\n\tpop %1":"+r"(r),"=r"(fl):"r"(bb):"cc"); return (RF){(uint32_t)a,(unsigned)(fl&M_FLAGS)}; }
    else if (!strcmp(op,"test")) { __asm__ volatile("test %2,%0\n\tpushfq\n\tpop %1":"+r"(r),"=r"(fl):"r"(bb):"cc"); return (RF){(uint32_t)a,(unsigned)(fl&M_FLAGS)}; }
    else return (RF){0,0};
    return (RF){r,(unsigned)(fl&M_FLAGS)};
}
static RF host16(const char *op, uint64_t a, uint64_t b) {
    uint16_t r=(uint16_t)a, bb=(uint16_t)b; unsigned long fl;
    if (!strcmp(op,"add")) __asm__ volatile("add %2,%0\n\tpushfq\n\tpop %1":"+r"(r),"=r"(fl):"r"(bb):"cc");
    else if (!strcmp(op,"sub")) __asm__ volatile("sub %2,%0\n\tpushfq\n\tpop %1":"+r"(r),"=r"(fl):"r"(bb):"cc");
    else if (!strcmp(op,"and")) __asm__ volatile("and %2,%0\n\tpushfq\n\tpop %1":"+r"(r),"=r"(fl):"r"(bb):"cc");
    else if (!strcmp(op,"or")) __asm__ volatile("or %2,%0\n\tpushfq\n\tpop %1":"+r"(r),"=r"(fl):"r"(bb):"cc");
    else if (!strcmp(op,"xor")) __asm__ volatile("xor %2,%0\n\tpushfq\n\tpop %1":"+r"(r),"=r"(fl):"r"(bb):"cc");
    else if (!strcmp(op,"imul")) __asm__ volatile("imul %2,%0\n\tpushfq\n\tpop %1":"+r"(r),"=r"(fl):"r"(bb):"cc");
    else if (!strcmp(op,"cmp")) { __asm__ volatile("cmp %2,%0\n\tpushfq\n\tpop %1":"+r"(r),"=r"(fl):"r"(bb):"cc"); return (RF){(uint16_t)a,(unsigned)(fl&M_FLAGS)}; }
    else if (!strcmp(op,"test")) { __asm__ volatile("test %2,%0\n\tpushfq\n\tpop %1":"+r"(r),"=r"(fl):"r"(bb):"cc"); return (RF){(uint16_t)a,(unsigned)(fl&M_FLAGS)}; }
    else return (RF){0,0};
    return (RF){r,(unsigned)(fl&M_FLAGS)};
}
static RF host8(const char *op, uint64_t a, uint64_t b) {
    uint8_t r=(uint8_t)a, bb=(uint8_t)b; unsigned long fl;
    if (!strcmp(op,"imul")) return eval_mul(a,b,1);
    if (!strcmp(op,"add")) __asm__ volatile("add %2,%0\n\tpushfq\n\tpop %1":"+q"(r),"=r"(fl):"q"(bb):"cc");
    else if (!strcmp(op,"sub")) __asm__ volatile("sub %2,%0\n\tpushfq\n\tpop %1":"+q"(r),"=r"(fl):"q"(bb):"cc");
    else if (!strcmp(op,"and")) __asm__ volatile("and %2,%0\n\tpushfq\n\tpop %1":"+q"(r),"=r"(fl):"q"(bb):"cc");
    else if (!strcmp(op,"or")) __asm__ volatile("or %2,%0\n\tpushfq\n\tpop %1":"+q"(r),"=r"(fl):"q"(bb):"cc");
    else if (!strcmp(op,"xor")) __asm__ volatile("xor %2,%0\n\tpushfq\n\tpop %1":"+q"(r),"=r"(fl):"q"(bb):"cc");
    else if (!strcmp(op,"cmp")) { __asm__ volatile("cmp %2,%0\n\tpushfq\n\tpop %1":"+q"(r),"=r"(fl):"q"(bb):"cc"); return (RF){(uint8_t)a,(unsigned)(fl&M_FLAGS)}; }
    else if (!strcmp(op,"test")) { __asm__ volatile("test %2,%0\n\tpushfq\n\tpop %1":"+q"(r),"=r"(fl):"q"(bb):"cc"); return (RF){(uint8_t)a,(unsigned)(fl&M_FLAGS)}; }
    else return (RF){0,0};
    return (RF){r,(unsigned)(fl&M_FLAGS)};
}
static RF host_shift(int w, const char *op, uint64_t a, uint64_t c) {
    unsigned char cl=(unsigned char)c; unsigned long fl; unsigned sm = w<8?31u:63u;
    if (w==8) {
        uint64_t r=a;
        if (!strcmp(op,"shl")) __asm__ volatile("shl %%cl,%0\n\tpushfq\n\tpop %1":"+r"(r),"=r"(fl):"c"(cl):"cc");
        else if (!strcmp(op,"shr")) __asm__ volatile("shr %%cl,%0\n\tpushfq\n\tpop %1":"+r"(r),"=r"(fl):"c"(cl):"cc");
        else __asm__ volatile("sar %%cl,%0\n\tpushfq\n\tpop %1":"+r"(r),"=r"(fl):"c"(cl):"cc");
        if ((c&sm)==0) return (RF){a,0xffffffffu};
        return (RF){r,(unsigned)(fl&M_FLAGS)};
    } else if (w==4) {
        uint32_t r=(uint32_t)a;
        if (!strcmp(op,"shl")) __asm__ volatile("shl %%cl,%0\n\tpushfq\n\tpop %1":"+r"(r),"=r"(fl):"c"(cl):"cc");
        else if (!strcmp(op,"shr")) __asm__ volatile("shr %%cl,%0\n\tpushfq\n\tpop %1":"+r"(r),"=r"(fl):"c"(cl):"cc");
        else __asm__ volatile("sar %%cl,%0\n\tpushfq\n\tpop %1":"+r"(r),"=r"(fl):"c"(cl):"cc");
        if ((c&sm)==0) return (RF){(uint32_t)a,0xffffffffu};
        return (RF){r,(unsigned)(fl&M_FLAGS)};
    } else if (w==2) {
        uint16_t r=(uint16_t)a;
        if (!strcmp(op,"shl")) __asm__ volatile("shl %%cl,%0\n\tpushfq\n\tpop %1":"+r"(r),"=r"(fl):"c"(cl):"cc");
        else if (!strcmp(op,"shr")) __asm__ volatile("shr %%cl,%0\n\tpushfq\n\tpop %1":"+r"(r),"=r"(fl):"c"(cl):"cc");
        else __asm__ volatile("sar %%cl,%0\n\tpushfq\n\tpop %1":"+r"(r),"=r"(fl):"c"(cl):"cc");
        if ((c&sm)==0) return (RF){(uint16_t)a,0xffffffffu};
        return (RF){r,(unsigned)(fl&M_FLAGS)};
    } else {
        uint8_t r=(uint8_t)a;
        if (!strcmp(op,"shl")) __asm__ volatile("shl %%cl,%0\n\tpushfq\n\tpop %1":"+q"(r),"=r"(fl):"c"(cl):"cc");
        else if (!strcmp(op,"shr")) __asm__ volatile("shr %%cl,%0\n\tpushfq\n\tpop %1":"+q"(r),"=r"(fl):"c"(cl):"cc");
        else __asm__ volatile("sar %%cl,%0\n\tpushfq\n\tpop %1":"+q"(r),"=r"(fl):"c"(cl):"cc");
        if ((c&sm)==0) return (RF){(uint8_t)a,0xffffffffu};
        return (RF){r,(unsigned)(fl&M_FLAGS)};
    }
}
static RF host_binop(int w, const char *op, uint64_t a, uint64_t b) {
    if (w==8) return host64(op,a,b);
    if (w==4) return host32(op,a,b);
    if (w==2) return host16(op,a,b);
    return host8(op,a,b);
}
#else
#define HAS_ASM 0
static RF host_binop(int w, const char *op, uint64_t a, uint64_t b) { (void)w;(void)op;(void)a;(void)b; return (RF){0,0}; }
static RF host_shift(int w, const char *op, uint64_t a, uint64_t c) { (void)w;(void)op;(void)a;(void)c; return (RF){0,0}; }
#endif

static uint64_t xr(uint64_t *s) { uint64_t x=*s; x^=x>>12; x^=x<<25; x^=x>>27; *s=x; return x*0x2545F4914F6CDD1Dull; }
static const uint64_t EDGES[] = {
    0,1,2,0xff,0x7f,0x80,0xffff,0x7fff,0x8000,0x7fffffffULL,0x80000000ULL,0xffffffffULL,
    0x7fffffffffffffffULL,0x8000000000000000ULL,~0ull
};
static const uint64_t SHIFTS[] = {0,1,7,8,15,16,31,32,63,64,65,127,255};

static RF ir_binop(const char *op, uint64_t a, uint64_t b, int w) {
    if (!strcmp(op,"add")) return eval_add(a,b,w);
    if (!strcmp(op,"sub")||!strcmp(op,"cmp")) { RF e=eval_sub(a,b,w); if (!strcmp(op,"cmp")) e.res=a&mask_w(w); return e; }
    if (!strcmp(op,"and")||!strcmp(op,"test")) { RF e=eval_logic(a,b,w,'&'); if (!strcmp(op,"test")) e.res=a&mask_w(w); return e; }
    if (!strcmp(op,"or")) return eval_logic(a,b,w,'|');
    if (!strcmp(op,"xor")) return eval_logic(a,b,w,'^');
    if (!strcmp(op,"imul")) return eval_mul(a,b,w);
    return (RF){0,0};
}
static RF ir_shift(const char *op, uint64_t a, uint64_t c, int w) {
    if (!strcmp(op,"shl")) return eval_shl(a,c,w);
    if (!strcmp(op,"shr")) return eval_shr(a,c,w);
    return eval_sar(a,c,w);
}

static void check(const char *tag, uint64_t a, uint64_t b, int w, RF h, RF e, unsigned mask) {
    g_cases++;
    if (h.fl == 0xffffffffu) { if (h.res!=e.res) { if (g_fail<20) printf("FAIL %s\n", tag); g_fail++; } else g_ok++; return; }
    if (h.res!=e.res || ((h.fl^e.fl)&mask)) {
        if (g_fail<20) printf("FAIL %s w=%d a=%#" PRIx64 " b=%#" PRIx64 " h=%#" PRIx64 "/%#x e=%#" PRIx64 "/%#x\n",
            tag,w,a,b,h.res,h.fl&mask,e.res,e.fl&mask);
        g_fail++;
    } else g_ok++;
}

static void run_binop(const char *op, int w) {
    uint64_t m=mask_w(w);
    for (size_t i=0;i<sizeof(EDGES)/sizeof(EDGES[0]);i++)
        for (size_t j=0;j<sizeof(EDGES)/sizeof(EDGES[0]);j++) {
            uint64_t a=EDGES[i]&m, b=EDGES[j]&m;
            RF h=host_binop(w,op,a,b), e=ir_binop(op,a,b,w);
            unsigned mask = !strcmp(op,"imul") ? (F_CF|F_OF) : M_FLAGS;
            if (!strcmp(op,"imul")) { g_cases++; if (h.res!=e.res||((h.fl^e.fl)&mask)) g_fail++; else g_ok++; }
            else check(op,a,b,w,h,e,mask);
        }
    uint64_t rng=0xC0FFEEULL^(uint64_t)w<<40^(uint64_t)op[0];
    for (int n=0;n<200;n++) {
        uint64_t a=xr(&rng)&m, b=xr(&rng)&m;
        RF h=host_binop(w,op,a,b), e=ir_binop(op,a,b,w);
        unsigned mask = !strcmp(op,"imul") ? (F_CF|F_OF) : M_FLAGS;
        if (!strcmp(op,"imul")) { g_cases++; if (h.res!=e.res||((h.fl^e.fl)&mask)) g_fail++; else g_ok++; }
        else check(op,a,b,w,h,e,mask);
    }
}
static void run_shift(const char *op, int w) {
    uint64_t m=mask_w(w);
    for (size_t i=0;i<sizeof(EDGES)/sizeof(EDGES[0]);i++)
        for (size_t j=0;j<sizeof(SHIFTS)/sizeof(SHIFTS[0]);j++) {
            uint64_t a=EDGES[i]&m, c=SHIFTS[j];
            RF h=host_shift(w,op,a,c), e=ir_shift(op,a,c,w);
            unsigned sm=w<8?31u:63u, cnt=(unsigned)c&sm;
            unsigned mask = F_CF|F_PF|F_ZF|F_SF | (cnt==1?F_OF:0);
            check(op,a,c,w,h,e,mask);
        }
    uint64_t rng=0xBADC0DEULL^(uint64_t)w<<32;
    for (int n=0;n<200;n++) {
        uint64_t a=xr(&rng)&m, c=xr(&rng)&0xff;
        RF h=host_shift(w,op,a,c), e=ir_shift(op,a,c,w);
        unsigned sm=w<8?31u:63u, cnt=(unsigned)c&sm;
        check(op,a,c,w,h,e,F_CF|F_PF|F_ZF|F_SF|(cnt==1?F_OF:0));
    }
}

static int cc_holds(IrCond c, unsigned fl) {
    int cf=!!(fl&F_CF), zf=!!(fl&F_ZF), sf=!!(fl&F_SF), of=!!(fl&F_OF);
    switch (c) {
    case IR_CC_EQ: return zf; case IR_CC_NE: return !zf;
    case IR_CC_LT: return sf!=of; case IR_CC_LE: return zf||sf!=of;
    case IR_CC_GT: return !zf&&sf==of; case IR_CC_GE: return sf==of;
    case IR_CC_ULT: return cf; case IR_CC_ULE: return cf||zf;
    case IR_CC_UGT: return !cf&&!zf; case IR_CC_UGE: return !cf;
    case IR_CC_NEG: return sf; case IR_CC_POS: return !sf;
    default: return 0;
    }
}

int main(void) {
#if !HAS_ASM
    printf("cpu diff: SKIP\n"); return 0;
#endif
    const char *binops[] = {"add","sub","and","or","xor","cmp","test"};
    const char *shifts[] = {"shl","shr","sar"};
    int widths[] = {1,2,4,8};
    for (size_t o=0;o<sizeof(binops)/sizeof(*binops);o++)
        for (size_t w=0;w<sizeof(widths)/sizeof(*widths);w++) run_binop(binops[o], widths[w]);
    for (size_t w=1;w<sizeof(widths)/sizeof(*widths);w++) run_binop("imul", widths[w]);
    for (size_t o=0;o<sizeof(shifts)/sizeof(*shifts);o++)
        for (size_t w=0;w<sizeof(widths)/sizeof(*widths);w++) run_shift(shifts[o], widths[w]);
    /* unary neg/not */
    for (int w=1;w<=8;w*=2) {
        uint64_t m=mask_w(w);
        for (size_t i=0;i<sizeof(EDGES)/sizeof(*EDGES);i++) {
            uint64_t a=EDGES[i]&m;
            RF hn, en=eval_sub(0,a,w);
            if (w==8) { uint64_t r=a; unsigned long fl; __asm__ volatile("neg %0\n\tpushfq\n\tpop %1":"+r"(r),"=r"(fl)::"cc"); hn=(RF){r,(unsigned)(fl&M_FLAGS)}; }
            else if (w==4) { uint32_t r=(uint32_t)a; unsigned long fl; __asm__ volatile("neg %0\n\tpushfq\n\tpop %1":"+r"(r),"=r"(fl)::"cc"); hn=(RF){r,(unsigned)(fl&M_FLAGS)}; }
            else if (w==2) { uint16_t r=(uint16_t)a; unsigned long fl; __asm__ volatile("neg %0\n\tpushfq\n\tpop %1":"+r"(r),"=r"(fl)::"cc"); hn=(RF){r,(unsigned)(fl&M_FLAGS)}; }
            else { uint8_t r=(uint8_t)a; unsigned long fl; __asm__ volatile("neg %0\n\tpushfq\n\tpop %1":"+q"(r),"=r"(fl)::"cc"); hn=(RF){r,(unsigned)(fl&M_FLAGS)}; }
            check("neg",a,0,w,hn,en,M_FLAGS);
            RF hnot=(RF){(~a)&m,0};
            g_cases++; if (hnot.res != ((~a)&m)) g_fail++; else g_ok++;
            (void)en; (void)hnot;
        }
    }
    /* condition codes */
    IrCond all[] = {IR_CC_EQ,IR_CC_NE,IR_CC_LT,IR_CC_LE,IR_CC_GT,IR_CC_GE,IR_CC_ULT,IR_CC_ULE,IR_CC_UGT,IR_CC_UGE};
    for (int w=1;w<=8;w*=2) {
        uint64_t m=mask_w(w);
        for (size_t i=0;i<sizeof(EDGES)/sizeof(*EDGES);i++)
            for (size_t j=0;j<sizeof(EDGES)/sizeof(*EDGES);j++) {
                uint64_t a=EDGES[i]&m, b=EDGES[j]&m;
                RF h=host_binop(w,"cmp",a,b), e=ir_binop("cmp",a,b,w);
                for (size_t k=0;k<sizeof(all)/sizeof(*all);k++) {
                    g_cases++;
                    if (cc_holds(all[k],h.fl)!=cc_holds(all[k],e.fl)) g_fail++; else g_ok++;
                }
            }
    }
    /* 32-bit zero-extend */
    for (uint64_t a=0xffffffffULL;; a = (a==0xffffffffULL)?0x80000000ULL : (a==0x80000000ULL)?1:0) {
        RF h=host_binop(4,"add",a,1);
        g_cases++; if ((h.res>>32)!=0) g_fail++; else g_ok++;
        if (a==1) break;
    }
    /* wraparound fold */
    g_cases++; if (((0x7fffffffULL+1)&0xffffffffULL)!=0x80000000ULL) g_fail++; else g_ok++;
    g_cases++; if (((uint64_t)(int64_t)0x7fffffffffffffffLL+1)!=0x8000000000000000ULL) g_fail++; else g_ok++;
    /* decode smoke */
    unsigned char add64[]={0x48,0x01,0xc8}; X86Insn xi;
    g_cases++; if (x86_decode(add64,3,0x1000,&xi)<=0||xi.op!=X86_ADD) g_fail++; else g_ok++;
    unsigned char sar64[]={0x48,0xd3,0xf8};
    g_cases++; if (x86_decode(sar64,3,0x1000,&xi)<=0||xi.op!=X86_SAR) g_fail++; else g_ok++;
    printf("cpu diff: %d ok, %d fail, %d cases\n", g_ok, g_fail, g_cases);
    return g_fail?1:0;
}
