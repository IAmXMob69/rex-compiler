/* Differential check for packed-integer SSE lanes.
 * For many input vectors, every packed op is computed two ways: on the real CPU
 * via inline asm (result -> S) and by a plain-C per-lane reference (result -> R).
 * Any byte where S and R disagree sets the global BAD, and main returns BAD. So
 * the exit code is 0 exactly when the real CPU and the reference agree on every
 * op and vector. `rex match` runs this binary (real SSE) against the recovered
 * REX source (rex's recovered lane model) and compares exit codes, so a wrong
 * lane, shuffle immediate, qword shift or wraparound in the recovered model
 * makes the recovered run return nonzero while the original returns zero.
 *
 * Shape notes so the test exercises only the SSE lanes, not unrelated decompiler
 * quirks: no syscall anywhere in main (keeps main decompilable); the mismatch
 * check (CHK) is a macro inlined at the END of each helper, never a trailing call
 * (a function that ends in a call is mis-recovered by the current decompiler, so
 * a trailing chk() would be silently dropped and the test would lose its teeth);
 * helpers return void and fold into a global accumulator; split into small
 * helpers to stay under REX's local-variable cap; no .rodata, so the gmem blob
 * stays small. Built like the game samples (rt.h _start -> main). */
#include "rt.h"
typedef unsigned long u64; typedef unsigned int u32; typedef unsigned short u16; typedef unsigned char u8;
typedef signed char s8; typedef short s16; typedef int s32;

#define NV 24
static u8 V[NV][16];
static u8 S[16], R[16];
static int BAD;

static u32 g32(const u8 *p, int i){ u32 v; memcpy(&v, p+i*4, 4); return v; }
static void p32(u8 *p, int i, u32 v){ memcpy(p+i*4, &v, 4); }
static u16 g16(const u8 *p, int i){ u16 v; memcpy(&v, p+i*2, 2); return v; }
static void p16(u8 *p, int i, u16 v){ memcpy(p+i*2, &v, 2); }
static u64 g64(const u8 *p, int i){ u64 v; memcpy(&v, p+i*8, 8); return v; }
static void p64(u8 *p, int i, u64 v){ memcpy(p+i*8, &v, 8); }
static u8  g8 (const u8 *p, int i){ u8 v; memcpy(&v, p+i, 1); return v; }
static void p8 (u8 *p, int i, u8 v){ memcpy(p+i, &v, 1); }

#define CHK() do { for (int ci=0; ci<16; ci++) BAD |= (S[ci]!=R[ci]); } while (0)
#define BIN(insn, a, b) __asm__ volatile("movdqu (%1),%%xmm0\n\tmovdqu (%2),%%xmm1\n\t" insn " %%xmm1,%%xmm0\n\tmovdqu %%xmm0,(%0)"::"r"(S),"r"(a),"r"(b):"xmm0","xmm1","memory")
#define UN(insn, a)    __asm__ volatile("movdqu (%1),%%xmm0\n\t" insn " %%xmm0\n\tmovdqu %%xmm0,(%0)"::"r"(S),"r"(a):"xmm0","memory")
#define SHUF(a, IMM)   __asm__ volatile("movdqu (%1),%%xmm0\n\tpshufd $0x" #IMM ",%%xmm0,%%xmm1\n\tmovdqu %%xmm1,(%0)"::"r"(S),"r"(a):"xmm0","xmm1","memory")

static void t_paddd(const u8*a,const u8*b){ BIN("paddd",a,b);  for(int d=0;d<4;d++) p32(R,d, g32(a,d)+g32(b,d)); CHK(); }
static void t_psubd(const u8*a,const u8*b){ BIN("psubd",a,b);  for(int d=0;d<4;d++) p32(R,d, g32(a,d)-g32(b,d)); CHK(); }
static void t_pand (const u8*a,const u8*b){ BIN("pand",a,b);   for(int d=0;d<4;d++) p32(R,d, g32(a,d)&g32(b,d)); CHK(); }
static void t_por  (const u8*a,const u8*b){ BIN("por",a,b);    for(int d=0;d<4;d++) p32(R,d, g32(a,d)|g32(b,d)); CHK(); }
static void t_pxor (const u8*a,const u8*b){ BIN("pxor",a,b);   for(int d=0;d<4;d++) p32(R,d, g32(a,d)^g32(b,d)); CHK(); }
static void t_eqb(const u8*a,const u8*b){ BIN("pcmpeqb",a,b); for(int i=0;i<16;i++) p8(R,i, g8(a,i)==g8(b,i)?0xff:0); CHK(); }
static void t_eqw(const u8*a,const u8*b){ BIN("pcmpeqw",a,b); for(int i=0;i<8;i++) p16(R,i, g16(a,i)==g16(b,i)?0xffff:0); CHK(); }
static void t_eqd(const u8*a,const u8*b){ BIN("pcmpeqd",a,b); for(int d=0;d<4;d++) p32(R,d, g32(a,d)==g32(b,d)?0xffffffffu:0); CHK(); }
static void t_gtb(const u8*a,const u8*b){ BIN("pcmpgtb",a,b); for(int i=0;i<16;i++) p8(R,i, (s8)g8(a,i)>(s8)g8(b,i)?0xff:0); CHK(); }
static void t_gtw(const u8*a,const u8*b){ BIN("pcmpgtw",a,b); for(int i=0;i<8;i++) p16(R,i,(s16)g16(a,i)>(s16)g16(b,i)?0xffff:0); CHK(); }
static void t_gtd(const u8*a,const u8*b){ BIN("pcmpgtd",a,b); for(int d=0;d<4;d++) p32(R,d,(s32)g32(a,d)>(s32)g32(b,d)?0xffffffffu:0); CHK(); }
static void t_lbw(const u8*a,const u8*b){ BIN("punpcklbw",a,b); for(int i=0;i<8;i++){p8(R,2*i,g8(a,i));p8(R,2*i+1,g8(b,i));} CHK(); }
static void t_hbw(const u8*a,const u8*b){ BIN("punpckhbw",a,b); for(int i=0;i<8;i++){p8(R,2*i,g8(a,8+i));p8(R,2*i+1,g8(b,8+i));} CHK(); }
static void t_lwd(const u8*a,const u8*b){ BIN("punpcklwd",a,b); for(int i=0;i<4;i++){p16(R,2*i,g16(a,i));p16(R,2*i+1,g16(b,i));} CHK(); }
static void t_hwd(const u8*a,const u8*b){ BIN("punpckhwd",a,b); for(int i=0;i<4;i++){p16(R,2*i,g16(a,4+i));p16(R,2*i+1,g16(b,4+i));} CHK(); }
static void t_ldq(const u8*a,const u8*b){ BIN("punpckldq",a,b); p32(R,0,g32(a,0));p32(R,1,g32(b,0));p32(R,2,g32(a,1));p32(R,3,g32(b,1)); CHK(); }
static void t_hdq(const u8*a,const u8*b){ BIN("punpckhdq",a,b); p32(R,0,g32(a,2));p32(R,1,g32(b,2));p32(R,2,g32(a,3));p32(R,3,g32(b,3)); CHK(); }
static void t_lqdq(const u8*a,const u8*b){ BIN("punpcklqdq",a,b); p64(R,0,g64(a,0));p64(R,1,g64(b,0)); CHK(); }
static void t_hqdq(const u8*a,const u8*b){ BIN("punpckhqdq",a,b); p64(R,0,g64(a,1));p64(R,1,g64(b,1)); CHK(); }

#define SH(name, IMM) static void name(const u8*a){ SHUF(a,IMM); u32 d0=g32(a,0),d1=g32(a,1),d2=g32(a,2),d3=g32(a,3); u32 dw[4]; dw[0]=d0;dw[1]=d1;dw[2]=d2;dw[3]=d3; for(int d=0;d<4;d++) p32(R,d, dw[(0x##IMM>>(2*d))&3]); CHK(); }
SH(s00,00) SH(s4e,4e) SH(se5,e5) SH(sff,ff) SH(s1b,1b) SH(s39,39) SH(s93,93) SH(sb1,b1) SH(sc6,c6)

#define RL(name, C) static void name(const u8*a){ UN("psrlq $" #C ",",a); for(int q=0;q<2;q++) p64(R,q, (C)>=64?0:g64(a,q)>>(C)); CHK(); }
#define LL(name, C) static void name(const u8*a){ UN("psllq $" #C ",",a); for(int q=0;q<2;q++) p64(R,q, (C)>=64?0:g64(a,q)<<(C)); CHK(); }
RL(rl1,1) RL(rl7,7) RL(rl32,32) RL(rl63,63)
LL(ll1,1) LL(ll7,7) LL(ll32,32) LL(ll63,63)

static void setrow(int i, u32 a, u32 b, u32 c, u32 d){ p32(V[i],0,a); p32(V[i],1,b); p32(V[i],2,c); p32(V[i],3,d); }
static void gen(void){
    setrow(0,0,0,0,0);
    setrow(1,0xffffffffu,0xffffffffu,0xffffffffu,0xffffffffu);
    setrow(2,0x7fffffffu,0x80000000u,1,0xffffffffu);
    setrow(3,0x80000000u,0x80000000u,0x80000000u,0x80000000u);
    setrow(4,1,2,3,4);
    setrow(5,0x00ff00ffu,0xff00ff00u,0x0f0f0f0fu,0xf0f0f0f0u);
    setrow(6,0x7f7f7f7fu,0x80808080u,0x01010101u,0xfefefefeu);
    setrow(7,0x12345678u,0x9abcdef0u,0x0f1e2d3cu,0x4b5a6978u);
    u64 s = 0x9e3779b97f4a7c15ull;
    for (int i=8;i<NV;i++) for (int j=0;j<16;j++){ s=s*6364136223846793005ull+1442695040888963407ull; V[i][j]=(u8)(s>>33); }
}

int main(void) {
    gen();
    BAD = 0;
    for (int ii=0; ii<NV; ii++) for (int jj=0; jj<NV; jj++) {
        const u8 *a=V[ii], *b=V[jj];
        t_paddd(a,b); t_psubd(a,b); t_pand(a,b); t_por(a,b); t_pxor(a,b);
        t_eqb(a,b); t_eqw(a,b); t_eqd(a,b); t_gtb(a,b); t_gtw(a,b); t_gtd(a,b);
        t_lbw(a,b); t_hbw(a,b); t_lwd(a,b); t_hwd(a,b);
        t_ldq(a,b); t_hdq(a,b); t_lqdq(a,b); t_hqdq(a,b);
    }
    for (int ii=0; ii<NV; ii++) {
        const u8 *a=V[ii];
        s00(a); s4e(a); se5(a); sff(a); s1b(a); s39(a); s93(a); sb1(a); sc6(a);
        rl1(a); rl7(a); rl32(a); rl63(a); ll1(a); ll7(a); ll32(a); ll63(a);
    }
    return BAD;
}
