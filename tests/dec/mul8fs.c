/* 8/16-bit one-operand mul/imul rebuilt by rex compare and recovered by
 * rex match: ax = al * src, dx:ax = ax * src. rax and rdx come in with
 * other bits set, and all 64 bits are read after, so a lift that loses
 * the bits above the 16 written shows. No C library, or with -DMAIN a main
 * for rex match (exit status folds all 64 bits). tests/dyn.sh */
typedef unsigned long u64;
#define F(name, insn, ...) __attribute__((noinline)) u64 name(u64 a, u64 b){ u64 x = a, d = ~b; \
    __asm__(insn : "+a"(x), "+d"(d) : __VA_ARGS__ : "cc"); return x ^ (d * 7); }
F(mb, "mulb %b2", "c"(b))
F(ib, "imulb %b2", "c"(b))
F(mbs, "mulb %%sil", "S"(b))
F(mba, "mulb %%al", "c"(b))
F(mbm, "mulb %2", "m"(*(unsigned char *)&b))
F(ibm, "imulb %2", "m"(*(unsigned char *)&b))
F(mw, "mulw %w2", "c"(b))
F(iw, "imulw %w2", "c"(b))
F(mwa, "mulw %%ax", "c"(b))
F(iwm, "imulw %2", "m"(*(unsigned short *)&b))
F(mwr, "mulw %w2", "r"(b ^ 0x1234))
__attribute__((noinline)) u64 mwd(u64 a, u64 b){ u64 x = a, d = b; __asm__("mulw %%dx" : "+a"(x), "+d"(d) :: "cc"); return x ^ (d * 7); }
__attribute__((noinline)) u64 iwd(u64 a, u64 b){ u64 x = a, d = b; __asm__("imulw %%dx" : "+a"(x), "+d"(d) :: "cc"); return x ^ (d * 7); }
__attribute__((noinline)) u64 mwp(u64 a, u64 b){ unsigned short v = (unsigned short)b; u64 x = a, d = (u64)&v;
    __asm__("mulw (%%rdx)" : "+a"(x), "+d"(d) : "m"(v) : "cc"); return x ^ (d * 7); }
static u64 run(void){
    u64 h = 7, x = 0x9e3779b97f4a7c15UL;
    for (int i = 0; i < 400; i++) { x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        u64 y = (i & 3) == 0 ? x | 0x8080 : (i & 3) == 1 ? x & ~0x8080UL : x;
        h = h * 31 + mb(y, h) + ib(h, y) + mbs(y, h) + mba(h, y) + mbm(y, h) + ibm(h, y) + mw(y, h) + iw(h, y)
              + mwa(y, h) + iwm(h, y) + mwr(y, h) + mwd(y, h) + iwd(h, y) + (mwp(y, h) & 0xffff); }
    return h;
}
#ifdef MAIN
int main(void){ u64 h = run(); h ^= h >> 32; h ^= h >> 16; h ^= h >> 8; return (int)(h & 255); }
#else
static char out[8];
void _start(void){
    u64 h = run();
    for (int i = 0; i < 8; i++) out[i] = (char)(h >> (8 * i));
    __asm__ volatile("mov $1, %%edi; mov %0, %%rsi; mov $8, %%edx; mov $1, %%eax; syscall" :: "r"(out) : "rdi", "rsi", "rdx", "rax", "rcx", "r11", "memory");
    __asm__ volatile("mov %0, %%rdi; mov $60, %%eax; syscall" :: "r"((u64)(h % 253)) : "rdi", "rax");
    __builtin_unreachable();
}
#endif
