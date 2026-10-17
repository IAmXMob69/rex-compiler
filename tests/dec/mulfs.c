/* One-operand mul/imul rebuilt by rex compare: no C library, so _start
 * exits by syscall. tests/dyn.sh */
typedef unsigned long u64;
__attribute__((noinline)) u64 mq(u64 a, u64 b){ u64 hi, lo = a; __asm__("mulq %2" : "+a"(lo), "=d"(hi) : "c"(b) : "cc"); return hi ^ (lo * 3); }
__attribute__((noinline)) u64 iq(u64 a, u64 b){ u64 hi, lo = a; __asm__("imulq %2" : "+a"(lo), "=d"(hi) : "c"(b) : "cc"); return hi ^ (lo * 5); }
__attribute__((noinline)) u64 mqd(u64 a, u64 b){ u64 hi = b, lo = a; __asm__("mulq %%rdx" : "+a"(lo), "+d"(hi) :: "cc"); return hi + lo; }
__attribute__((noinline)) u64 ml(u64 a, u64 b){ unsigned hi, lo = (unsigned)a; __asm__("mull %2" : "+a"(lo), "=d"(hi) : "c"((unsigned)b) : "cc"); return ((u64)hi << 32) | lo; }
__attribute__((noinline)) u64 il(u64 a, u64 b){ unsigned hi, lo = (unsigned)a; __asm__("imull %2" : "+a"(lo), "=d"(hi) : "c"((unsigned)b) : "cc"); return ((u64)hi << 32) | lo; }
__attribute__((noinline)) u64 md(u64 x){ return x % 251 + x / 977; }
void _start(void){
    u64 h = 7, x = 0x9e3779b97f4a7c15UL;
    for (int i = 0; i < 500; i++) { x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        h = h * 31 + mq(x, h) + iq(h, x) + mqd(x, ~h) + ml(x, h) + il(h, x) + md(x); }
    __asm__ volatile("mov %0, %%rdi; mov $60, %%eax; syscall" :: "r"((u64)(h % 253)) : "rdi", "rax");
    __builtin_unreachable();
}
