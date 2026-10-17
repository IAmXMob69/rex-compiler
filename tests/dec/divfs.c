/* tests/dyn.sh: 32/64-bit div and idiv rebuilt by rex compare (no C library,
 * so _start exits by syscall). A sign sweep (a negative 32-bit dividend once
 * made the rebuilt idiv fault), and work(), where gcc -O2 keeps values in
 * r11 and rcx across calls to dv/du because it knows they don't touch them. */
typedef unsigned long u64;
__attribute__((noinline)) static int dv(int a, int b){ return a / b + a % b; }
__attribute__((noinline)) static unsigned du(unsigned a, unsigned b){ return a / b * 3 + a % b; }
__attribute__((noinline)) static long dq(long a, long b){ return a / b * 7 + a % b; }
__attribute__((noinline)) static u64 duq(u64 a, const u64 *b){ return a / *b + a % *b; }
__attribute__((noinline)) int work(int *p, int n){
    int a0=p[0],a1=p[1],a2=p[2],a3=p[3],a4=p[4],a5=p[5],a6=p[6],a7=p[7],a8=p[8],a9=p[9],a10=p[10],a11=p[11],a12=p[12];
    int s = 0;
    for (int i = 1; i < n; i++) {
        s += dv(a0 * i + a1, i + a2) ^ (int)du((unsigned)(a3 + i * a4), (unsigned)(i + 7));
        a0 += a5; a1 ^= a6; a2 = (a2 + a7) & 15; a3 += a8; a4 -= a9; a5 ^= a10; a6 += a11; a7 = a7 * 3 + a12; a8++; a9 ^= s; a10 += a0; a11 -= a1; a12 += a2;
    }
    return s + a0+a1+a2+a3+a4+a5+a6+a7+a8+a9+a10+a11+a12;
}
__attribute__((force_align_arg_pointer)) void _start(void){
    static const int vals[] = { 0, 1, -1, 7, -7, 100, -100, 2147483647, -2147483647, 13, -2 };
    u64 h = 0;
    for (volatile int i = 0; i < 11; i++)
        for (volatile int j = 0; j < 11; j++) {
            int a = vals[i], b = vals[j];
            if (b == 0) continue;
            u64 ub = (u64)(unsigned)b * 3 + 1;
            h = h * 31 + (unsigned)dv(a, b);
            h = h * 31 + du((unsigned)a, (unsigned)b);
            h = h * 31 + (u64)dq((long)a * 1000003, (long)b);
            h = h * 31 + duq((u64)a * 0x9e3779b97f4a7c15ul, &ub);
        }
    int v[13]; for (volatile int i = 0; i < 13; i++) v[i] = i * 7 - 20;
    h = h * 31 + (unsigned)work(v, 40);
    __asm__ volatile("mov %0, %%rdi; mov $60, %%eax; syscall" :: "r"(h % 253) : "rdi", "rax");
    __builtin_unreachable();
}
