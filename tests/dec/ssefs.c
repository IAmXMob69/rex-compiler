/* tests/dyn.sh: gcc -O3 copies this array with 16-byte SSE moves. The rebuild
 * has no encoding for xmm values yet and refuses with E500 (it used to put
 * both halves in r8 and store the wrong data). */
typedef unsigned long u64;
__attribute__((noinline)) int sum(const int *p, int n){ int s = 0; for (int i = 0; i < n; i++) s = s * 3 + p[i]; return s; }
__attribute__((force_align_arg_pointer)) void _start(void){
    int v[12]; for (int i = 0; i < 12; i++) v[i] = i * 7 - 20;
    u64 r = (unsigned)sum(v, 12) & 255;
    __asm__ volatile("mov %0, %%rdi; mov $60, %%eax; syscall" :: "r"(r) : "rdi", "rax");
    __builtin_unreachable();
}
