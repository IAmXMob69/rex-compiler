/* tests/dyn.sh: the switches of the sw2 test rebuilt by rex compare (no C
 * library, so _start exits by syscall); clang -O3 checks the bound of its
 * second table in each block that jumps to it. */
__attribute__((noinline)) int body(int x, int acc){
    for (int i = 0; i < 3; i++) {
        switch (x + i) {
        case 0: acc += 3; break;
        case 1: acc ^= 0x55; /* fallthrough */
        case 2: acc = acc * 5 + 1; break;
        case 3: { int j = 0; while (j < x) { acc += j * j; j++; } break; }
        case 4: acc -= 7; break;
        case 5: acc = (acc << 2) | 1; break;
        case 6: acc = acc / 3 + 2; break;
        case 7: continue;
        case 8: acc += 100; break;
        default: acc -= 1;
        }
        acc += i;
    }
    return acc;
}
__attribute__((noinline)) int off(int x){
    switch (x) { case 10: return 1; case 11: return 4; case 12: return 9; case 13: return 16;
                 case 14: return 25; case 15: return 36; case 16: return 49; default: return 0; }
}
__attribute__((noinline)) int chr(const char *s){
    int n = 0;
    for (; *s; s++) switch (*s) { case 'a': n += 1; break; case 'b': n += 20; break; case 'c': n *= 3; break;
        case 'd': n -= 4; break; case 'e': n ^= 9; break; case 'f': n += 77; break; default: n++; }
    return n;
}
void _start(void){
    unsigned s = 0;
    for (int x = -2; x < 11; x++) s = s * 33 + (unsigned)body(x, x * 7);
    for (int x = 5; x < 20; x++) s = s * 31 + (unsigned)off(x);
    s += (unsigned)chr("abcdefabcxyzfed");
    __asm__ volatile("mov %0, %%rdi; mov $60, %%eax; syscall" :: "r"((unsigned long)(s % 253)) : "rdi", "rax");
    __builtin_unreachable();
}
