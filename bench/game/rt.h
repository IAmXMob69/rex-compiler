/* Freestanding runtime for the game samples: no libc, static, exit code = result. */
void *memset(void *d, int c, unsigned long n) { unsigned char *p = d; while (n--) *p++ = (unsigned char)c; return d; }
void *memcpy(void *d, const void *s, unsigned long n) { unsigned char *p = d; const unsigned char *q = s; while (n--) *p++ = *q++; return d; }
int main(void);
__asm__(".globl _start\n_start:\n xor %ebp, %ebp\n and $-16, %rsp\n call main\n movslq %eax, %rdi\n mov $60, %eax\n syscall\n hlt\n");
