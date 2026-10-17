/* tests/dyn.sh: at gcc -O2 work() keeps values in r11 and rcx across the calls
 * to dv/du (gcc knows they only write rax and rdx). The lift borrows r11 for
 * the divide and puts it back; the decompiler must not count it as written. */
__attribute__((noinline)) static int dv(int a, int b){ return a / b + a % b; }
__attribute__((noinline)) static unsigned du(unsigned a, unsigned b){ return a / b * 3 + a % b; }
__attribute__((noinline)) int work(int *p, int n){
    int a0=p[0],a1=p[1],a2=p[2],a3=p[3],a4=p[4],a5=p[5],a6=p[6],a7=p[7],a8=p[8],a9=p[9],a10=p[10],a11=p[11],a12=p[12];
    int s = 0;
    for (int i = 1; i < n; i++) {
        s += dv(a0 * i + a1, i + a2) ^ (int)du((unsigned)(a3 + i * a4), (unsigned)(i + 7));
        a0 += a5; a1 ^= a6; a2 = (a2 + a7) & 15; a3 += a8; a4 -= a9; a5 ^= a10; a6 += a11; a7 = a7 * 3 + a12; a8++; a9 ^= s; a10 += a0; a11 -= a1; a12 += a2;
    }
    return s + a0+a1+a2+a3+a4+a5+a6+a7+a8+a9+a10+a11+a12;
}
int main(void){ int v[13]; for (int i = 0; i < 13; i++) v[i] = i * 7 - 20; return work(v, 40) & 255; }
