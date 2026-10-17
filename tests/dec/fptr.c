/* Calls through function pointers: a const table, a pointer passed as an
 * argument, a struct of pointers. tests/dyn.sh */
typedef long (*op_t)(long, long);
__attribute__((noinline)) long add(long a, long b){ return a + b; }
__attribute__((noinline)) long sub(long a, long b){ return a - b; }
__attribute__((noinline)) long mul(long a, long b){ return a * b; }
__attribute__((noinline)) long xr(long a, long b){ return a ^ (b << 3); }
static op_t const ops[] = { add, sub, mul, xr };
__attribute__((noinline)) long apply(op_t f, long a, long b){ return f(a, b) + 1; }
struct vt { long (*one)(long); long (*two)(long, long); };
__attribute__((noinline)) long neg1(long a){ return -a + 7; }
static struct vt V = { neg1, add };
int main(void){
    long s = 3;
    for (int i = 0; i < 40; i++) { s = ops[i & 3](s, i) & 0xffff; s = apply(ops[(i + 1) & 3], s, 5) & 0xffff; s += V.one(s) + V.two(s, i); s &= 0xffff; }
    return (int)(s & 255);
}
