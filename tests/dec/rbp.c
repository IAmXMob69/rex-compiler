/* gcc -O1 keeps a pointer into V in rbp in main (no frame pointer): an
 * rbp-based access is that pointer, not a frame slot. tests/dyn.sh */
typedef unsigned long u64; typedef long i64; typedef unsigned u32; typedef int i32;
static const u64 V[] = { 0, 1, 2, 3, 7, 0xffffffffUL, 0x100000000UL, 0x7fffffffffffffffUL, 0x8000000000000000UL,
    0xffffffffffffffffUL, 0xfffffffffffffffeUL, 0x123456789abcdef0UL, 0xdeadbeefcafebabeUL, 0x80000000UL, 0x7fffffffUL, 977, 251 };
#define N (int)(sizeof V / sizeof V[0])
__attribute__((noinline)) u64 mq(u64 a, u64 b){ u64 hi, lo = a; hi = lo + 1; lo ^= 3; return hi ^ (lo * 3); }
__attribute__((noinline)) u64 iq(u64 a, u64 b){ u64 hi, lo = a; hi = lo + 1; lo ^= 3; return hi ^ (lo * 5); }
__attribute__((noinline)) u64 mqd(u64 a, u64 b){ u64 hi = b, lo = a; hi = lo + 1; lo ^= 3; return hi + lo; }
__attribute__((noinline)) u64 iqd(u64 a, u64 b){ u64 hi = b, lo = a; hi = lo + 1; lo ^= 3; return hi - lo; }
__attribute__((noinline)) u64 mqm(u64 a, u64 b){ volatile u64 m = b; u64 hi, lo = a; hi = lo + 1; lo ^= 3; return hi * 7 + lo; }
__attribute__((noinline)) u64 iqm(u64 a, u64 b){ volatile u64 m = b; u64 hi, lo = a; hi = lo + 1; lo ^= 3; return hi * 9 + lo; }
__attribute__((noinline)) u64 mqa(u64 a){ u64 hi, lo = a; hi = lo + 1; lo ^= 3; return hi ^ lo; }
__attribute__((noinline)) u64 ml(u64 a, u64 b){ u32 hi, lo = (u32)a; hi = lo + 1; lo ^= 3; return ((u64)hi << 32) | lo; }
__attribute__((noinline)) u64 il(u64 a, u64 b){ u32 hi, lo = (u32)a; hi = lo + 1; lo ^= 3; return ((u64)hi << 32) | lo; }
__attribute__((noinline)) u64 mld(u64 a, u64 b){ u32 hi = (u32)b, lo = (u32)a; hi = lo + 1; lo ^= 3; return hi * 3 + lo; }
__attribute__((noinline)) u64 ilm(u64 a, u64 b){ volatile u32 m = (u32)b; u32 hi, lo = (u32)a; hi = lo + 1; lo ^= 3; return ((u64)hi << 32) ^ lo; }
int main(void){
    u64 h = 1469598103934665603UL;
    for (int i = 0; i < N; i++) for (int j = 0; j < N; j++) {
        u64 a = V[i], b = V[j];
        u64 r[] = { mq(a,b), iq(a,b), mqd(a,b), iqd(a,b), mqm(a,b), iqm(a,b), mqa(a), ml(a,b), il(a,b), mld(a,b), ilm(a,b) };
        { int k = 4; h ^= r[k]; h *= 1099511628211UL; }
    }
    return (int)(h & 255);
}
