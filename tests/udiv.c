#include "rt.h"
/* unsigned div/mod at 32 and 64 bits, including values above 2^63 */
static unsigned int d32 = 7;
static unsigned long d64 = 10;
static unsigned long big = 0xfffffffffffffff1ul;
__attribute__((noinline)) static unsigned int q32(unsigned int a, unsigned int b) { return a / b + a % b; }
__attribute__((noinline)) static unsigned long q64(unsigned long a, unsigned long b) { return a / b ^ a % b; }
int main(void) {
    unsigned int x = 4000000000u;
    unsigned long r = q32(x, d32) + q64(big, d64);
    return (int)(r & 255);
}
