#include "rt.h"
static unsigned int st = 2463534242u;
static unsigned int xs(void) { st ^= st << 13; st ^= st >> 17; st ^= st << 5; return st; }
int main(void) {
    unsigned int a = 0;
    for (int i = 0; i < 100; i++) a += xs() % 6;
    return (int)(a & 255);
}
