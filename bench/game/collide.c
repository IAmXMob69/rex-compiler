#include "rt.h"
static int mn(int a, int b) { return a < b ? a : b; }
static int mx(int a, int b) { return a > b ? a : b; }
static int overlap(int ax, int aw, int bx, int bw) { return mx(0, mn(ax + aw, bx + bw) - mx(ax, bx)); }
static int hit(int ax, int ay, int bx, int by) { return ax < bx + 4 && bx < ax + 4 && ay < by + 4 && by < ay + 4; }
int main(void) {
    int s = 0;
    for (int i = 0; i < 10; i++) s += overlap(i, 5, 3, 5) + hit(i, i, 5, 5);
    return s;
}
