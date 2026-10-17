#include "rt.h"
/* short-circuit chains and rotated (guarded) loops */
static int box[8] = {3, 9, 1, 7, 5, 2, 8, 4};
__attribute__((noinline)) static int inside(int x, int y) { return x > 0 && x < 10 && y > 0 && y < 10; }
__attribute__((noinline)) static int edge(int x, int y) { return x == 0 || y == 0 || x == 9 || y == 9; }
__attribute__((noinline)) static int sum(int n) { int s = 0; for (int i = 0; i < n; i++) s += box[i & 7]; return s; }
__attribute__((noinline)) static int count(int lo, int hi) { int c = 0; while (lo < hi) { if (box[lo & 7] > 4 && lo != 3) c++; lo++; } return c; }
int main(void) {
    int r = 0;
    for (int i = -1; i < 11; i++) r += inside(i, 5) + 2 * edge(i, 4);
    return r + sum(10) + count(0, 8) * 3;
}
