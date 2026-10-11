#include "rt.h"
typedef struct { int x, y, vx, vy, alive; } Ent;
#define FP 8
static Ent ents[8];
static void update(Ent *e, int n) {
    for (int i = 0; i < n; i++) {
        if (!e[i].alive) continue;
        e[i].x += e[i].vx;
        e[i].y += e[i].vy;
        e[i].vy += 1 << (FP - 2);
        if ((e[i].y >> FP) > 100) e[i].alive = 0;
    }
}
int main(void) {
    for (int i = 0; i < 8; i++) { ents[i].x = i << FP; ents[i].vx = 3 << FP; ents[i].vy = -(i << FP); ents[i].alive = 1; }
    for (int t = 0; t < 20; t++) update(ents, 8);
    int a = 0;
    for (int i = 0; i < 8; i++) a += ents[i].alive + (ents[i].x >> FP);
    return a & 255;
}
