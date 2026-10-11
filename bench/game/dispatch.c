#include "rt.h"
static int handle(int ev, int v) {
    switch (ev) {
    case 0: return v + 1;
    case 1: return v - 1;
    case 2: return v * 2;
    case 3: return v / 2;
    case 4: return -v;
    case 5: return v ^ 7;
    case 6: return v << 1;
    case 7: return 0;
    default: return v;
    }
}
int main(void) {
    int v = 5;
    for (int i = 0; i < 12; i++) v = handle(i % 9, v);
    return v & 255;
}
