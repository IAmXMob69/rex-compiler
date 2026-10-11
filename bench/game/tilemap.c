#include "rt.h"
#define W 8
#define H 6
static unsigned char map[H][W];
int main(void) {
    for (int y = 0; y < H; y++)
        for (int x = 0; x < W; x++)
            map[y][x] = (x == 0 || y == 0 || x == W - 1 || y == H - 1) ? 1 : 0;
    map[2][3] = 2;
    int walls = 0, items = 0;
    for (int y = 0; y < H; y++)
        for (int x = 0; x < W; x++) {
            if (map[y][x] == 1) walls++;
            else if (map[y][x] == 2) items++;
        }
    return walls + items * 100;
}
