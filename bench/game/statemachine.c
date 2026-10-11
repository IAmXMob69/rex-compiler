#include "rt.h"
enum { TITLE, PLAY, PAUSE, OVER, WIN };
static int step(int s, int ev, int *score) {
    switch (s) {
    case TITLE: return ev == 1 ? PLAY : TITLE;
    case PLAY:
        if (ev == 2) return PAUSE;
        if (ev == 3) return OVER;
        *score += 10;
        return *score >= 50 ? WIN : PLAY;
    case PAUSE: return ev == 2 ? PLAY : PAUSE;
    case OVER: return TITLE;
    default: return s;
    }
}
int main(void) {
    int s = TITLE, score = 0;
    int evs[] = {0, 1, 0, 0, 2, 0, 2, 0, 0, 0};
    for (int i = 0; i < 10; i++) s = step(s, evs[i], &score);
    return s * 10 + score / 10;
}
