#define TEN 10
#define LETTER 65

fn main() {
    let n = TEN;
    switch (n) {
        case 1: print(1);
        case 10: print(LETTER);
        default: print(0);
    }
    switch ('B') {
        case 66: print(2);
        default: print(9);
    }
}
