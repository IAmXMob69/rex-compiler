struct Point { x; y; }

fn main() {
    let pt = Point;
    pt.x = 40;
    pt.y = 2;
    let p = &pt;
    print(p->x + p->y);
    p->x = 7;
    print(pt.x);
}
