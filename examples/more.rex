enum Color { RED = 1, GREEN, BLUE }

fn main() {
    let i = 1;
    print(i++);
    i++;
    print(i);
    print(++i);
    print(i == 4 ? 40 : 0);
    print(RED + GREEN + BLUE);
    print("REX" == "REX");
    print("REX" == "NO");
}
