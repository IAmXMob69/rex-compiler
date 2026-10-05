// XFCE-facing sample. notify-send ships with most Arch XFCE installs.
// Harmless if the session has no notification daemon: the binary still exits 0.
fn main() {
    print("REX online.");
    exec("notify-send REX 'Native code. No interpreter. No apology.'");
}
