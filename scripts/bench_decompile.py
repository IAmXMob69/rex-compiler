#!/usr/bin/env python3
"""Decompile quality benchmark for REX.

Corpus: buildable REX examples + gcc/clang -O0/-O1/-O2 samples under
/tmp/isa-samples (or BENCH_ISA_DIR). Metrics per binary:
  decompile_ok, match_ok, match_ir_ok, loc, temps, raw_ir_fallbacks
"""
from __future__ import annotations
import os, re, subprocess, sys, tempfile, csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REX = ROOT / "rex"
ISA = Path(os.environ.get("BENCH_ISA_DIR", "/tmp/isa-samples"))
OUT_DIR = Path(os.environ.get("BENCH_OUT", "/tmp/rex-bench-decompile"))

def run(cmd, timeout=30):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"

def count_metrics(src: str):
    loc = sum(1 for ln in src.splitlines() if ln.strip() and not ln.strip().startswith("//"))
    temps = len(set(re.findall(r"\bt\d+\b", src)))
    # raw-IR / unrecovered markers
    raw = len(re.findall(r"\br\d+\b|\bfn_[0-9a-f]+\b|\bm-?\d+\b|\*r\d+", src))
    return loc, temps, raw

def ensure_isa():
    if not ISA.is_dir():
        ISA.mkdir(parents=True, exist_ok=True)
    srcs = {
        "loops": 'int g;int f(int n){int s=0;for(int i=0;i<n;i++)s+=i;return s;}int main(){g=f(10);return g;}\n',
        "switch": 'int sw(int x){switch(x){case 0:return 1;case 1:return 2;case 2:return 4;case 3:return 8;default:return -1;} }int main(){return sw(2);}\n',
        "structs": 'typedef struct{int a,b;long c;}S; long sum(S*s){return s->a+s->b+s->c;}int main(){S s={1,2,3};return (int)sum(&s);}\n',
        "strings": '#include <string.h>\nint main(){char a[32];strcpy(a,"hi");return (int)strlen(a);}\n',
        "recur": 'int fib(int n){if(n<2)return n;return fib(n-1)+fib(n-2);}int main(){return fib(10);}\n',
        "arith": 'long f(long a,long b){return a*b+(a<<3)-(b>>1)+(a&b)|(a^b);}int main(){return (int)f(7,3);}\n',
    }
    for name, body in srcs.items():
        (ISA / f"{name}.c").write_text(body)
    for cc in ("gcc", "clang"):
        if not shutil_which(cc):
            continue
        for opt in ("O0", "O1", "O2"):
            for name in srcs:
                out = ISA / f"{name}_{cc}_{opt}"
                if out.exists() and os.access(out, os.X_OK):
                    continue
                run([cc, f"-{opt}", "-no-pie", "-fno-pic", "-o", str(out), str(ISA / f"{name}.c")])

def shutil_which(cmd):
    from shutil import which
    return which(cmd)

def rex_examples():
    ex = ROOT / "examples"
    bins = []
    work = OUT_DIR / "bins"
    work.mkdir(parents=True, exist_ok=True)
    for src in sorted(ex.glob("*.rex")):
        # skip known-bad / error-only examples
        out = work / (src.stem + ".bin")
        rc, _, err = run([str(REX), "build", str(src), "-o", str(out)])
        if rc == 0 and out.exists():
            bins.append(("rex:" + src.name, out))
    return bins

def isa_bins():
    ensure_isa()
    bins = []
    for p in sorted(ISA.iterdir()):
        if p.is_file() and os.access(p, os.X_OK) and re.search(r"_(gcc|clang)_O[012]$", p.name):
            bins.append(("isa:" + p.name, p))
    return bins

def bench_one(label: str, path: Path):
    dec = OUT_DIR / "dec" / (path.name + ".dec.rex")
    dec.parent.mkdir(parents=True, exist_ok=True)
    row = {
        "binary": label,
        "decompile_ok": 0,
        "match_ok": 0,
        "match_ir_ok": 0,
        "loc": 0,
        "temps": 0,
        "raw_ir_fallbacks": 0,
        "decompile_err": "",
    }
    rc, out, err = run([str(REX), "decompile", str(path), "-o", str(dec)])
    if rc != 0 or not dec.exists():
        row["decompile_err"] = (err or out).strip().splitlines()[-1] if (err or out) else f"rc={rc}"
        return row
    row["decompile_ok"] = 1
    text = dec.read_text(errors="replace")
    loc, temps, raw = count_metrics(text)
    row["loc"], row["temps"], row["raw_ir_fallbacks"] = loc, temps, raw
    # match / match --ir only meaningful for ELF we can re-run (REX + gcc/clang ET_EXEC)
    rc2, _, e2 = run([str(REX), "match", str(path), "-o", str(dec)])
    if rc2 == 0:
        row["match_ok"] = 1
    rc3, _, e3 = run([str(REX), "match", "--ir", str(path), "-o", str(dec)])
    if rc3 == 0:
        row["match_ir_ok"] = 1
    return row

def main():
    if not REX.exists():
        print("rex binary missing; run make first", file=sys.stderr)
        return 2
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    corpus = rex_examples() + isa_bins()
    rows = [bench_one(lab, p) for lab, p in corpus]
    # summary
    n = len(rows)
    def sumk(k): return sum(r[k] for r in rows)
    print(f"bench-decompile: {n} binaries")
    print(f"  decompile_ok:  {sumk('decompile_ok')}/{n}")
    print(f"  match_ok:      {sumk('match_ok')}/{n}")
    print(f"  match_ir_ok:   {sumk('match_ir_ok')}/{n}")
    print(f"  loc total:     {sumk('loc')}")
    print(f"  temps total:   {sumk('temps')}")
    print(f"  raw_ir total:  {sumk('raw_ir_fallbacks')}")
    # CSV
    csv_path = OUT_DIR / "bench.csv"
    with csv_path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"  wrote {csv_path}")
    # also a markdown summary table for the report
    md = OUT_DIR / "bench.md"
    with md.open("w") as f:
        f.write("| binary | decomp | match | match --ir | loc | temps | raw_ir |\n")
        f.write("| --- | ---: | ---: | ---: | ---: | ---: | ---: |\n")
        for r in rows:
            f.write(f"| {r['binary']} | {r['decompile_ok']} | {r['match_ok']} | {r['match_ir_ok']} | {r['loc']} | {r['temps']} | {r['raw_ir_fallbacks']} |\n")
        f.write(f"\n**Totals:** decomp {sumk('decompile_ok')}/{n}, match {sumk('match_ok')}/{n}, "
                f"match_ir {sumk('match_ir_ok')}/{n}, loc {sumk('loc')}, temps {sumk('temps')}, raw {sumk('raw_ir_fallbacks')}\n")
    print(f"  wrote {md}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
