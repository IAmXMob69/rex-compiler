#!/bin/sh
# Golden decompiler output: build each example, decompile, compare text,
# then check the round trip. Regenerate with: tests/golden.sh --update
set -e
REX=${REX:-./rex}
T=${TMPDIR:-/tmp}/rex-golden
mkdir -p "$T"
IR="array struct arrow ptr ptrptr do break loop switch elseif branch args stage7 arithmetic read"
ALL="$IR cont"
for x in $ALL; do
    $REX build examples/$x.rex -o "$T/$x"
    $REX decompile "$T/$x" -o "$T/$x.dec.rex"
    if [ "$1" = "--update" ]; then cp "$T/$x.dec.rex" tests/golden/$x.dec.rex
    else diff -u tests/golden/$x.dec.rex "$T/$x.dec.rex"; fi
    $REX match "$T/$x" -o "$T/$x.m.rex" </dev/null >/dev/null 2>&1
done
for x in $IR; do $REX match --ir "$T/$x" -o "$T/$x.m.rex" </dev/null >/dev/null 2>&1; done
rm -rf "$T"
echo "golden: $(echo $ALL | wc -w) decompiled texts, $(echo $IR | wc -w) match --ir"
