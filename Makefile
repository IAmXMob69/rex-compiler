# REX — native compiler for Arch / XFCE
# Imperial standard: base-devel, nothing else.

PREFIX ?= /usr/local
CC     ?= gcc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra
override CFLAGS += -DREX_PREFIX=\"$(PREFIX)\"

SRCS = src/rex.c src/elf.c src/ir.c src/elfread.c src/x86_decode.c src/cfg.c src/x86_lift.c src/codegen.c src/recompiler.c src/decompiler.c src/inspect.c src/loader.c

.PHONY: all install uninstall test unit clean

all: rex

rex: $(SRCS) src/ir.h src/elfread.h src/x86_decode.h src/cfg.h src/x86_lift.h src/codegen.h src/recompiler.h src/decompiler.h src/loader.h
	$(CC) $(CFLAGS) -o rex $(SRCS)
	chmod +x rex

install: rex
	install -d $(DESTDIR)$(PREFIX)/bin
	install -d $(DESTDIR)$(PREFIX)/share/applications
	install -d $(DESTDIR)$(PREFIX)/share/mime/packages
	install -d $(DESTDIR)$(PREFIX)/share/gtksourceview-4/language-specs
	install -m 755 rex $(DESTDIR)$(PREFIX)/bin/rex
	install -m 755 share/rex-open $(DESTDIR)$(PREFIX)/bin/rex-open
	install -m 644 share/rex.desktop $(DESTDIR)$(PREFIX)/share/applications/rex.desktop
	install -m 644 share/rex.lang $(DESTDIR)$(PREFIX)/share/gtksourceview-4/language-specs/rex.lang
	install -m 644 share/rex-mime.xml $(DESTDIR)$(PREFIX)/share/mime/packages/rex.xml
	@if [ -z "$(DESTDIR)" ] && command -v update-mime-database >/dev/null 2>&1; then \
		update-mime-database $(PREFIX)/share/mime || true; \
	fi
	@echo "installed rex to $(PREFIX)/bin/rex"

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/rex
	rm -f $(DESTDIR)$(PREFIX)/bin/rex-open
	rm -rf $(DESTDIR)$(PREFIX)/share/rex  # left by older installs
	rm -f $(DESTDIR)$(PREFIX)/share/applications/rex.desktop
	rm -f $(DESTDIR)$(PREFIX)/share/gtksourceview-4/language-specs/rex.lang
	rm -f $(DESTDIR)$(PREFIX)/share/mime/packages/rex.xml

unit:
	$(CC) $(CFLAGS) -o /tmp/rex_test_ir tests/test_ir.c src/ir.c && /tmp/rex_test_ir
	$(CC) $(CFLAGS) -o /tmp/rex_test_elf tests/test_elf.c src/elfread.c && /tmp/rex_test_elf
	$(CC) $(CFLAGS) -o /tmp/rex_test_loader tests/test_loader.c src/loader.c src/elfread.c && /tmp/rex_test_loader
	$(CC) $(CFLAGS) -o /tmp/rex_test_err tests/test_err.c src/loader.c src/elfread.c && /tmp/rex_test_err
	$(CC) $(CFLAGS) -o /tmp/rex_test_x86 tests/test_x86.c src/x86_decode.c && /tmp/rex_test_x86
	$(CC) $(CFLAGS) -o /tmp/rex_test_cpu tests/test_cpu_diff.c src/ir.c src/x86_decode.c && /tmp/rex_test_cpu

# rexcomp reads in.rex from its working directory; keep it out of the tree.
RT = /tmp/rex-test

test: rex unit
	rm -rf $(RT) && mkdir -p $(RT)
	./rex run examples/arithmetic.rex | cmp - examples/arithmetic.out
	./rex run examples/loop.rex | cmp - examples/loop.out
	./rex run examples/branch.rex | cmp - examples/branch.out
	./rex run examples/functions.rex | cmp - examples/functions.out
	./rex run examples/elseif.rex | cmp - examples/elseif.out
	./rex run examples/args.rex | cmp - examples/args.out
	./rex run examples/args6.rex | cmp - examples/args6.out
	./rex run examples/ptr.rex | cmp - examples/ptr.out
	./rex run examples/struct.rex | cmp - examples/struct.out
	./rex run examples/heap.rex | cmp - examples/heap.out
	./rex run examples/ptrmath.rex | cmp - examples/ptrmath.out
	./rex run examples/cont.rex | cmp - examples/cont.out
	./rex run examples/arrow.rex | cmp - examples/arrow.out
	./rex run examples/global.rex | cmp - examples/global.out
	./rex run examples/switch.rex | cmp - examples/switch.out
	./rex run examples/ptrptr.rex | cmp - examples/ptrptr.out
	./rex run examples/bits.rex | cmp - examples/bits.out
	./rex run examples/more.rex | cmp - examples/more.out
	./rex run examples/do.rex | cmp - examples/do.out
	./rex run examples/fptr.rex | cmp - examples/fptr.out
	./rex build examples/rexcomp.rex -o /tmp/rexcomp
	cp examples/stage.rex $(RT)/in.rex
	cd $(RT) && /tmp/rexcomp > /tmp/stage.s
	./rex elf /tmp/stage.s -o /tmp/stage
	/tmp/stage | cmp - examples/stage.out
	cp examples/stage2.rex $(RT)/in.rex
	cd $(RT) && /tmp/rexcomp > /tmp/stage2.s
	./rex elf /tmp/stage2.s -o /tmp/stage2
	/tmp/stage2 | cmp - examples/stage2.out
	cp examples/stage3.rex $(RT)/in.rex
	cd $(RT) && /tmp/rexcomp > /tmp/stage3.s
	./rex elf /tmp/stage3.s -o /tmp/stage3
	/tmp/stage3 | cmp - examples/stage3.out
	cp examples/stage4.rex $(RT)/in.rex
	cd $(RT) && /tmp/rexcomp > /tmp/stage4.s
	./rex elf /tmp/stage4.s -o /tmp/stage4
	/tmp/stage4 | cmp - examples/stage4.out
	cp examples/stage5.rex $(RT)/in.rex
	cd $(RT) && /tmp/rexcomp > /tmp/stage5.s
	./rex elf /tmp/stage5.s -o /tmp/stage5
	/tmp/stage5 | cmp - examples/stage5.out
	cp examples/stage6.rex $(RT)/in.rex
	cd $(RT) && /tmp/rexcomp > /tmp/stage6.s
	./rex elf /tmp/stage6.s -o /tmp/stage6
	/tmp/stage6 | cmp - examples/stage6.out
	cp examples/stage7.rex $(RT)/in.rex
	cd $(RT) && /tmp/rexcomp > /tmp/stage7.s
	./rex elf /tmp/stage7.s -o /tmp/stage7
	/tmp/stage7 | cmp - examples/stage7.out
	cp examples/rexcomp.rex $(RT)/in.rex
	cd $(RT) && /tmp/rexcomp > /tmp/self.s
	./rex elf /tmp/self.s -o /tmp/self2
	cp examples/rexcomp.rex $(RT)/in.rex
	cd $(RT) && /tmp/self2 > /tmp/self3.s
	cmp /tmp/self.s /tmp/self3.s
	cp examples/stage.rex $(RT)/in.rex
	cd $(RT) && /tmp/self2 > /tmp/stage_self.s
	./rex elf /tmp/stage_self.s -o /tmp/stage_self
	/tmp/stage_self | cmp - examples/stage.out
	./rex run examples/logic.rex | cmp - examples/logic.out
	./rex run examples/array.rex | cmp - examples/array.out
	./rex run examples/for.rex | cmp - examples/for.out
	./rex run examples/break.rex | cmp - examples/break.out
	./rex run examples/strings.rex | cmp - examples/strings.out
	./rex run examples/exec.rex | cmp - examples/exec.out
	printf '42\n' | ./rex run examples/read.rex | cmp - examples/read.out
	./rex run examples/use_before.rex > /tmp/rexub.out 2> /tmp/rexub.err; \
		test $$? -ne 0 && grep -q 'used before declaration' /tmp/rexub.err && grep -q '\^' /tmp/rexub.err
	./rex run examples/dup.rex > /tmp/rexd.out 2> /tmp/rexd.err; \
		test $$? -ne 0 && grep -q 'already declared' /tmp/rexd.err && grep -q '\^' /tmp/rexd.err
	./rex run examples/badcall.rex > /tmp/rexc.out 2> /tmp/rexc.err; \
		test $$? -ne 0 && grep -q 'wants 1 argument' /tmp/rexc.err && grep -q '\^' /tmp/rexc.err
	./rex run examples/recover.rex > /tmp/rexr.out 2> /tmp/rexr.err; \
		test $$? -ne 0 && grep -c 'error:' /tmp/rexr.err | grep -q 2
	./rex run examples/typemix.rex > /tmp/rext.out 2> /tmp/rext.err; \
		test $$? -ne 0 && grep -q 'string is not a number' /tmp/rext.err
	./rex run examples/typearr.rex > /tmp/rexa.out 2> /tmp/rexa.err; \
		test $$? -ne 0 && grep -q 'array is not printable' /tmp/rexa.err
	./rex run examples/typed.rex | cmp - examples/typed.out
	./rex run examples/typedbad.rex > /tmp/rextb.out 2> /tmp/rextb.err; \
		test $$? -ne 0 && grep -q 'is int, initializer is not' /tmp/rextb.err
	./rex run examples/ret.rex | cmp - examples/ret.out
	./rex check examples/retbad.rex > /tmp/rexrb.out 2> /tmp/rexrb.err; \
		test $$? -ne 0 && grep -q 'return is not an int' /tmp/rexrb.err
	./rex check examples/callbad.rex > /tmp/rexcb.out 2> /tmp/rexcb.err; \
		test $$? -ne 0 && grep -q 'argument 1 has the wrong type' /tmp/rexcb.err
	./rex run examples/divzero.rex > /tmp/rexdz.out 2> /tmp/rexdz.err; \
		test $$? -eq 1 && grep -q 'division by zero' /tmp/rexdz.err
	printf '%s\n' 'fn main() { print(7); }' > /tmp/rexstdin.rex
	rm -f /tmp/rexfifo
	mkfifo /tmp/rexfifo
	cat /tmp/rexstdin.rex > /tmp/rexfifo &
	./rex asm /tmp/rexfifo | grep -q 'mov $$7'
	rm -f /tmp/rexfifo
	./rex inspect /tmp/stage | grep -q 'Executable segments: 1'
	./rex disasm /tmp/stage | grep -q syscall
	! ./rex inspect Makefile 2>/tmp/rexin.err && grep -qE 'bad magic|unrecognized binary format' /tmp/rexin.err
	./rex disasm --cfg /tmp/self2 | grep -q 'block'
	./rex disasm --function main /tmp/stage | grep -q 'return'
	./rex recompile --poison /tmp/stage -o /tmp/stage.re
	/tmp/stage.re | cmp - /tmp/stage.out 2>/dev/null || /tmp/stage.re | cmp - examples/stage.out
	./rex decompile /tmp/stage -o /tmp/stage.dec.rex
	./rex run /tmp/stage.dec.rex | cmp - examples/stage.out
	printf '%s\n' 'fn add(a,b){return a+b;}' 'fn main(){print(add(40,2));}' > /tmp/leaf.rex
	./rex build /tmp/leaf.rex -o /tmp/leaf
	./rex decompile /tmp/leaf -o /tmp/leaf.dec.rex
	printf '42\n' > /tmp/leaf.exp
	./rex run /tmp/leaf.dec.rex | cmp - /tmp/leaf.exp
	rm -rf $(RT)
	@echo "tests passed"

clean:
	rm -f rex
