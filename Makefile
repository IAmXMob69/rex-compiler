# REX — native compiler for Arch / XFCE
# Imperial standard: base-devel, nothing else.

PREFIX ?= /usr/local
CC     ?= gcc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra -Wno-unused-function
override CFLAGS += -DREX_PREFIX=\"$(PREFIX)\"

SRCS = src/rex.c src/elf.c src/ir.c src/elfread.c src/x86_decode.c src/cfg.c src/x86_lift.c src/inspect.c

.PHONY: all install uninstall test unit clean

all: rex

rex: $(SRCS) src/ir.h src/elfread.h src/x86_decode.h src/cfg.h src/x86_lift.h
	$(CC) $(CFLAGS) -o rex $(SRCS)
	chmod +x rex

install: rex
	install -d $(DESTDIR)$(PREFIX)/bin
	install -d $(DESTDIR)$(PREFIX)/share/rex
	install -d $(DESTDIR)$(PREFIX)/share/applications
	install -d $(DESTDIR)$(PREFIX)/share/mime/packages
	install -d $(DESTDIR)$(PREFIX)/share/gtksourceview-4/language-specs
	install -m 755 rex $(DESTDIR)$(PREFIX)/bin/rex
	install -m 755 share/rex-open $(DESTDIR)$(PREFIX)/bin/rex-open
	install -m 644 src/rexrt.c $(DESTDIR)$(PREFIX)/share/rex/rexrt.c
	install -m 644 share/rex.desktop $(DESTDIR)$(PREFIX)/share/applications/rex.desktop
	install -m 644 share/rex.lang $(DESTDIR)$(PREFIX)/share/gtksourceview-4/language-specs/rex.lang
	install -m 644 share/rex-mime.xml $(DESTDIR)$(PREFIX)/share/mime/packages/rex.xml
	@if [ -z "$(DESTDIR)" ] && command -v update-mime-database >/dev/null 2>&1; then \
		update-mime-database $(PREFIX)/share/mime || true; \
	fi
	@echo "installed rex to $(PREFIX)/bin/rex"
	@echo "runtime: $(PREFIX)/share/rex/rexrt.c"

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/rex
	rm -f $(DESTDIR)$(PREFIX)/bin/rex-open
	rm -rf $(DESTDIR)$(PREFIX)/share/rex
	rm -f $(DESTDIR)$(PREFIX)/share/applications/rex.desktop
	rm -f $(DESTDIR)$(PREFIX)/share/gtksourceview-4/language-specs/rex.lang
	rm -f $(DESTDIR)$(PREFIX)/share/mime/packages/rex.xml

unit:
	$(CC) $(CFLAGS) -o /tmp/rex_test_ir tests/test_ir.c src/ir.c && /tmp/rex_test_ir
	$(CC) $(CFLAGS) -o /tmp/rex_test_elf tests/test_elf.c src/elfread.c && /tmp/rex_test_elf
	$(CC) $(CFLAGS) -o /tmp/rex_test_x86 tests/test_x86.c src/x86_decode.c && /tmp/rex_test_x86

test: rex unit
	REX_RUNTIME=src/rexrt.c ./rex run examples/arithmetic.rex | cmp - examples/arithmetic.out
	REX_RUNTIME=src/rexrt.c ./rex run examples/loop.rex | cmp - examples/loop.out
	REX_RUNTIME=src/rexrt.c ./rex run examples/branch.rex | cmp - examples/branch.out
	REX_RUNTIME=src/rexrt.c ./rex run examples/functions.rex | cmp - examples/functions.out
	REX_RUNTIME=src/rexrt.c ./rex run examples/elseif.rex | cmp - examples/elseif.out
	REX_RUNTIME=src/rexrt.c ./rex run examples/args.rex | cmp - examples/args.out
	REX_RUNTIME=src/rexrt.c ./rex run examples/args6.rex | cmp - examples/args6.out
	REX_RUNTIME=src/rexrt.c ./rex run examples/ptr.rex | cmp - examples/ptr.out
	REX_RUNTIME=src/rexrt.c ./rex run examples/struct.rex | cmp - examples/struct.out
	REX_RUNTIME=src/rexrt.c ./rex run examples/heap.rex | cmp - examples/heap.out
	REX_RUNTIME=src/rexrt.c ./rex run examples/ptrmath.rex | cmp - examples/ptrmath.out
	REX_RUNTIME=src/rexrt.c ./rex run examples/cont.rex | cmp - examples/cont.out
	REX_RUNTIME=src/rexrt.c ./rex run examples/arrow.rex | cmp - examples/arrow.out
	REX_RUNTIME=src/rexrt.c ./rex run examples/global.rex | cmp - examples/global.out
	REX_RUNTIME=src/rexrt.c ./rex run examples/switch.rex | cmp - examples/switch.out
	REX_RUNTIME=src/rexrt.c ./rex run examples/ptrptr.rex | cmp - examples/ptrptr.out
	REX_RUNTIME=src/rexrt.c ./rex run examples/bits.rex | cmp - examples/bits.out
	REX_RUNTIME=src/rexrt.c ./rex run examples/more.rex | cmp - examples/more.out
	REX_RUNTIME=src/rexrt.c ./rex run examples/do.rex | cmp - examples/do.out
	REX_RUNTIME=src/rexrt.c ./rex run examples/fptr.rex | cmp - examples/fptr.out
	./rex build examples/rexcomp.rex -o /tmp/rexcomp
	cp examples/stage.rex in.rex
	/tmp/rexcomp > /tmp/stage.s
	./rex elf /tmp/stage.s -o /tmp/stage
	/tmp/stage | cmp - examples/stage.out
	cp examples/stage2.rex in.rex
	/tmp/rexcomp > /tmp/stage2.s
	./rex elf /tmp/stage2.s -o /tmp/stage2
	/tmp/stage2 | cmp - examples/stage2.out
	cp examples/stage3.rex in.rex
	/tmp/rexcomp > /tmp/stage3.s
	./rex elf /tmp/stage3.s -o /tmp/stage3
	/tmp/stage3 | cmp - examples/stage3.out
	cp examples/stage4.rex in.rex
	/tmp/rexcomp > /tmp/stage4.s
	./rex elf /tmp/stage4.s -o /tmp/stage4
	/tmp/stage4 | cmp - examples/stage4.out
	cp examples/stage5.rex in.rex
	/tmp/rexcomp > /tmp/stage5.s
	./rex elf /tmp/stage5.s -o /tmp/stage5
	/tmp/stage5 | cmp - examples/stage5.out
	cp examples/stage6.rex in.rex
	/tmp/rexcomp > /tmp/stage6.s
	./rex elf /tmp/stage6.s -o /tmp/stage6
	/tmp/stage6 | cmp - examples/stage6.out
	cp examples/stage7.rex in.rex
	/tmp/rexcomp > /tmp/stage7.s
	./rex elf /tmp/stage7.s -o /tmp/stage7
	/tmp/stage7 | cmp - examples/stage7.out
	cp examples/rexcomp.rex in.rex
	/tmp/rexcomp > /tmp/self.s
	./rex elf /tmp/self.s -o /tmp/self2
	cp examples/rexcomp.rex in.rex
	/tmp/self2 > /tmp/self3.s
	cmp /tmp/self.s /tmp/self3.s
	cp examples/stage.rex in.rex
	/tmp/self2 > /tmp/stage_self.s
	./rex elf /tmp/stage_self.s -o /tmp/stage_self
	/tmp/stage_self | cmp - examples/stage.out
	REX_RUNTIME=src/rexrt.c ./rex run examples/logic.rex | cmp - examples/logic.out
	REX_RUNTIME=src/rexrt.c ./rex run examples/array.rex | cmp - examples/array.out
	REX_RUNTIME=src/rexrt.c ./rex run examples/for.rex | cmp - examples/for.out
	REX_RUNTIME=src/rexrt.c ./rex run examples/break.rex | cmp - examples/break.out
	REX_RUNTIME=src/rexrt.c ./rex run examples/strings.rex | cmp - examples/strings.out
	REX_RUNTIME=src/rexrt.c ./rex run examples/exec.rex | cmp - examples/exec.out
	printf '42\n' | REX_RUNTIME=src/rexrt.c ./rex run examples/read.rex | cmp - examples/read.out
	REX_RUNTIME=src/rexrt.c ./rex run examples/use_before.rex > /tmp/rexub.out 2> /tmp/rexub.err; \
		test $$? -ne 0 && grep -q 'used before declaration' /tmp/rexub.err && grep -q '\^' /tmp/rexub.err
	REX_RUNTIME=src/rexrt.c ./rex run examples/dup.rex > /tmp/rexd.out 2> /tmp/rexd.err; \
		test $$? -ne 0 && grep -q 'already declared' /tmp/rexd.err && grep -q '\^' /tmp/rexd.err
	REX_RUNTIME=src/rexrt.c ./rex run examples/badcall.rex > /tmp/rexc.out 2> /tmp/rexc.err; \
		test $$? -ne 0 && grep -q 'wants 1 argument' /tmp/rexc.err && grep -q '\^' /tmp/rexc.err
	REX_RUNTIME=src/rexrt.c ./rex run examples/recover.rex > /tmp/rexr.out 2> /tmp/rexr.err; \
		test $$? -ne 0 && grep -c 'error:' /tmp/rexr.err | grep -q 2
	REX_RUNTIME=src/rexrt.c ./rex run examples/typemix.rex > /tmp/rext.out 2> /tmp/rext.err; \
		test $$? -ne 0 && grep -q 'string is not a number' /tmp/rext.err
	REX_RUNTIME=src/rexrt.c ./rex run examples/typearr.rex > /tmp/rexa.out 2> /tmp/rexa.err; \
		test $$? -ne 0 && grep -q 'array is not printable' /tmp/rexa.err
	REX_RUNTIME=src/rexrt.c ./rex run examples/typed.rex | cmp - examples/typed.out
	REX_RUNTIME=src/rexrt.c ./rex run examples/typedbad.rex > /tmp/rextb.out 2> /tmp/rextb.err; \
		test $$? -ne 0 && grep -q 'is int, initializer is not' /tmp/rextb.err
	REX_RUNTIME=src/rexrt.c ./rex run examples/ret.rex | cmp - examples/ret.out
	REX_RUNTIME=src/rexrt.c ./rex check examples/retbad.rex > /tmp/rexrb.out 2> /tmp/rexrb.err; \
		test $$? -ne 0 && grep -q 'return is not an int' /tmp/rexrb.err
	REX_RUNTIME=src/rexrt.c ./rex check examples/callbad.rex > /tmp/rexcb.out 2> /tmp/rexcb.err; \
		test $$? -ne 0 && grep -q 'argument 1 has the wrong type' /tmp/rexcb.err
	REX_RUNTIME=src/rexrt.c ./rex run examples/divzero.rex > /tmp/rexdz.out 2> /tmp/rexdz.err; \
		test $$? -eq 1 && grep -q 'division by zero' /tmp/rexdz.err
	printf '%s\n' 'fn main() { print(7); }' > /tmp/rexstdin.rex
	rm -f /tmp/rexfifo
	mkfifo /tmp/rexfifo
	cat /tmp/rexstdin.rex > /tmp/rexfifo &
	REX_RUNTIME=src/rexrt.c ./rex asm /tmp/rexfifo | grep -q 'mov $$7'
	rm -f /tmp/rexfifo
	./rex inspect /tmp/stage | grep -q 'Executable segments: 1'
	./rex disasm /tmp/stage | grep -q syscall
	! ./rex inspect Makefile 2>/tmp/rexin.err && grep -q 'bad magic' /tmp/rexin.err
	./rex disasm --cfg /tmp/self2 | grep -q 'block'
	./rex disasm --function main /tmp/stage | grep -q 'return'
	@echo "tests passed"

clean:
	rm -f rex
