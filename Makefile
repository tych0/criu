# Import the build engine first
__nmk_dir=$(CURDIR)/scripts/nmk/scripts/
export __nmk_dir

include $(__nmk_dir)/include.mk

VERSION_MAJOR		:= 1
VERSION_MINOR		:= 8
VERSION_SUBLEVEL	:=
VERSION_EXTRA		:=
VERSION_NAME		:=
VERSION_SO_MAJOR	:= 1
VERSION_SO_MINOR	:= 0

export VERSION_MAJOR VERSION_MINOR VERSION_SUBLEVEL VERSION_EXTRA VERSION_NAME
export VERSION_SO_MAJOR VERSION_SO_MINOR

#
# FIXME zdtm building procedure requires implicit rules
# so I can't use strict make file mode and drop completely
# all of implicit rules, so I tuned only .SUFFIXES:
#
# In future zdtm makefiles need to be fixed and the line below
# may be uncommented.
#
#MAKEFLAGS := -r -R

#
# Common definitions
#

FIND		:= find
CSCOPE		:= cscope
RM		:= rm -f
LD		:= $(CROSS_COMPILE)ld
CC		:= $(CROSS_COMPILE)gcc
NM		:= $(CROSS_COMPILE)nm
SH		:= bash
MAKE		:= make
OBJCOPY		:= $(CROSS_COMPILE)objcopy
HOSTCC		?= gcc
HOSTLD		?= ld

CFLAGS		+= $(USERCFLAGS)
HOSTCFLAGS	?= $(CFLAGS)

export HOSTCC
export HOSTLD
export HOSTCFLAGS


ifeq ($(ARCH),x86_64)
	ARCH         := x86
endif

ifeq ($(ARCH),x86)
	SRCARCH      := x86
	DEFINES      := -DCONFIG_X86_64
	LDARCH       := i386:x86-64
	VDSO         := y
endif
ifeq ($(ARCH),ia32)
	SRCARCH      := x86
	DEFINES      := -DCONFIG_X86_32
	LDARCH       := i386
	ldflags-y    += -m elf_i386
	VDSO         := y
	USERCFLAGS   += -m32
	PROTOUFIX    := y
	export PROTOUFIX ldflags-y
endif

ifeq ($(GCOV),1)
	LDFLAGS += -lgcov
	DEBUG = 1	# disable optimization if we want to measure code coverage
%.o $(PROGRAM): override CFLAGS += --coverage -fno-exceptions -fno-inline
endif

ifeq ($(shell echo $(ARCH) | sed -e 's/arm.*/arm/'),arm)
	ARMV         := $(shell echo $(ARCH) | sed -nr 's/armv([[:digit:]]).*/\1/p; t; i7')
	SRCARCH      := arm
	DEFINES      := -DCONFIG_ARMV$(ARMV)

	USERCFLAGS += -Wa,-mimplicit-it=always

	ifeq ($(ARMV),6)
		USERCFLAGS += -march=armv6
	endif

	ifeq ($(ARMV),7)
		USERCFLAGS += -march=armv7-a
	endif
endif
ifeq ($(ARCH),aarch64)
	VDSO         := y
endif

ifeq ($(SRCARCH),arm)
	PROTOUFIX    := y
	export PROTOUFIX
endif

#
# The PowerPC 64 bits architecture could be big or little endian.
# They are handled in the same way.
#
ifeq ($(shell echo $(ARCH) | sed -e 's/ppc64.*/ppc64/'),ppc64)
	ifeq ($(ARCH),ppc64)
		error	:= $(error ppc64 big endian not yet supported)
	endif
	SRCARCH	:= ppc64
	DEFINES := -DCONFIG_PPC64
	LDARCH	:= powerpc:common64
	VDSO	:= y
endif

LDARCH		?= $(SRCARCH)

SRC_DIR		?= $(CURDIR)
ARCH_DIR	:= arch/$(SRCARCH)

$(if $(wildcard $(ARCH_DIR)),,$(error "The architecture $(ARCH) isn't supported"))

#
# piegen might be disabled by hands. Don't use it  until
# you know what you're doing.
ifneq ($(filter ia32 x86 ppc64le, $(ARCH)),)
ifneq ($(PIEGEN),no)
	piegen-y := y
	export piegen-y
endif
endif

cflags-y		+= -iquote include -iquote pie -iquote .
cflags-y		+= -iquote $(ARCH_DIR) -iquote $(ARCH_DIR)/include
cflags-y		+= -fno-strict-aliasing
export cflags-y

LIBS		:= -lrt -lpthread -lprotobuf-c -ldl

DEFINES		+= -D_FILE_OFFSET_BITS=64
DEFINES		+= -D_GNU_SOURCE

WARNINGS	:= -Wall

ifneq ($(WERROR),0)
	WARNINGS += -Werror
endif

ifeq ($(DEBUG),1)
	DEFINES += -DCR_DEBUG
	CFLAGS	+= -O0 -ggdb3
else
	CFLAGS	+= -O2
endif

ifeq ($(GMON),1)
	CFLAGS	+= -pg
	GMONLDOPT = -pg
endif

CFLAGS		+= $(WARNINGS) $(DEFINES)
SYSCALL-LIB	:= $(ARCH_DIR)/syscalls.built-in.o
ARCH-LIB	:= $(ARCH_DIR)/crtools.built-in.o
CRIU-SO		:= libcriu
CRIU-LIB	:= lib/c/$(CRIU-SO).so
CRIU-INC	:= lib/criu.h include/criu-plugin.h include/criu-log.h protobuf/rpc.proto
ifeq ($(piegen-y),y)
piegen		:= pie/piegen/piegen
endif

export CC MAKE CFLAGS LIBS SRCARCH DEFINES MAKEFLAGS CRIU-SO
export SRC_DIR SYSCALL-LIB SH RM ARCH_DIR OBJCOPY LDARCH LD
export USERCFLAGS
export cflags-y
export VDSO

include Makefile.inc
include Makefile.config
include scripts/Makefile.version
include scripts/Makefile.rules

.SUFFIXES:

#
# shorthand
build-old := -r -R -f scripts/Makefile.build makefile=Makefile obj
build-old-crtools := -r -R -f scripts/Makefile.build makefile=Makefile.crtools obj

PROGRAM		:= criu

.PHONY: all zdtm test rebuild clean distclean tags cscope	\
	docs help pie protobuf $(ARCH_DIR) clean-built lib crit

all: config pie $(VERSION_HEADER) $(CRIU-LIB)
	$(Q) $(MAKE) $(PROGRAM)
	$(Q) $(MAKE) crit

protobuf/%::
	$(Q) $(MAKE) $(build-old)=protobuf $@
protobuf:
	$(Q) $(MAKE) $(build-old)=protobuf all

$(ARCH_DIR)/%:: protobuf config
	$(Q) $(MAKE) $(build-old)=$(ARCH_DIR) $@
$(ARCH_DIR): protobuf config
	$(Q) $(MAKE) $(build-old)=$(ARCH_DIR) all

ifeq ($(piegen-y),y)
pie/piegen/%: config
	$(Q) CC=$(HOSTCC) LD=$(HOSTLD) CFLAGS="$(HOSTCFLAGS)" $(MAKE) $(build-old)=pie/piegen $@
pie/piegen: config
	$(Q) CC=$(HOSTCC) LD=$(HOSTLD) CFLAGS="$(HOSTCFLAGS)" $(MAKE) $(build-old)=pie/piegen all
$(piegen): pie/piegen/built-in.o
	$(E) "  LINK    " $@
	$(Q) $(HOSTCC) $(HOSTCFLAGS) $^ $(LDFLAGS) -o $@
.PHONY: pie/piegen
endif

pie: $(ARCH_DIR) $(piegen)
	$(Q) $(MAKE) $(build-old)=pie all

%.o %.i %.s %.d: $(VERSION_HEADER) pie
	$(Q) $(MAKE) $(build-old-crtools)=. $@
built-in.o: $(VERSION_HEADER) pie
	$(Q) $(MAKE) $(build-old-crtools)=. $@

lib/%:: $(VERSION_HEADER) config built-in.o
	$(Q) $(MAKE) -C lib $@
lib: $(VERSION_HEADER) config built-in.o
	$(Q) $(MAKE) -C lib all

$(CRIU-LIB): lib
	@true
crit: lib
	@true


PROGRAM-BUILTINS	+= protobuf/built-in.o
PROGRAM-BUILTINS	+= built-in.o

$(SYSCALL-LIB) $(ARCH-LIB) $(PROGRAM-BUILTINS): config

$(PROGRAM): $(SYSCALL-LIB) $(ARCH-LIB) $(PROGRAM-BUILTINS)
	$(E) "  LINK    " $@
	$(Q) $(CC) $(CFLAGS) $^ $(LIBS) $(LDFLAGS) $(GMONLDOPT) -rdynamic -o $@

zdtm: all
	$(Q) $(MAKE) -C test/zdtm all

test: zdtm
	$(Q) $(MAKE) -C test

clean-built:
	$(Q) $(RM) $(VERSION_HEADER)
	$(Q) $(MAKE) $(build-old)=$(ARCH_DIR) clean
	$(Q) $(MAKE) $(build-old)=protobuf clean
	$(Q) $(MAKE) $(build-old)=pie/piegen clean
	$(Q) $(MAKE) $(build-old)=pie clean
	$(Q) $(MAKE) -C lib clean
	$(Q) $(MAKE) $(build-old-crtools)=. clean
	$(Q) $(MAKE) -C Documentation clean
	$(Q) $(RM) ./include/config.h
	$(Q) $(RM) ./$(PROGRAM)

rebuild: clean-built
	$(E) "  FORCE-REBUILD"
	$(Q) $(MAKE)

clean: clean-built
	$(E) "  CLEAN"
	$(Q) $(RM) ./*.img
	$(Q) $(RM) ./*.out
	$(Q) $(RM) ./*.bin
	$(Q) $(RM) ./*.{gcda,gcno,gcov} ./test/`pwd`/*.{gcda,gcno,gcov} ./pie/*.{gcda,gcno,gcov}
	$(Q) $(RM) -r ./gcov
	$(Q) $(RM) protobuf-desc-gen.h
	$(Q) $(MAKE) -C test $@
	$(Q) $(RM) ./*.pyc
	$(Q) $(RM) -r build
	$(Q) $(RM) -r usr

distclean: clean
	$(E) "  DISTCLEAN"
	$(Q) $(RM) ./tags
	$(Q) $(RM) ./cscope*

tags:
	$(E) "  GEN     " $@
	$(Q) $(RM) tags
	$(Q) $(FIND) . -name '*.[hcS]' ! -path './.*' ! -path './test/*' -print | xargs ctags -a

cscope:
	$(E) "  GEN     " $@
	$(Q) $(FIND) . -name '*.[hcS]' ! -path './.*' ! -path './test/*' ! -type l -print > cscope.files
	$(Q) $(CSCOPE) -bkqu

docs:
	$(Q) $(MAKE) -s -C Documentation all

dist: tar
tar: criu-$(CRTOOLSVERSION).tar.bz2
criu-$(CRTOOLSVERSION).tar.bz2:
	git archive --format tar --prefix 'criu-$(CRTOOLSVERSION)/' \
		v$(CRTOOLSVERSION) | bzip2 > $@
.PHONY: dist tar

install: install-criu install-man 

install-criu: all $(CRIU-LIB) install-crit
	$(E) "  INSTALL " $(PROGRAM)
	$(Q) mkdir -p $(DESTDIR)$(SBINDIR)
	$(Q) install -m 755 $(PROGRAM) $(DESTDIR)$(SBINDIR)
	$(Q) mkdir -p $(DESTDIR)$(LIBDIR)
	$(Q) install -m 755 $(CRIU-LIB) \
		$(DESTDIR)$(LIBDIR)/$(CRIU-SO).so.$(VERSION_SO_MAJOR).$(VERSION_SO_MINOR)
	$(Q) ln -fns $(CRIU-SO).so.$(VERSION_SO_MAJOR).$(VERSION_SO_MINOR) \
		$(DESTDIR)$(LIBDIR)/$(CRIU-SO).so.$(VERSION_SO_MAJOR)
	$(Q) ln -fns $(CRIU-SO).so.$(VERSION_SO_MAJOR).$(VERSION_SO_MINOR) \
		$(DESTDIR)$(LIBDIR)/$(CRIU-SO).so
	$(Q) mkdir -p $(DESTDIR)$(INCLUDEDIR)
	$(Q) install -m 644 $(CRIU-INC) $(DESTDIR)$(INCLUDEDIR)
	$(Q) mkdir -p $(DESTDIR)$(SYSTEMDUNITDIR)
	$(Q) sed -e 's,@version@,$(CRTOOLSVERSION),' \
		-e 's,@libdir@,$(LIBDIR),' \
		-e 's,@includedir@,$(dir $(INCLUDEDIR)),' \
		lib/criu.pc.in > criu.pc
	$(Q) mkdir -p $(DESTDIR)$(LIBDIR)/pkgconfig
	$(Q) install -m 644 criu.pc $(DESTDIR)$(LIBDIR)/pkgconfig

install-man:
	$(Q) $(MAKE) -C Documentation install

install-crit: crit
	$(E) "  INSTALL crit"
	$(Q) python scripts/crit-setup.py install --root=$(DESTDIR) --prefix=$(PREFIX)

.PHONY: install install-man install-crit install-criu

help:
	@echo '    Targets:'
	@echo '      all             - Build all [*] targets'
	@echo '    * criu            - Build criu'
	@echo '      zdtm            - Build zdtm test-suite'
	@echo '      docs            - Build documentation'
	@echo '      install         - Install binary and man page'
	@echo '      dist            - Create a source tarball'
	@echo '      clean           - Clean everything'
	@echo '      tags            - Generate tags file (ctags)'
	@echo '      cscope          - Generate cscope database'
	@echo '      rebuild         - Force-rebuild of [*] targets'
	@echo '      test            - Run zdtm test-suite'
	@echo '      gcov	     - Make code coverage report'

gcov:
	$(E) " GCOV"
	$(Q) test -d gcov || mkdir gcov && \
	cp *.{gcno,c} test/`pwd`/ 	&& \
	geninfo --output-filename gcov/crtools.h.info --no-recursion . && \
	geninfo --output-filename gcov/crtools.ns.info --no-recursion test/`pwd`/ && \
	sed -i 's#/test/`pwd`##' gcov/crtools.ns.info && \
	cd gcov && \
	lcov --rc lcov_branch_coverage=1 --add-tracefile crtools.h.info --add-tracefile crtools.ns.info --output-file criu.info && \
	genhtml --rc lcov_branch_coverage=1 --output-directory html criu.info
	@echo "Code coverage report is in `pwd`/gcov/html/ directory."
.PHONY: gcov

docker-build:
	docker build -t criu .

docker-test:
	docker run --rm -it --privileged criu ./test/zdtm.sh -C -x tcp6 -x tcpbuf6 -x static/rtc -x cgroup -x mountpoint

.DEFAULT_GOAL	:= all

# include optional local rules
-include Makefile.local
