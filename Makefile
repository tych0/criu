#
# Import the build engine first
__nmk_dir=$(CURDIR)/scripts/nmk/scripts/
export __nmk_dir

include $(__nmk_dir)/include.mk
include $(__nmk_dir)/macro.mk

#
# To build host helpers.
HOSTCC		?= gcc
HOSTLD		?= ld
export HOSTCC HOSTLD

CFLAGS		+= $(USERCFLAGS)
export CFLAGS

HOSTCFLAGS	?= $(CFLAGS)
export HOSTCFLAGS

#
# Where we live.
SRC_DIR	:= $(CURDIR)
export SRC_DIR

#
# Architecture specific options.
ifeq ($(ARCH),x86)
        DEFINES		:= -DCONFIG_X86_64
        LDARCH		:= i386:x86-64
        VDSO		:= y
endif

ifeq ($(ARCH),ia32)
        DEFINES		:= -DCONFIG_X86_32
        LDARCH		:= i386
        ldflags-y	+= -m elf_i386
        VDSO		:= y
        USERCFLAGS	+= -m32
        PROTOUFIX	:= y
endif

ifeq ($(shell echo $(ARCH) | sed -e 's/arm.*/arm/'),arm)
        ARMV		:= $(shell echo $(ARCH) | sed -nr 's/armv([[:digit:]]).*/\1/p; t; i7')
        SRCARCH		:= arm
        DEFINES		:= -DCONFIG_ARMV$(ARMV)

        USERCFLAGS	+= -Wa,-mimplicit-it=always

        ifeq ($(ARMV),6)
                USERCFLAGS += -march=armv6
        endif

        ifeq ($(ARMV),7)
                USERCFLAGS += -march=armv7-a
        endif
endif

ifeq ($(ARCH),aarch64)
        VDSO		:= y
endif

ifeq ($(SRCARCH),arm)
        PROTOUFIX	:= y
endif

#
# The PowerPC 64 bits architecture could be big or little endian.
# They are handled in the same way.
#
ifeq ($(shell echo $(ARCH) | sed -e 's/ppc64.*/ppc64/'),ppc64)
        ifeq ($(ARCH),ppc64)
                error := $(error ppc64 big endian not yet supported)
        endif

        SRCARCH		:= ppc64
        DEFINES		:= -DCONFIG_PPC64
        LDARCH		:= powerpc:common64
        VDSO		:= y
endif

LDARCH ?= $(SRCARCH)

export PROTOUFIX VDSO DEFINES LDARCH ldflags-y

#
# Protobuf images first, they are not depending
# on anything else.
$(eval $(call gen-built-in,images))
PHONY += images

#
# CRIU building done in own directory
# with slightly different rules so we
# can't use nmk engine directly (we
# build syscalls library and such).
#
# But note that we're already included
# the nmk so we can reuse it there.
criu/%: images/built-in.o
	$(Q) $(MAKE) -C criu $@
criu: images/built-in.o
	$(Q) $(MAKE) -C criu all
criu/criu: criu
PHONY += criu

#
# Libraries.
lib/%: criu
	$(Q) $(MAKE) -C lib $@
lib: criu
	$(Q) $(MAKE) -C lib all
PHONY += lib

all: criu lib
PHONY += all

zdtm: all
	$(Q) $(MAKE) -C test/zdtm all
PHONY += zdtm

test: zdtm
	$(Q) $(MAKE) -C test
PHONY += test

clean-built:
	$(Q) $(MAKE) $(build)=images clean
	$(Q) $(MAKE) -C criu clean
	$(Q) $(MAKE) -C lib clean
PHONY += clean-built

clean: clean-built
	$(call msg-clean, criu)
PHONY += clean

dist: tar
tar: criu-$(CRTOOLSVERSION).tar.bz2
criu-$(CRTOOLSVERSION).tar.bz2:
	git archive --format tar --prefix 'criu-$(CRTOOLSVERSION)/' \
		v$(CRTOOLSVERSION) | bzip2 > $@
.PHONY: dist tar

tags:
	$(call msg-gen, $@)
	$(Q) $(RM) tags
	$(Q) $(FIND) . -name '*.[hcS]' ! -path './.*' ! -path './test/*' -print | xargs ctags -a
PHONY += tags

cscope:
	$(call msg-gen, $@)
	$(Q) $(FIND) . -name '*.[hcS]' ! -path './.*' ! -path './test/*' ! -type l -print > cscope.files
	$(Q) $(CSCOPE) -bkqu
PHONY += cscope

docs:
	$(Q) $(MAKE) -s -C Documentation all
PHONY += docs

gcov:
	$(E) " GCOV"
	$(Q) test -d gcov || mkdir gcov && \
	cp *.{gcno,c} test/`pwd`/ 	&& \
	geninfo --output-filename gcov/crtools.h.info --no-recursion . && \
	geninfo --output-filename gcov/crtools.ns.info --no-recursion test/`pwd`/ && \
	sed -i 's#/test/`pwd`##' gcov/crtools.ns.info && \
	cd gcov && \
	lcov --rc lcov_branch_coverage=1 --add-tracefile crtools.h.info \
	--add-tracefile crtools.ns.info --output-file criu.info && \
	genhtml --rc lcov_branch_coverage=1 --output-directory html criu.info
	@echo "Code coverage report is in `pwd`/gcov/html/ directory."
PHONY += gcov

docker-build:
	docker build -t criu .
PHONY += docker-build

docker-test:
	docker run --rm -it --privileged criu ./test/zdtm.sh -C -x tcp6 -x tcpbuf6 -x static/rtc -x cgroup -x mountpoint
PHONY += docker-test

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
	@echo '      gcov            - Make code coverage report'
PHONY += help

include Makefile.install

.PHONY: $(PHONY)

.DEFAULT_GOAL := all

#
# Optional local include.
-include Makefile.local
