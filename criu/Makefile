#
# CRIU version.
VERSION_MAJOR		:= 2
VERSION_MINOR		:= 0
VERSION_SUBLEVEL	:=
VERSION_EXTRA		:=
VERSION_NAME		:=

export VERSION_MAJOR VERSION_MINOR
export VERSION_SUBLEVEL VERSION_EXTRA VERSION_NAME

#
# HOST part is needed to build helper
# tools such as piegen.
HOSTCC			?= gcc
HOSTLD			?= ld
HOSTCFLAGS		?= $(CFLAGS)
CFLAGS			+= $(USERCFLAGS)

export HOSTCC HOSTLD HOSTCFLAGS USERCFLAGS

ifeq ($(ARCH),x86)
        SRCARCH		:= x86
        DEFINES		:= -DCONFIG_X86_64
        LDARCH		:= i386:x86-64
        VDSO		:= y
endif

#
# FIXME ---
#
# Compatibility hacks for old make engine,
# need to tune up for generic cases as in
# linux kernel.
OLDARCH := $(shell uname -m | sed	\
		-e s/i.86/i386/		\
		-e s/sun4u/sparc64/	\
		-e s/s390x/s390/	\
		-e s/parisc64/parisc/	\
		-e s/mips.*/mips/	\
		-e s/sh[234].*/sh/)

ifeq ($(shell echo $(OLDARCH) | sed -e 's/arm.*/arm/'),arm)
        ARCH		:= arm
        ARMV		:= $(shell echo $(OLDARCH) | sed -nr 's/armv([[:digit:]]).*/\1/p; t; i7')
        SRCARCH		:= arm
        DEFINES		:= -DCONFIG_ARMV$(ARMV)

        USERCFLAGS += -Wa,-mimplicit-it=always

        ifeq ($(ARMV),6)
                USERCFLAGS += -march=armv6
        endif

        ifeq ($(ARMV),7)
                USERCFLAGS += -march=armv7-a
        endif
endif

ifeq ($(OLDARCH),aarch64)
        ARCH		:= aarch64
        VDSO		:= y
endif

#
# The PowerPC 64 bits architecture could be big or little endian.
# They are handled in the same way.
#
ifeq ($(shell echo $(OLDARCH) | sed -e 's/ppc64.*/ppc64/'),ppc64)
        ifeq ($(OLDARCH),ppc64)
                error	:= $(error ppc64 big endian not yet supported)
        endif
        ARCH		:= ppc64
        SRCARCH		:= ppc64
        DEFINES		:= -DCONFIG_PPC64
        LDARCH		:= powerpc:common64
        VDSO		:= y
endif

ifeq ($(SRCARCH),arm)
        PROTOUFIX	:= y
        export PROTOUFIX
endif

#
# FIXME ---
#

SRCARCH			?= $(ARCH)
LDARCH			?= $(SRCARCH)
ARCH_DIR		:= arch/$(SRCARCH)

export SRCARCH LDARCH ARCH_DIR VDSO

$(if $(wildcard $(ARCH_DIR)),,$(error "The architecture $(ARCH) isn't supported"))

#
# General flags.
ccflags-y		+= -iquote include -iquote $(SRC_DIR)/images -iquote pie
ccflags-y		+= -iquote $(ARCH_DIR) -iquote $(ARCH_DIR)/include
ccflags-y		+= -fno-strict-aliasing

export ccflags-y

LIBS			:= -lrt -lpthread -lprotobuf-c -ldl

DEFINES			+= -D_FILE_OFFSET_BITS=64
DEFINES			+= -D_GNU_SOURCE

WARNINGS		:= -Wall

ifneq ($(WERROR),0)
        WARNINGS	+= -Werror
endif

ifeq ($(DEBUG),1)
        DEFINES		+= -DCR_DEBUG
        CFLAGS		+= -O0 -ggdb3
else
        CFLAGS		+= -O2
endif

ifeq ($(GMON),1)
	CFLAGS		+= -pg
	GMONLDOPT	= -pg
endif

CFLAGS			+= $(WARNINGS) $(DEFINES)

export CFLAGS

#
# piegen tool might be disabled by hands. Don't use it until
# you know what you're doing.
ifneq ($(filter ia32 x86 ppc64,$(ARCH)),)
        ifneq ($(PIEGEN),no)
                piegen-y := y
                export piegen-y
        endif
endif

#
# Version header file.
include Makefile.version

#
# Configure variables.
include Makefile.config
config: $(VERSION_HEADER)

#
# System calls library.
SYSCALL-LIB		:= $(ARCH_DIR)/syscalls.built-in.o
$(SYSCALL-LIB): config
	$(Q) $(MAKE) $(call build-as,Makefile.syscalls,$(ARCH_DIR)) all
PHONY += $(SYSCALL-LIB)

#
# Architecture dependant part.
ARCH-LIB		:= $(ARCH_DIR)/crtools.built-in.o
$(ARCH-LIB): config $(SYSCALL-LIB)
	$(Q) $(MAKE) $(call build-as,Makefile,$(ARCH_DIR)) $@
PHONY += $(ARCH-LIB)

#
# piegen tool needed for PIE code.
ifeq ($(piegen-y),y)
piegen			:= pie/piegen/piegen

pie/piegen/%: config
	$(Q) CC=$(HOSTCC) LD=$(HOSTLD) CFLAGS="$(HOSTCFLAGS) $(WARNINGS) $(DEFINES)" $(MAKE) $(build)=pie/piegen $@
pie/piegen: config
	$(Q) CC=$(HOSTCC) LD=$(HOSTLD) CFLAGS="$(HOSTCFLAGS) $(WARNINGS) $(DEFINES)" $(MAKE) $(build)=pie/piegen all
$(piegen): pie/piegen/built-in.o
	$(call msg-link, $@)
	$(Q) $(HOSTCC) $(HOSTCFLAGS) $^ $(LDFLAGS) -o $@
PHONY += pie/piegen
endif

#
# PIE library code.
pie/lib.a: $(ARCH-LIB)
	$(Q) $(MAKE) $(call build-as,Makefile.library,pie) all

#
# PIE code blobs themseves.
pie: $(ARCH_DIR) $(piegen) pie/lib.a
	$(Q) $(MAKE) $(build)=pie all
PHONY += pie

#
# CRIU executable
PROGRAM-BUILTINS	+= ../images/built-in.o
PROGRAM-BUILTINS	+= built-in.o
PROGRAM-BUILTINS	+= pie/lib.a
PROGRAM-BUILTINS	+= $(SYSCALL-LIB)

LIBS			+= arch/$(ARCH)/crtools.built-in.o

built-in.o: pie/lib.a
	$(Q) $(MAKE) $(call build-as,Makefile.crtools,.) all

criu: $(PROGRAM-BUILTINS) built-in.o
	$(call msg-link, $@)
	$(Q) $(CC) $(CFLAGS) $^ $(LIBS) $(LDFLAGS) $(GMONLDOPT) -rdynamic -o $@
PHONY += criu

#
# Cleanup everything.
clean:
	$(Q) $(MAKE) $(call build-as,Makefile.syscalls,$(ARCH_DIR)) $@
	$(Q) $(MAKE) $(call build-as,Makefile.library,pie) $@
	$(Q) $(MAKE) $(call build-as,Makefile.crtools,.) $@
	$(Q) $(MAKE) $(build)=pie/piegen $@
	$(Q) $(MAKE) $(build)=pie $@
	$(Q) $(RM) $(VERSION_HEADER)
	$(Q) $(RM) criu

#
# Final @all target.
all: $(PHONY)
	@true

.PHONY: $(PHONY) clean
