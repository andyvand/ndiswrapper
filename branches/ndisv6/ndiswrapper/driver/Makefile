# Name of the module
MODNAME = ndis6wrapper

DISTFILES = divdi3.c hal.c iw_ndis.c iw_ndis.h loader.c loader.h \
		longlong.h Makefile crt.c ndis.c ndis.h \
		ndiswrapper.h ntoskernel.c ntoskernel.h ntoskernel_io.c \
		pe_linker.c pe_linker.h pnp.c pnp.h proc.c rtl.c usb.c usb.h \
		winnt_types.h workqueue.c wrapmem.h wrapmem.c wrapper.c \
		wrapndis.h wrapndis.c lin2win.h win2lin_stubs.S ndisdot11.h \
		mkexport.sh mkstubs.sh

# By default, we try to compile the modules for the currently running
# kernel.  But it's the first approximation, as we will re-read the
# version from the kernel sources.
KVERS ?= $(shell uname -r)

# KBUILD is the path to the Linux kernel build tree.  It is usually the
# same as the kernel source tree, except when the kernel was compiled in
# a separate directory.
KBUILD ?= $(shell readlink -f /lib/modules/$(KVERS)/build)

# Some old kernels only install the "source" link
ifeq (,$(KBUILD))
KBUILD := $(shell readlink -f /lib/modules/$(KVERS)/source)
endif

ifeq (,$(KBUILD))
$(error Kernel tree not found - please set KBUILD to configured kernel)
endif

# Kernel Makefile doesn't always know the exact kernel version, so we
# get it from the kernel headers instead and pass it to make.

VERSION_H := $(KBUILD)/include/linux/utsrelease.h
ifeq (,$(wildcard $(VERSION_H)))
VERSION_H := $(KBUILD)/include/linux/version.h
endif
ifeq (,$(wildcard $(VERSION_H)))
$(error Cannot find kernel version in $(KBUILD), is it configured?)
endif

KVERS := $(shell sed -ne 's/"//g;s/^\#define UTS_RELEASE //p' $(VERSION_H))

# distros use different paths for kernel include files

KSRC ?= $(shell if \
	[ -f /lib/modules/$(KVERS)/source/include/linux/kernel.h ]; then \
		echo /lib/modules/$(KVERS)/source ; \
	else \
		echo $(KBUILD); \
	fi)

ifdef DIST_DESTDIR
DESTDIR = $(DIST_DESTDIR)
else
DESTDIR ?= /
endif

INST_DIR ?= $(shell echo $(DESTDIR)/lib/modules/$(KVERS)/misc | sed 's^//^/^g')

SRC_DIR=$(shell pwd)

KCONFIG := $(KBUILD)/.config
ifeq (,$(wildcard $(KCONFIG)))
$(error No .config found in $(KBUILD), please set KBUILD to configured kernel)
endif
include $(KBUILD)/.config

MOD_CFLAGS += $(shell [ -f $(KSRC)/include/linux/modversions.h ] && \
		  echo -DEXPORT_SYMTAB -DMODVERSIONS \
		  -include $(KSRC)/include/linux/modversions.h)

# returns of structs and unions in registers when possible, like Windows 
MOD_CFLAGS += -freg-struct-return

# to produce debug trace, add option "DEBUG=<n>" where <n> is 1 to 6
ifdef DEBUG
MOD_CFLAGS += -DDEBUG=$(DEBUG) -g
endif

# to debug timers, add option "TIMER_DEBUG=1 DEBUG=<n>"
ifdef TIMER_DEBUG
MOD_CFLAGS += -DTIMER_DEBUG
endif

# to debug event layer, add option "EVENT_DEBUG=1 DEBUG=<n>"
ifdef EVENT_DEBUG
MOD_CFLAGS += -DEVENT_DEBUG
endif

# to debug USB layer, add option "USB_DEBUG=1 DEBUG=<n>"
ifdef USB_DEBUG
MOD_CFLAGS += -DUSB_DEBUG
endif

# to debug I/O layer, add option "IO_DEBUG=1 DEBUG=<n>"
ifdef IO_DEBUG
MOD_CFLAGS += -DIO_DEBUG
endif

# to debug worker threads
ifdef WORK_DEBUG
MOD_CFLAGS += -DWORK_DEBUG
endif

# to debug memory allocation issues
ifdef ALLOC_DEBUG
MOD_CFLAGS += -DALLOC_DEBUG=$(ALLOC_DEBUG)
endif

# emulate (pseudo) preemption
ifdef WRAP_PREEMPT
MOD_CFLAGS += -DWRAP_PREEMPT
endif

OBJS = crt.o hal.o iw_ndis.o loader.o ndis.o ntoskernel.o ntoskernel_io.o \
	pe_linker.o pnp.o proc.o rtl.o wrapmem.o wrapndis.o wrapper.o

EXPORTS = crt_exports.h hal_exports.h ndis_exports.h ntoskernel_exports.h \
	ntoskernel_io_exports.h rtl_exports.h

STUB_SRCS = crt.c hal.c ndis.c ntoskernel.c ntoskernel_io.c \
	pnp.c rtl.c wrapndis.c


# Disable USB support and use own workqueue code if GPL-only symbols
# are not available
ifneq (,$(shell grep -s -A1 '"$(MODNAME)"' $(KSRC)/kernel/module.c | \
			grep 'add_taint_module'))
$(warning GPL-only symbols not available, disabling USB support)
WRAP_WQ = 1
DISABLE_USB = 1
endif

# By default, USB layer is compiled in if USB support is in kernel;
# to disable USB support in ndiswrapper even if USB support is in kenrel,
# add option "DISABLE_USB=1"
ifndef DISABLE_USB
ifeq ($(CONFIG_USB),y)
ENABLE_USB = 1
endif
ifeq ($(CONFIG_USB),m)
ENABLE_USB = 1
endif
endif

ifdef ENABLE_USB
EXPORTS += usb_exports.h
STUB_SRCS += usb.c
OBJS += usb.o
MOD_CFLAGS += $(shell if grep -q 'struct module \*owner;' \
		   $(KSRC)/include/linux/usb.h ; then \
			echo -DUSB_DRIVER_OWNER; \
		  fi)
else
MOD_CFLAGS += -DDISABLE_USB
endif

ifdef WRAP_WQ
MOD_CFLAGS += -DWRAP_WQ
OBJS += workqueue.o
endif


all: prereq_check modules stack_check

# generate exports symbol table from C files
quiet_cmd_mkexport = MKEXPORT $@
cmd_mkexport = $(SHELL) $(obj)/mkexport.sh $< $@

%_exports.h: %.c $(obj)/mkexport.sh FORCE
	$(call if_changed,mkexport)

extra-y := $(EXPORTS)

ifeq ($(CONFIG_X86_64),y)
quiet_cmd_mkstubs = MKSTUBS $@
cmd_mkstubs = $(SHELL) $(obj)/mkstubs.sh $(addprefix $(src)/,$(STUB_SRCS)) >$@

$(obj)/win2lin_stubs.h: $(addprefix $(src)/,$(STUB_SRCS)) FORCE
	$(call if_changed,mkstubs)

extra-y += win2lin_stubs.h
OBJS += win2lin_stubs.o
else
OBJS += divdi3.o
endif

wflags := $(shell if grep -qw "EXTRA_CFLAGS" $(KSRC)/scripts/Makefile.build; \
		             then echo "EXTRA_CFLAGS"; else echo "CFLAGS"; fi)

ifeq ($(wflags), CFLAGS)
CFLAGS += $(MOD_CFLAGS)
else
EXTRA_CFLAGS += $(MOD_CFLAGS)
endif

MODULE := $(MODNAME).ko
obj-m := $(MODNAME).o

$(MODNAME)-objs := $(OBJS)


prereq_check:
	@if [ ! -f $(KBUILD)/include/linux/version.h ]; then \
		echo "Can't find kernel build files in $(KBUILD);"; \
		echo "  give the path to kernel build directory with " ; \
		echo "  KBUILD=<path> argument to make";\
		exit 1;\
	fi
	@if [ ! -f $(KSRC)/include/linux/kernel.h ]; then \
		echo "Can't find kernel build files in $(KSRC);"; \
		echo "  give the path to kernel build directory with " ; \
		echo "  KSRC=<path> argument to make";\
		exit 1;\
	fi

stack_check:
	@if [ "x$(CONFIG_X86_64)" = "x" ] && \
	       grep -q "CONFIG_4KSTACKS=y" $(KBUILD)/.config; then \
	    echo; echo; \
	    echo "*** WARNING: This kernel seems to use 4K stack size"\
		 "option (CONFIG_4KSTACKS); many Windows drivers will"\
		 "not work with this option enabled. Disable"\
		 "CONFIG_4KSTACKS option, recompile and install kernel";\
	    echo; echo; \
	fi

modules:
	$(MAKE) -C $(KBUILD) M=$(SRC_DIR)

clean:
	rm -f *.o *.ko .*.cmd *.mod.c *.symvers modules.order *~ .\#*
	rm -f *_exports.h win2lin_stubs.h
	rm -rf .tmp_versions

install: prereq_check modules stack_check
	echo $(INST_DIR)
	mkdir -p $(INST_DIR)
	install -m 0644 $(MODULE) $(INST_DIR)
ifndef DIST_DESTDIR
	-/sbin/depmod -a $(KVERS) -b $(DESTDIR)
endif

dist:
	@for file in $(DISTFILES); do \
		cp $$file $(distdir)/$$file; \
	done

.PHONY: all modules clean install prereq_check stack_check dist
