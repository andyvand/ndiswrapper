# Name of the module
MODNAME = ndis6wrapper

DISTFILES=divdi3.c hal.c iw_ndis.c iw_ndis.h loader.c loader.h \
		longlong.h Makefile crt.c ndis.c ndis.h \
		ndiswrapper.h ntoskernel.c ntoskernel.h ntoskernel_io.c \
		pe_linker.c pe_linker.h pnp.c pnp.h proc.c rtl.c usb.c usb.h \
		winnt_types.h workqueue.c wrapmem.h wrapmem.c wrapper.c \
		wrapndis.h wrapndis.c lin2win.h win2lin_stubs.S ndisdot11.h

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

KREV := $(shell echo $(KVERS) | sed -e 's/[^\.]*\.[^\.]*\.\([0-9]*\).*/\1/')

KCONFIG := $(KBUILD)/.config
ifeq (,$(wildcard $(KCONFIG)))
$(error No .config found in $(KBUILD), please set KBUILD to configured kernel)
endif
include $(KBUILD)/.config

MOD_CFLAGS += $(shell [ -f $(KSRC)/include/linux/modversions.h ] && \
		  echo -DEXPORT_SYMTAB -DMODVERSIONS \
		  -include $(KSRC)/include/linux/modversions.h)

ifndef DISABLE_USB
MOD_CFLAGS += $(shell if grep -q 'struct module \*owner;' \
		   $(KSRC)/include/linux/usb.h ; then \
			echo -DUSB_DRIVER_OWNER; \
		  fi)
endif

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

.PHONY: prereq_check gen_exports clean dist_clean install stack_check

all : prereq_check win2lin_stubs.h gen_exports compat.h default stack_check

OBJS := crt.o hal.o iw_ndis.o loader.o ndis.o ntoskernel.o ntoskernel_io.o \
	pe_linker.o pnp.o proc.o rtl.o wrapmem.o wrapndis.o wrapper.o

# Disable USB support and use own workqueue code if GPL-only symbols
# are not available
ifneq (,$(shell grep -s -A1 '$(MODNAME)' $(KSRC)/kernel/module.c | \
			grep 'add_taint_module'))
$(warning GPL-only symbols not available, disabling USB support)
WRAP_WQ = 1
DISABLE_USB = 1
endif

# by default, USB layer is compiled in if USB support is in kernel;
# to disable USB support in ndiswrapper even if USB support is in kenrel,
# add option "DISABLE_USB=1"

ifdef DISABLE_USB
usb_exports.h:

MOD_CFLAGS += -DDISABLE_USB
else
usb_exports.h: usb.c

ifeq ($(CONFIG_USB),y)
OBJS += usb.o
endif
ifeq ($(CONFIG_USB),m)
OBJS += usb.o
endif
endif

ifdef WRAP_WQ
MOD_CFLAGS += -DWRAP_WQ
OBJS += workqueue.o
endif

ifdef NTOS_WQ
MOD_CFLAGS += -DNTOS_WQ
endif

ntoskernel.h: lin2win.h

ndis.h: ntoskernel.h

iw_ndis.h: ntoskernel.h

pnp.h: ntoskernel.h ndis.h

wrapndis.h: ndis.h pnp.h

usb.h: ntoskernel.h

divdi3.o: divdi3.c longlong.h

hal.o: hal.c ntoskernel.h

iw_ndis.o: iw_ndis.c iw_ndis.h wrapndis.h

loader.o: loader.c loader.h ndis.h wrapndis.h

crt.o: crt.c ndis.h

ndis.o: ndis.c ndis.h iw_ndis.h wrapndis.h

wrapndis.o: wrapndis.c wrapndis.h

ntoskernel.o: ntoskernel.c ndis.h usb.h

ntoskernel_io.o: ntoskernel_io.c ndis.h usb.h

pe_linker.o: pe_linker.c

pnp.o: pnp.c

proc.o: proc.c ndis.h iw_ndis.h wrapndis.h

rtl.o: rtl.c ndis.h

usb.o: usb.c usb.h ndis.h

wrapper.o: wrapper.c wrapndis.h iw_ndis.h ntoskernel.h loader.h

ifeq ($(CONFIG_X86_64),y)
OBJS += win2lin_stubs.o
win2lin_stubs.o: win2lin_stubs.h win2lin_stubs.S

ifdef DISABLE_USB
win2lin_stubs.h: hal.c crt.c ndis.c ntoskernel.c ntoskernel_io.c \
	pnp.c rtl.c wrapndis.c
else
win2lin_stubs.h: hal.c crt.c ndis.c ntoskernel.c ntoskernel_io.c \
	pnp.c rtl.c usb.c wrapndis.c
endif
	@for file in $^; do \
		echo; \
		echo "# automatically generated from $$file"; \
		sed -n \
			-e 's/.*WIN_FUNC(\([^\,]\+\) *\, *\([0-9]\+\)).*/\
			   win2lin(\1, \2)/p'   \
			-e 's/.*WIN_FUNC_PTR(\([^\,]\+\) *\, *\([0-9]\+\)).*/\
			   win2lin(\1, \2)/p'   \
		   $$file | sed -e 's/[ \t	]\+//' | sort -u; \
	done > $@
else
win2lin_stubs.h:

OBJS += divdi3.o
endif

# generate exports symbol table from C files
%_exports.h: %.c
	@if :; then \
		echo "/* automatically generated from $< */"; \
		echo "#ifdef CONFIG_X86_64"; \
		sed -n \
			-e 's/.*WIN_FUNC(\([^\,]\+\) *\, *\([0-9]\+\)).*/\
			   WIN_FUNC_DECL(\1, \2)/p' \
			-e 's/.*WIN_FUNC_PTR(\([^\,]\+\) *\, *\([0-9]\+\)).*/\
			   WIN_FUNC_DECL(\1, \2)/p' \
		   $< | sed -e 's/[ \t	]\+//' | sort -u; \
		echo "#endif"; \
		echo "struct wrap_export $(basename $<)_exports[] = {";\
		sed -n \
			-e 's/.*WIN_FUNC(_win_\([^\,]\+\) *\, *\([0-9]\+\)).*/\
				WIN_WIN_SYMBOL(\1,\2),/p' \
			-e 's/.*WIN_FUNC(\([^\,]\+\) *\, *\([0-9]\+\)).*/\
				WIN_SYMBOL(\1,\2),/p' \
			-e 's/.*WIN_SYMBOL_MAP(\("[^"]\+"\)[ ,\n]\+\([^)]\+\)).*/\
				{\1,(generic_func)\2},/p'  \
			   $< | sed -e 's/[ \t	]*/   /' | sort -u; \
		echo "   {NULL, NULL}"; \
		echo "};"; \
	fi > $@

gen_exports: crt_exports.h ndis_exports.h hal_exports.h ntoskernel_exports.h \
			 ntoskernel_io_exports.h rtl_exports.h usb_exports.h

compat.h: $(KBUILD)/include/linux/version.h
	@echo "/* this file is automatically generated */" > $@
	@if ! grep -qw kzalloc $(KSRC)/include/linux/slab.h; then \
		echo "static inline void *kzalloc(size_t size, unsigned long flags)"; \
		echo "{ void *ret = kmalloc(size, flags);"; \
		echo "if (ret) memset(ret, 0, size); return ret;}"; \
	fi >> $@
	@if [ -f $(KSRC)/include/linux/netdevice.h ]; then \
		echo "#include <linux/netdevice.h>"; \
	fi >> $@
	@if ! grep -qw netif_tx_lock $(KSRC)/include/linux/netdevice.h; then \
		echo "static inline void netif_tx_lock(struct net_device *dev)"; \
		echo "{ spin_lock(&dev->xmit_lock); }"; \
		echo "static inline void netif_tx_unlock(struct net_device *dev)"; \
		echo "{ spin_unlock(&dev->xmit_lock); }"; \
		echo "static inline void netif_tx_lock_bh(struct net_device *dev)"; \
		echo "{ spin_lock_bh(&dev->xmit_lock); }"; \
		echo "static inline void netif_tx_unlock_bh(struct net_device *dev)"; \
		echo "{ spin_unlock_bh(&dev->xmit_lock); }"; \
	fi >> $@
	@if ! grep -qw netif_poll_enable $(KSRC)/include/linux/netdevice.h; then \
	    echo "static inline void netif_poll_enable(struct net_device *dev) {}"; \
	    echo "static inline void netif_poll_disable(struct net_device *dev) {}"; \
	fi >> $@
	@if ! grep -qw pci_set_consistent_dma_mask \
			   $(KSRC)/include/linux/pci.h; then \
		echo "static inline int pci_set_consistent_dma_mask" ; \
		echo "(struct pci_dev *dev, u64 mask) { return 0; }" ; \
	fi >> $@
	@if ! grep -qw create_workqueue $(KSRC)/include/linux/*.h; then \
		echo "#define WRAP_WQ 1"; \
	fi >> $@
	@if ! grep -qw create_workqueue $(KSRC)/include/linux/*.h; then \
		echo "#define WRAP_WQ 1"; \
	fi >> $@
	@if [ -f $(KSRC)/include/linux/percpu.h ]; then \
		echo "#include <linux/percpu.h>"; \
	fi >> $@
	@if grep -qw proc_net $(KSRC)/include/linux/proc_fs.h; then \
		echo "#define proc_net_root proc_net"; \
     else \
		echo "#define proc_net_root init_net.proc_net"; \
	fi >> $@

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

clean:
	rm -f *.o *.ko .*.cmd *.mod.c compat.h *.symvers modules.order *~
	rm -rf .tmp_versions

distclean: clean
	rm -f *_exports.h .\#* win2lin_stubs.h

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

default:
	$(MAKE) -C $(KBUILD) SUBDIRS=$(SRC_DIR)


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

install: prereq_check win2lin_stubs.h gen_exports compat.h default stack_check
	echo $(INST_DIR)
	mkdir -p $(INST_DIR)
	install -m 0644 $(MODULE) $(INST_DIR)
	-@/bin/rm -rf $(SRC_DIR)/.tmp_versions
ifndef DIST_DESTDIR
	-/sbin/depmod -a $(KVERS) -b $(DESTDIR)
endif

dist:
	@for file in $(DISTFILES); do \
	  cp  $$file $(distdir)/$$file; \
	done

