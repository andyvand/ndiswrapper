-include ../version

DISTFILES=Makefile ndiswrapper.h pe_loader.c pe_loader.h  ndis.c ndis.h \
				   hal.c ntoskernel.c ntoskernel.h  iw_ndis.c iw_ndis.h \
				   wrapper.c wrapper.h  proc.c misc_funcs.c \
				   divdi3.c longlong.h usb.c usb.h

KVERS ?= $(shell uname -r)
KSRC  ?= /lib/modules/$(KVERS)/build

KPSUB := $(shell echo $(KVERS) |  sed -e 's/\([^\.]*\)\.\([^\.]*\)\..*/\1\2/')

INST_DIR := /lib/modules/$(KVERS)/misc

SRC_DIR=$(shell pwd)

.PHONY: prereq_check clean install

all : prereq_check default

wrapper.o: wrapper.c pe_loader.h ndis.h

iw_ndis..o:	iw_ndis.c iw_ndis.h

pe_loader.o: pe_loader.c pe_loader.h

misc_funcs.o: misc_funcs.c ndis.h

hal.o: hal.c ndis.h

ntoskernel.o: ntoskernel.c ntoskernel.h

ndis.o:	ndis.c ndis.h

proc.o: proc.c ndis.h

divdi3.o: divdi3.c longlong.h

iw_ndis.h: ndis.h

ndis.h : ntoskernel.h

ntoskernel.h : ndiswrapper.h

usb.o: usb.c usb.h ndis.h

OBJS := wrapper.o iw_ndis.o pe_loader.o ntoskernel.o ndis.o \
		  misc_funcs.o proc.o divdi3.o hal.o

ifeq ($(KPSUB),24)
-include $(KSRC)/.config
endif

ifeq ($(CONFIG_USB),y)
OBJS += usb.o
endif
ifeq ($(CONFIG_USB),m)
OBJS += usb.o
endif

ifdef DEBUG
CFLAGS += -DDEBUG=$(DEBUG) -g -DDEBUG_TIMER
endif

ifdef DEBUG_TIMER
CFLAGS += -DDEBUG_TIMER
endif

prereq_check:
	@ if [ ! -f $(KSRC)/include/linux/version.h ]; then \
		echo "Can't find kernel sources in $(KSRC);"; \
		echo "  give the path to kernel sources with KSRC=<path>\
		       argument to make";\
		exit 1;\
	  fi

CFLAGS += $(shell [ -f $(KSRC)/include/linux/modversions.h ] && \
		  echo -DEXPORT_SYMTAB -DMODVERSIONS \
		  -include $(KSRC)/include/linux/modversions.h)

ifdef NDISWRAPPER_VERSION
CFLAGS += -DNDISWRAPPER_VERSION=\"${NDISWRAPPER_VERSION}\" \
		  -DEXTRA_VERSION=\"${EXTRA_VERSION}\"
endif

ifeq ($(KPSUB),24)
MODULE := ndiswrapper.o
CFLAGS  += -DLINUX -D__KERNEL__ -DMODULE -I$(KSRC)/include \
		  -Wall -Wstrict-prototypes -fomit-frame-pointer    \
		  -fno-strict-aliasing -pipe -mpreferred-stack-boundary=2 -O2

default: $(OBJS)
	$(LD) -r -o $(MODULE) $(OBJS)
clean:
	rm -f $(MODULE) $(OBJS) usb.o

else

MODULE := ndiswrapper.ko
obj-m := ndiswrapper.o 
ndiswrapper-objs := $(OBJS)

default:
	$(MAKE) -C $(KSRC) SUBDIRS=$(SRC_DIR) \
		NDISWRAPPER_VERSION=$(NDISWRAPPER_VERSION) \
		EXTRA_VERSION=$(EXTRA_VERSION) modules

clean:
	rm -rf $(MODULE) ndiswrapper.o $(OBJS) usb.o .ndiswrapper.ko.cmd \
	   ndiswrapper.mod.[oc] .*.o.cmd *~ .tmp_versions

endif

install: default
	mkdir -p $(INST_DIR)
	install -m 0644 $(MODULE) $(INST_DIR)
	/sbin/depmod -a

dist:
	@for file in $(DISTFILES); do \
	  cp  $$file $(distdir)/$$file; \
	done

