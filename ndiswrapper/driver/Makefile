ifndef DRV_VERSION
DRV_VERSION=$(shell cat ../version)
endif
#DEBUG=1

DISTFILES=Makefile coffpe.h loader.c loader.h misc_funcs.c \
 ndis.c ndis.h ntoskernel.h proc.c rt8180.c \
 winsyms.c winsyms.h wrapper.c wrapper.h \
 divdi3.c longlong.h


KSRC  := /lib/modules/$(shell uname -r)/build

KVERS := $(shell uname -r |  sed -e 's/\([^\.]*\)\.\([^\.]*\)\..*/\1\2/')

INST_DIR := /lib/modules/$(shell uname -r)/misc

SRC_DIR=$(shell pwd)

.PHONY: prereq_check

.PHONY: clean

.PHONY: install

all : prereq_check default

wrapper.o:	wrapper.c loader.h ndis.h loader.h

loader.o:	loader.c ndis.h

winsyms.o:	winsyms.c ndis.h

misc_funcs.o:	misc_funcs.c ndis.h

ndis.o:	ndis.c ndis.h

proc.o : proc.c ndis.h

divdi3.o: divdi3.c longlong.h

OBJS   := wrapper.o loader.o winsyms.o ndis.o misc_funcs.o proc.o divdi3.o

ifdef DBG_ATHEROS
CFLAGS += -DDBG_ATHEROS
endif

ifdef DBG_TI
CFLAGS += -DDBG_TI
endif

ifdef DBG_REALTEK
CFLAGS += -DDBG_REALTEK

rt8180.o : rt8180.c
endif

ifdef DEBUG
CFLAGS += -DDEBUG -g
endif

prereq_check:
	@ if [ ! -f $(KSRC)/include/linux/version.h ]; then \
		echo "You don't seem to have sources for your kernel; \
		       install them in /usr/src, link $(KSRC) to it and try again."; \
		exit 1;\
	  fi
	@ if grep -q ' SMP ' /proc/version; then \
		echo "SMP is enabled in the kernel;\
			right now ndiswrapper doesn't work with SMP.\
			Disable SMP to use ndiswrapper.";\
		exit 1;\
	fi


CFLAGS += $(shell [ -f $(KSRC)/include/linux/modversions.h ] && echo -DEXPORT_SYMTAB -DMODVERSIONS -include $(KSRC)/include/linux/modversions.h)

ifdef DRV_VERSION
CFLAGS += -DDRV_VERSION=\"${DRV_VERSION}\"
endif


ifeq ($(KVERS),24)
MODULE := ndiswrapper.o
CFLAGS  += -DLINUX -D__KERNEL__ -DMODULE -I$(KSRC)/include \
  -Wall -Wstrict-prototypes -fomit-frame-pointer    \
  -fno-strict-aliasing -pipe -mpreferred-stack-boundary=2 -O2

default: $(OBJS)
	$(LD) -r -o $(MODULE) $(OBJS)
clean:
	rm -f $(MODULE) $(OBJS)

else
MODULE := ndiswrapper.ko
obj-m := ndiswrapper.o 
ndiswrapper-objs := $(OBJS)

default:
	$(MAKE) -C $(KSRC) SUBDIRS=$(SRC_DIR) DRV_VERSION=$(DRV_VERSION) modules

clean:
	rm -f $(MODULE) ndiswrapper.o $(OBJS) .ndiswrapper.ko.cmd ndiswrapper.mod.[oc] .*.o.cmd *~

endif

install: default
	mkdir -p $(INST_DIR)
	install -m 0644 $(MODULE) $(INST_DIR)
	/sbin/depmod -a

dist:
	@for file in $(DISTFILES); do \
	  cp  $$file $(distdir)/$$file; \
	done

