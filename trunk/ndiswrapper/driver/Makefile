ifndef DRV_VERSION
#DRV_VERSION="$(shell cat ../version)@$(shell date +'%d-%b-%y+%R')"
#DRV_VERSION="$(shell cat ../version)@$(shell date +'%d-%b-%y')"
DRV_VERSION="$(shell cat ../version)"
endif

DISTFILES=Makefile \
 coffpe.h \
 ndiswrapper.h \
 loader.c loader.h \
 ndis.c ndis.h \
 hal.c \
 ntoskernel.c ntoskernel.h \
 iw_ndis.c iw_ndis.h \
 wrapper.c wrapper.h \
 proc.c misc_funcs.c \
 divdi3.c longlong.h \
 usb.h usb.c


ifndef KVER
KVER := $(shell uname -r)
endif

KVERS := $(shell echo $(KVER) |  sed -e 's/\([^\.]*\)\.\([^\.]*\)\..*/\1\2/')

ifndef KSRC
KSRC  := /lib/modules/$(KVER)/build
endif

INST_DIR := /lib/modules/$(KVER)/misc

SRC_DIR=$(shell pwd)

.PHONY: prereq_check

.PHONY: clean

.PHONY: install

all : prereq_check default

wrapper.o:	wrapper.c loader.h ndis.h

iw_ndis..o:	iw_ndis.c iw_ndis.h

loader.o:	loader.c loader.h ndis.h

misc_funcs.o:	misc_funcs.c ndis.h

hal.o:		hal.c ndis.h

ntoskernel.o: ntoskernel.c ntoskernel.h

ndis.o:	ndis.c ndis.h

proc.o : proc.c ndis.h

divdi3.o: divdi3.c longlong.h

iw_ndis.h : ndis.h

ndis.h : ntoskernel.h

ntoskernel.h : ndiswrapper.h

usb.o : usb.c ndis.h

OBJS   := wrapper.o iw_ndis.o loader.o ntoskernel.o ndis.o misc_funcs.o proc.o divdi3.o hal.o usb.o

ifdef DEBUG
CFLAGS += -DDEBUG=$(DEBUG) -g -DDEBUG_TIMER
endif

ifdef DEBUG_TIMER
CFLAGS += -DDEBUG_TIMER
endif

prereq_check:
	@ if [ ! -f $(KSRC)/include/linux/version.h ]; then \
		echo "You don't seem to have sources for your kernel; \
		       install them in /usr/src, link $(KSRC) to it and try again."; \
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
	@ echo -e "\n**\nPlease re-install utils and Windows drivers, as "
	@ echo -e "file formats have changed since 0.9 release.\n"

clean:
	rm -f $(MODULE) $(OBJS)

else

MODULE := ndiswrapper.ko
obj-m := ndiswrapper.o 
ndiswrapper-objs := $(OBJS)

default:
	$(MAKE) -C $(KSRC) SUBDIRS=$(SRC_DIR) DRV_VERSION=$(DRV_VERSION) modules
	@ echo -e "\n**\nPlease re-install utils and Windows drivers, as "
	@ echo -e "file formats have changed since 0.9 release.\n"

clean:
	rm -f $(MODULE) ndiswrapper.o $(OBJS) .ndiswrapper.ko.cmd ndiswrapper.mod.[oc] .*.o.cmd *~
	rm -rf .tmp_versions

endif

install: default
	mkdir -p $(INST_DIR)
	install -m 0644 $(MODULE) $(INST_DIR)
	/sbin/depmod -a

dist:
	@for file in $(DISTFILES); do \
	  cp  $$file $(distdir)/$$file; \
	done

