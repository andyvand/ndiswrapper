ifneq ($(KERNELRELEASE),)
obj-m := ndiswrapper.o 
ndiswrapper-objs := wrapper.o loader.o winsyms.o ndis.o misc_funcs.o
else
CFLAGS += -g
KDIR	:= /lib/modules/$(shell uname -r)/build
PWD	:= $(shell pwd)

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules


clean:
	rm -f *.ko 
	rm -f *.o
	rm -f .*.cmd
	rm -f *.mod.c
	rm -f *~
endif
