ifneq ($(KERNELRELEASE),)
obj-m := ndiswrapper.o 
ndiswrapper-objs := wrapper.o loader.o winsyms.o ndis.o misc_funcs.o
else
CFLAGS += -g
KDIR	:= /lib/modules/$(shell uname -r)/build
PWD	:= $(shell pwd)

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules


CFLAGS=-g -Wall
test_OBJS := test.o loader.o winsyms.o ndis.o misc_funcs.o
test: $(test_OBJS)
	gcc -o test $(test_OBJS)


clean:
	rm -f *.ko 
	rm -f *.o
	rm -f .*.cmd
	rm -f *.mod.c
	rm -f *~
	rm -f test

endif
