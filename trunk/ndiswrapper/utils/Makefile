DRV_VERSION="$(shell cat ../version)"

loadndisdriver_OBJS = loadndisdriver.o

CFLAGS = -Wall -g -DDRV_VERSION=\"$(DRV_VERSION)\" 

DISTFILES=Makefile ndiswrapper loadndisdriver.c

all: loadndisdriver 

loadndisdriver: $(loadndisdriver_OBJS) ../driver/wrapper.h
	gcc -o loadndisdriver $(loadndisdriver_OBJS)
	
clean:
	rm -f *~
	rm -f *.o
	rm -f loadndisdriver
	rm -f wlan_radio_averatec_5110hx

install: all
	install -m 755 loadndisdriver /sbin
	install -m 755 ndiswrapper /usr/sbin
dist:
	@for file in $(DISTFILES); do \
	  cp  $$file $(distdir)/$$file; \
	done
