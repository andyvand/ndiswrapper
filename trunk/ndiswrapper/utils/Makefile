-include ../version

loadndisdriver_OBJS = loadndisdriver.o

CFLAGS = -Wall -g -DNDISWRAPPER_VERSION=\"$(NDISWRAPPER_VERSION)\" 

DISTFILES=Makefile ndiswrapper loadndisdriver.c ndiswrapper-buginfo

all: loadndisdriver 

loadndisdriver: $(loadndisdriver_OBJS) ../driver/wrapper.h
	gcc -o loadndisdriver $(loadndisdriver_OBJS)
	
clean:
	rm -f *~ *.o loadndisdriver

install: all
	install -m 755 loadndisdriver /sbin
	install -m 755 ndiswrapper /usr/sbin
	install -m 755 ndiswrapper-buginfo /usr/sbin

dist:
	@for file in $(DISTFILES); do \
	  cp  $$file $(distdir)/$$file; \
	done
