-include ../version

OBJS = loadndisdriver.o

CFLAGS = -Wall -g -DNDISWRAPPER_VERSION=\"$(NDISWRAPPER_VERSION)\" 

DISTFILES=Makefile ndiswrapper loadndisdriver.c ndiswrapper-buginfo

all: loadndisdriver 

loadndisdriver: $(OBJS) ../driver/wrapper.h
	gcc -o loadndisdriver $(OBJS)
	
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
