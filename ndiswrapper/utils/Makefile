-include ../version

DESTDIR =
sbindir = $(DESTDIR)/sbin
usrsbindir = $(DESTDIR)/usr/sbin

OBJS = loadndisdriver.o

CFLAGS = -Wall -g -DNDISWRAPPER_VERSION=\"$(NDISWRAPPER_VERSION)\" 

DISTFILES=Makefile ndiswrapper loadndisdriver.c ndiswrapper-buginfo

all: loadndisdriver 

loadndisdriver: $(OBJS) ../driver/wrapper.h
	gcc -o loadndisdriver $(OBJS)
	
clean:
	rm -f *~ *.o loadndisdriver

distclean: clean
	rm -f .\#*

install: all
	install -D -m 755 loadndisdriver $(sbindir)/loadndisdriver
	install -D -m 755 ndiswrapper $(usrsbindir)/ndiswrapper
	install -D -m 755 ndiswrapper-buginfo $(usrsbindir)/ndiswrapper-buginfo

dist:
	@for file in $(DISTFILES); do \
	  cp  $$file $(distdir)/$$file; \
	done
