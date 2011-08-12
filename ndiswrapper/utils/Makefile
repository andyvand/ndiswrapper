sbindir = /sbin
usrsbindir = /usr/sbin

DRIVER_DIR ?= ../driver

CC = gcc
CFLAGS = -g -Wall -I$(DRIVER_DIR)

DISTFILES=Makefile ndis6wrapper loadndisdriver.c ndiswrapper-buginfo

all: loadndis6driver

loadndis6driver: loadndisdriver.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f *~ *.o loadndis6driver

distclean: clean
	rm -f .\#*

install: all
	mkdir -p -m 0755 $(DESTDIR)$(sbindir)
	mkdir -p -m 0755 $(DESTDIR)$(usrsbindir)
	install -m 755 loadndis6driver $(DESTDIR)$(sbindir)
	install -m 755 ndis6wrapper $(DESTDIR)$(usrsbindir)
	install -m 755 ndiswrapper-buginfo $(DESTDIR)$(usrsbindir)

uninstall:
	rm -f $(DESTDIR)$(sbindir)/loadndis6driver
	rm -f $(DESTDIR)$(usrsbindir)/ndis6wrapper
	rm -f $(DESTDIR)$(usrsbindir)/ndiswrapper-buginfo

dist:
	@for file in $(DISTFILES); do \
	  cp $$file $(distdir)/$$file || exit 1; \
	done
