DESTDIR =
sbindir = $(DESTDIR)/sbin
usrsbindir = $(DESTDIR)/usr/sbin

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
	install -D -m 755 loadndis6driver $(sbindir)/loadndis6driver
	install -D -m 755 ndis6wrapper $(usrsbindir)/ndis6wrapper
	install -D -m 755 ndiswrapper-buginfo $(usrsbindir)/ndiswrapper-buginfo
	@echo

dist:
	@for file in $(DISTFILES); do \
	  cp  $$file $(distdir)/$$file; \
	done
