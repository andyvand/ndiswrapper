-include ../version

DESTDIR =
sbindir = $(DESTDIR)/sbin
usrsbindir = $(DESTDIR)/usr/sbin

CFLAGS = -Wall -DUTILS_VERSION=\"$(UTILS_VERSION)\" 
CFLAGS += $(shell if :; then \
				  libusb-config --libs && echo '-DLIB_USB'; \
				  fi 2>/dev/null)

DISTFILES=Makefile ndiswrapper loadndisdriver.c $(FW_AR5523).c \
				   ndiswrapper-buginfo

all: loadndisdriver 

loadndisdriver: loadndisdriver.c
	$(CC) $(CFLAGS) -o $@ $<
	
clean:
	rm -f *~ *.o loadndisdriver $(FW_AR5523)

distclean: clean
	rm -f .\#*

install: all
	install -D -m 755 loadndisdriver $(sbindir)/loadndisdriver
	install -D -m 755 ndiswrapper $(usrsbindir)/ndiswrapper
	install -D -m 755 ndiswrapper-buginfo $(usrsbindir)/ndiswrapper-buginfo
	@echo
	@echo "NOTE: Windows driver configuration file format has changed since" \
		  "1.0-rc2. You must re-install Windows drivers if they were" \
		  "installed before."

dist:
	@for file in $(DISTFILES); do \
	  cp  $$file $(distdir)/$$file; \
	done
