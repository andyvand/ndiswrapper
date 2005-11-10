-include ../version

DESTDIR =
sbindir = $(DESTDIR)/sbin
usrsbindir = $(DESTDIR)/usr/sbin

OBJS = loadndisdriver.o
FW_AR5523 = load_fw_ar5523

CFLAGS = -Wall -g -DUTILS_VERSION=\"$(UTILS_VERSION)\" 

DISTFILES=Makefile ndiswrapper loadndisdriver.c $(FW_AR5523).c \
				   ndiswrapper-buginfo

all: loadndisdriver 

loadndisdriver: $(OBJS)
	gcc -o loadndisdriver $(OBJS)
	
$(FW_AR5523): $(FW_AR5523).c
	@if :; then \
		USB_LIBS="$(shell libusb-config --libs)"; \
		if [ -z "$$USB_LIBS" ]; then \
			   echo "USB programming library is not installed"; \
			   exit 1; \
		fi; \
		cmd="gcc -Wall -o $@ $< $$USB_LIBS"; \
		echo "$$cmd"; \
		$$cmd; \
	fi

clean:
	rm -f *~ *.o loadndisdriver $(FW_AR5523)

distclean: clean
	rm -f .\#*

install: all
	install -D -m 755 loadndisdriver $(sbindir)/loadndisdriver
	install -D -m 755 ndiswrapper $(usrsbindir)/ndiswrapper
	install -D -m 755 ndiswrapper-buginfo $(usrsbindir)/ndiswrapper-buginfo
	if [ -f $(FW_AR5523) ]; then \
		install -D -m 755 $(FW_AR5523) $(usrsbindir)/$(FW_AR5523); \
	fi
	@echo
	@echo "NOTE: Windows driver configuration file format has changed since" \
		  "1.0-rc2. You must re-install Windows drivers if they were" \
		  "installed before."

dist:
	@for file in $(DISTFILES); do \
	  cp  $$file $(distdir)/$$file; \
	done
