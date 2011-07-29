DRIVER_VERSION = $(shell sed -n 's/^\#define[ \t]\+DRIVER_VERSION[ \t]\+"\([^"]\+\)"/\1/p' driver/ndiswrapper.h)

UTILS_VERSION = $(shell sed -n 's/^\#define[ \t]\+UTILS_VERSION[ \t]\+"\([^"]\+\)"/\1/p' driver/ndiswrapper.h)

distdir=ndiswrapper-${DRIVER_VERSION}
distarchive=${distdir}.tar.gz

DISTFILES=AUTHORS ChangeLog INSTALL Makefile README ndiswrapper.spec \
				   ndiswrapper.8 loadndisdriver.8
DIST_SUBDIRS=utils driver

DESTDIR =
mandir = $(DESTDIR)$(shell [ -d /usr/man/man8 ] && echo /usr/man || echo /usr/share/man )

KVERS ?= $(shell uname -r)

.PHONY: all

all:
	+$(MAKE) -C driver
	+$(MAKE) -C utils

.PHONY: install
install:
	+$(MAKE) -C driver install
	+$(MAKE) -C utils install
	mkdir -p -m 0755 $(mandir)/man8
	install -m 644 ndiswrapper.8 $(mandir)/man8
	install -m 644 loadndisdriver.8 $(mandir)/man8

.PHONY: clean distclean
clean:
	+$(MAKE) -C driver clean
	+$(MAKE) -C utils clean
	rm -f *~
	rm -fr ${distdir} ${distdir}.tar.gz patch-stamp

distclean: clean
	+$(MAKE) -C driver distclean
	+$(MAKE) -C utils distclean
	rm -f .\#*

uninstall:
	@echo "NOTE: Not all installed files are removed, as different" \
		"distributions install ndiswrapper files at different places."
	@echo "Run uninstall as many times as necessary until no" \
		"\"removing\" messages appear below."
	@if [ "x$(shell which loadndisdriver)" != "x" ]; then \
		echo "removing $(shell which loadndisdriver)"; \
		/bin/rm -f $(shell which loadndisdriver); \
	fi
	@if [ "x$(shell which ndiswrapper)" != "x" ]; then \
		echo "removing $(shell which ndiswrapper)"; \
		/bin/rm -f $(shell which ndiswrapper); \
	fi
	@if [ "x$(shell which ndiswrapper-buginfo)" != "x" ]; then \
		echo "removing $(shell which ndiswrapper-buginfo)"; \
		/bin/rm -f $(shell which ndiswrapper-buginfo); \
	fi
	@for module in $(shell find /lib/modules/$(KVERS) -type f | \
			grep 'ndiswrapper.\(\(ko\)\|\(o\)\)'$); do \
		echo "removing $$module"; \
		/bin/rm -f $$module; \
	done

dist:
	@rm -rf ${distdir}
	mkdir -p ${distdir}
	@for file in $(DISTFILES); do \
	  cp  $$file $(distdir)/$$file; \
	done
	for subdir in $(DIST_SUBDIRS); do \
	  if test "$$subdir" = .; then :; else \
	    test -d $(distdir)/$$subdir \
	    || mkdir $(distdir)/$$subdir \
	    || exit 1; \
	  fi; \
	done
	+$(MAKE) -C driver distdir=../${distdir}/driver dist
	+$(MAKE) -C utils distdir=../${distdir}/utils dist

	# Update version in dist rpm spec file - don't crash if it fails
	-sed -i "s/\%define\s\+ndiswrapper_version\s\+[^\}]\+\}/%define ndiswrapper_version $(DRIVER_VERSION)\}/" $(distdir)/ndiswrapper.spec
	tar cfz ${distarchive} ${distdir}

rpm: dist ndiswrapper.spec
	rpmbuild -ta $(distarchive) --define="ndiswrapper_version $(DRIVER_VERSION)"

