-include version

distdir=ndiswrapper-${DRIVER_VERSION}
distarchive=${distdir}.tar.gz

DISTFILES=AUTHORS ChangeLog INSTALL Makefile README ndiswrapper.spec version ndiswrapper.8
DIST_SUBDIRS=utils driver debian

DESTDIR = 
mandir = $(DESTDIR)$(shell [ -d /usr/man/man8 ] && echo /usr/man || echo /usr/share/man )

KVERS ?= $(shell uname -r)

.PHONY: all

all: 
	make -C driver
	make -C utils

.PHONY: install
install:
	make -C driver install
	make -C utils install
	mkdir -p -m 0755 $(mandir)/man8
	install -m 644 ndiswrapper.8 $(mandir)/man8

.PHONY: clean distclean
clean:
	make -C driver clean
	make -C utils clean
	rm -f *~
	rm -fr ${distdir} ${distdir}.tar.gz *.deb patch-stamp

distclean: clean
	make -C driver distclean
	make -C utils distclean
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
	@for module in $(shell find /lib/modules/$(KVERS) \
			-name "ndiswrapper*"); do \
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
	make -C driver distdir=../${distdir}/driver dist
	make -C utils distdir=../${distdir}/utils dist
	make -C debian distdir=../${distdir}/debian dist
	# Update version in dist rpm spec file - don't crash if it fails
	-sed -i "s/\%define\s\+ndiswrapper_version\s\+[^\}]\+\}/%define ndiswrapper_version $(DRIVER_VERSION)\}/" $(distdir)/ndiswrapper.spec
	tar cfz ${distarchive} ${distdir}

rpm: dist ndiswrapper.spec
	rpmbuild -ta $(distarchive) --define="ndiswrapper_version $(DRIVER_VERSION)"

deb:
	@if [ -d debian ]; then \
		echo -e "ndiswrapper (${DRIVER_VERSION}) unstable; urgency=low\n\n  * see ChangeLog for details\n\n -- NdisWrapper Team <ndiswrapper-general@lists.sourceforge.net>  `date '+%a, %d %b %Y %H:%M:%S %z'`" > debian/changelog; \
		fakeroot make -f debian/rules binary; \
	else \
		 echo "Huh?"; \
	fi
