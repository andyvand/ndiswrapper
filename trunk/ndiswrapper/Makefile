-include version

RPM_SOURCE_DIR ?= `rpmbuild -E %{_sourcedir}`

distdir=ndiswrapper-${NDISWRAPPER_VERSION}
distarchive=${distdir}.tar.gz

DISTFILES=AUTHORS ChangeLog INSTALL Makefile README ndiswrapper.spec.in version ndiswrapper.8
DIST_SUBDIRS=utils driver debian

.PHONY: all

all: 
	make -C driver
	make -C utils
	
.PHONY: install
install:
	make -C driver install
	make -C utils install
	@if test -d /usr/man/man8; then \
		install -m 644 ndiswrapper.8 /usr/man/man8; \
	else \
		install -m 644 ndiswrapper.8 /usr/share/man/man8; \
	fi

.PHONY: clean distclean
clean:
	make -C driver clean
	make -C utils clean
	rm -f *~ ndiswrapper.spec
	rm -fr ${distdir} ${distdir}.tar.gz *.deb patch-stamp

distclean: clean
	make -C driver distclean
	make -C utils distclean
	rm -f .\#*

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
	tar cfz ${distarchive} ${distdir}
	
rpm: dist ndiswrapper.spec.in
	cat ndiswrapper.spec.in | sed s/NDISWRAPPER_VERSION/${NDISWRAPPER_VERSION}/ >ndiswrapper.spec
	cp $(distarchive) $(RPM_SOURCE_DIR)
	rpmbuild -ba ndiswrapper.spec

deb:
	@if [ -d debian ]; then \
		echo -e "ndiswrapper (${NDISWRAPPER_VERSION}) unstable; urgency=low\n\n  * see ChangeLog for details\n\n -- NdisWrapper Team <ndiswrapper-general@lists.sourceforge.net>  `date '+%a, %d %b %Y %H:%M:%S %z'`" > debian/changelog; \
		fakeroot make -f debian/rules binary; \
	else \
		 echo "Huh?"; \
	fi
