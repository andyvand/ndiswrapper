DRV_VERSION=$(shell cat version)

distdir=ndiswrapper-${DRV_VERSION}
distarchive=${distdir}.tar.gz

DISTFILES=AUTHORS ChangeLog INSTALL Makefile README ndiswrapper.spec.in version
DIST_SUBDIRS=utils driver debian

.PHONY: all

all: 
	make -C driver
	make -C utils
	install -m 644 ndiswrapper.8 /usr/man/man8
	
.PHONY: install
install:
	make -C driver install
	make -C utils install

.PHONY: clean
clean:
	make -C driver clean
	make -C utils clean
	rm -f *~ ndiswrapper.spec
	rm -fr ${distdir} ${distdir}.tar.gz *.deb patch-stamp

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
	cat ndiswrapper.spec.in | sed s/DRV_VERSION/${DRV_VERSION}/ >ndiswrapper.spec
	if test -d /usr/src/redhat/SOURCES ; then \
	  cp $(distarchive) /usr/src/redhat/SOURCES ;\
	else \
	  cp $(distarchive) /usr/src/RPM/SOURCES ; \
	fi
	rpmbuild -ba ndiswrapper.spec

deb:
	@if [ -d debian ]; then \
		echo -e "ndiswrapper (${DRV_VERSION}) unstable; urgency=low\n\n  * see ChangeLog for details\n\n -- NdisWrapper Team <ndiswrapper-general@lists.sourceforge.net>  `date '+%a, %d %b %Y %H:%M:%S %z'`" > debian/changelog; \
		fakeroot make -f debian/rules binary; \
	else \
		 echo "Huh?"; \
	fi
