DRV_VERSION=$(shell cat version)

distdir=ndiswrapper-${DRV_VERSION}
distarchive=${distdir}.tar.gz

DISTFILES=AUTHORS ChangeLog INSTALL Makefile README ndiswrapper.spec.in version
DIST_SUBDIRS=utils driver

.PHONY: all

all: 
	make -C driver
	make -C utils

	
.PHONY: install
install:
	make -C driver install
	make -C utils install

.PHONY: clean
clean:
	make -C driver clean
	make -C utils clean
	rm -f *~ ndiswrapper.spec

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
	tar cfz ${distarchive} ${distdir}
	
rpm: dist ndiswrapper.spec.in
	cat ndiswrapper.spec.in | sed s/DRV_VERSION/${DRV_VERSION}/ >ndiswrapper.spec
	if test -d /usr/src/redhat/SOURCES ; then \
	  cp $(distarchive) /usr/src/redhat/SOURCES ;\
	else \
	  cp $(distarchive) /usr/src/RPM/SOURCES ; \
	fi
	rpmbuild -ba ndiswrapper.spec

