VERSION=0.4+CVS

distdir=ndiswrapper-${VERSION}
distarchive=${distdir}.tar.gz

DISTFILES=AUTHORS ChangeLog INSTALL Makefile README ndiswrapper.spec.in
DIST_SUBDIRS=utils driver

.PHONY: all

all: 
	make -C driver VERSION=${VERSION} 
	make -C utils VERSION=${VERSION}

	
.PHONY: install
install:
	make -C driver VERSION=${VERSION} install
	make -C utils VERSION=${VERSION} install

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
	cat ndiswrapper.spec.in | sed s/VERSION/${VERSION}/ >ndiswrapper.spec
	cp ${distarchive} /usr/src/redhat/SOURCES
	rpmbuild -ba ndiswrapper.spec

