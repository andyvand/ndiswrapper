DISTFILES=Makefile control.modules control.utils copyright dirs.utils docs \
	README.Debian rules changelog.template control.source postinst.modules

dist:
	@for file in $(DISTFILES); do \
		cp  $$file $(distdir)/$$file; \
	done

