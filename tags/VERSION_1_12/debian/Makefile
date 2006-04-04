DISTFILES=Makefile changelog.modules changelog.source changelog.utils \
			control.modules control.source control.utils copyright \
			dirs.utils docs postinst.modules README.Debian rules

dist:
	@for file in $(DISTFILES); do \
		cp  $$file $(distdir)/$$file; \
	done

