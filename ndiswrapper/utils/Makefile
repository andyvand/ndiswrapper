loadndisdriver_OBJS = loadndisdriver.o

CFLAGS = -Wall -g

DISTFILES=Makefile ndiswrapper loadndisdriver.c

loadndisdriver: $(loadndisdriver_OBJS) ../driver/wrapper.h
	gcc -o loadndisdriver $(loadndisdriver_OBJS)
	
all: loadndisdriver

clean:
	rm -f *~
	rm -f *.o
	rm -f loadndisdriver

install: all
	install -m 755 loadndisdriver /sbin
	install -m 755 ndiswrapper /usr/sbin

dist:
	@for file in $(DISTFILES); do \
	  cp  $$file $(distdir)/$$file; \
	done

