loaddriver_OBJS = loaddriver.o inf-parser.o

CFLAGS = -g -Wall
LEX = flex

loaddriver: $(loaddriver_OBJS) ../driver/wrapper.h
	gcc -o loaddriver $(loaddriver_OBJS)

all: loaddriver

clean:
	rm -f *~
	rm -f *.o
	rm -f loaddriver
