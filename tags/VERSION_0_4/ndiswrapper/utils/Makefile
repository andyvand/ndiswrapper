loadndisdriver_OBJS = loadndisdriver.o inf-parser.o

CFLAGS = -g -Wall
LEX = flex

loadndisdriver: $(loadndisdriver_OBJS) ../driver/wrapper.h
	gcc -o loadndisdriver $(loadndisdriver_OBJS)

all: loadndisdriver

clean:
	rm -f *~
	rm -f *.o
	rm -f loadndisdriver
