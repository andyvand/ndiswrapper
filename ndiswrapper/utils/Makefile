loadndisdriver_OBJS = loadndisdriver.o

CFLAGS = -Wall -g

loadndisdriver: $(loadndisdriver_OBJS) ../driver/wrapper.h
	gcc -o loadndisdriver $(loadndisdriver_OBJS)

all: loadndisdriver

clean:
	rm -f *~
	rm -f *.o
	rm -f loadndisdriver
