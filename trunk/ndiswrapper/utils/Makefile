loaddriver_OBJS = loaddriver.o

CFLAGS = -g -Wall
loaddriver: $(loaddriver_OBJS)
	gcc -o loaddriver $(loaddriver_OBJS)

all: loaddriver

clean:
	rm -f *~
	rm -f *.o
	rm -f loaddriver
