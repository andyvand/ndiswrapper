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
	rm -f *~
