/*
 * This program enables/disables the radio for
 * Averatec 5110HX
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/io.h>

int main()
{
	int ret = 0;
	char c;
	unsigned int r_cfc;
	unsigned int r_1184;
	unsigned int r_118c;

	if (iopl(3))
	{
		perror("iopl");
		exit(1);
	}
  
  	outl(0x80020800, 0xcf8);

	r_cfc = inl(0xcfc);
	if(r_cfc == 0xffffffff)
	{
		fprintf(stderr, "This program is not suitable for your hardware\n");
		ret = 1;
		goto out;
	}

	outb(0x6f, 0x72);
	inb(0x73);	

	r_1184 = inl(0x1184);
	outl(r_1184 | 0x10000000, 0x1184);
	
	r_118c = inl(0x118c);

	r_118c &= 0x10000000;
	if(r_118c == 0x10000000)
	{
		printf("Turning radio off\n");
		c = 0xe1;
	}
	else
	{
		printf("Turning radio on\n");
		c = 0xe0;
	}
	
	outb(c, 0xb2);	
out:
	iopl(0);
	return ret;
}
