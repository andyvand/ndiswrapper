#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <sys/mman.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "../driver/wrapper.h"



/*
 * Send some ioctl to module 
 */
void test(int device, unsigned long test)
{
	printf("Calling test ioctl\n");
	ioctl(device, WDIOC_TEST, test);
}
	

int get_filesize(int fd)
{
	struct stat statbuf;
	if(!fstat(fd, &statbuf))
	{
		return statbuf.st_size;
	}
	return -1;
}
	
/*
 * Open a windows driver and pass it to the kernel module.
 */
int load(char *filename, int device)
{
	int driver = open(filename, O_RDONLY);

	if(driver == -1)
	{
		perror("Unable to open driver");
		return 1;
	}

	int size = get_filesize(driver);
	void * image;
	image = mmap(0, size, PROT_READ, MAP_PRIVATE, driver, 0);

	if((int)image == -1)
	{
		perror("Unable to mmap driver");
		return 1;
	}


	char * buf = malloc(size + 4);
	memcpy(buf+4, image, size);
	*((unsigned int*)buf) = size;

	printf("Calling putdriver ioctl\n");
	ioctl(device, WDIOC_PUTDRIVER, buf);

	close(driver);

	return 0;
}

	
/*
 * Open a misc device without having a /dev/ entry
 */
int openMiscDevice(int minor)
{
	char tmp[] = {"/tmp/ndiswrapperXXXXXX"};
	int fd = mkstemp(tmp);
	unlink(tmp);
	close(fd);
	if(mknod(tmp, S_IFCHR | 0600, 10 << 8 | minor) == -1)
		return -1;

	fd = open(tmp, O_RDONLY);
	unlink(tmp);
	if(fd == -1)
		return -1;
	return fd;
}

/*
 * Parse /proc/misc to get the minor of out kernel driver
 */
int getMiscMinor()
{
	char line[200];
	FILE *misc = fopen("/proc/misc", "r");
	int minor = -1;
	if(!misc)
		return -1;
	while(fgets(line, sizeof(line), misc))
	{
		if(strstr(line, "ndiswrapper"))
		{
			int i = strtol(line, 0, 10);
			if(!errno)
			{
				minor = i;
				break;
			}
			
		}
	}
	fclose(misc);
	return minor;
}

	
int main(int argc, char* argv[])
{
	int device;
	int misc_minor;


	if(argc < 2)
	{
		fprintf(stderr, "Usage: %s windowsdriver.sys\n", argv[0]);
		return 1;
	}

	misc_minor = getMiscMinor();

	if(misc_minor == -1)
	{
		fprintf(stderr, "Cannot find minor for kernel module. Module loaded?\n");
		return 1;
	}
	
	device = openMiscDevice(misc_minor);
	if(device == -1)
	{
		perror("Unable to open kernel driver");
		return 1;
	}
	
	if(strcmp(argv[1], "-t") == 0)
		test(device, atoi(argv[2]));
	else
		load(argv[1], device);

	close(device);
	return 0;
}

