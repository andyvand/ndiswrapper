/*
 *  Copyright (C) 2003 Pontus Fuchs
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 */
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <libgen.h>

#include <sys/mman.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "../driver/wrapper.h"


static int get_filesize(int fd)
{
	struct stat statbuf;
	if(!fstat(fd, &statbuf))
	{
		return statbuf.st_size;
	}
	return -1;
}
	

/*
 * Trim s and remove whitespace at front and back.
 * Also remove quotation-marks if present
 */
static char* trim(char *s)
{
	int len = strlen(s);
	char *whitespace = " \t\r\n";

	/* trim from back */
	while(len)
	{
		if(!strchr(whitespace, s[len]))
			break;
		s[len] = 0;
		len--;
	}

	/* trim from start */
	while(len)
	{
		if(!strchr(whitespace, *s))
			break;
		s++;
		len--;
	}

	/* Remove quotation */
	if(*s == '"' && s[len] == '"')
	{
		s[len] = 0;
		s++;
	}
	return s;
}

	
/*
 * Split a string at c and put int dst
 *
 */
static int split(char *s, char c, char **dst, int dstlen)
{
	int i = 0;
	char *pos;
	char *curr = s;
	while(i < dstlen)
	{
		pos = index(curr, c);
		dst[i] = trim(curr);
		i++;
		if(!pos)
			break;
		*pos = 0;
		curr = pos+1;
	}
	return i;
}


/*
 * Read an inf-file and extract things needed. This is very primitive right now
 * so don't be suprised if some files are misinterpreted right now...
 */
static int loadsettings(int driver, char *inf_name)
{
	struct put_setting setting;
	struct setting_payload payload;
	
	char line[1024];
	char *cols[5];
	int nr_cols;
	
	FILE *inf = fopen(inf_name, "r");
	if(!inf)
	{
		perror("Unable to load inf-file");
		return 1;
	}

	while(fgets(line, sizeof(line), inf))
	{
		nr_cols = split(line, ',', cols, 5);
		if(nr_cols == 5 &&
		   strcasecmp(cols[2], "default") == 0)
		{
			
			char *key = cols[1];
			char *value = cols[4];

			nr_cols = split(key, '\\', cols, 3);
			if(nr_cols != 3)
				continue;
			key = cols[2];
			if(strcasecmp(key, "networkaddress") == 0)
				continue;
			
			// Hack...
			if(strcasecmp(key, "locale") == 0)
				value = "0";
				
			payload.data = atoi(value);

			setting.type = 0;
			setting.name_len = strlen(key);
			setting.name = key;

			setting.payload = &payload;
			setting.payload_len = sizeof(payload);
			
			printf("Adding setting: %s\t= %s\n", key, value);
			if(ioctl(driver, NDIS_PUTSETTING, &setting))
			{
				perror("Unable to put setting (check dmesg for more info)");
				return 1;
			}
		}
	}
	
	fclose(inf);
	return 0;
}

	
/*
 * Open a windows driver and pass it to the kernel module.
 */
static int load(int pci_vendor, int pci_device, char *driver_name, char *inf_name, int device)
{
	struct put_driver put_driver;
	int driver = open(driver_name, O_RDONLY);
	char *driver_basename;

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

	put_driver.pci_vendor = pci_vendor;
	put_driver.pci_device = pci_device;
	put_driver.size = size;
	put_driver.data = image;
	
	driver_basename = basename(driver_name);
	strncpy(put_driver.name, driver_basename, sizeof(put_driver.name));
	put_driver.name[sizeof(put_driver.name)-1] = 0;
	
	printf("Calling putdriver ioctl\n");
	if(ioctl(device, NDIS_PUTDRIVER, &put_driver))
	{
		perror("Unable to put driver (check dmesg for more info)");
		return 1;

	}

	if(!loadsettings(device, inf_name))
	{
		printf("Calling startdriver ioctl\n");

		if(ioctl(device, NDIS_STARTDRIVER, 0))
		{
			perror("Unable to start driver (check dmesg for more info)");
			return 1;
		}
	}
	else
	{
		printf("Loadsettings failed\n");
		if(ioctl(device, NDIS_CANCELLOAD, 0))
		{
			return 1;
		}
	}
	

	close(driver);

	return 0;
}

	
/*
 * Open a misc device without having a /dev/ entry
 */
static int open_misc_device(int minor)
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
static int get_misc_minor()
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


/*
 * Convert string with hex value to integer
 */
static int hexatoi(char *s)
{
	int i;
	sscanf(s, "%x", &i);
	return i;
}


	
int main(int argc, char* argv[])
{
	int device;
	int misc_minor;


	if(argc < 5)
	{
		fprintf(stderr, "Usage: %s pci_vendor pci_device windowsdriver.sys windowsdruver.inf \n", argv[0]);
		return 1;
	}

	misc_minor = get_misc_minor();

	if(misc_minor == -1)
	{
		fprintf(stderr, "Cannot find minor for kernel module. Module loaded?\n");
		return 1;
	}
	
	device = open_misc_device(misc_minor);
	if(device == -1)
	{
		perror("Unable to open kernel driver");
		return 1;
	}
	
	load(hexatoi(argv[1]), hexatoi(argv[2]), argv[3], argv[4], device);

	close(device);
	return 0;
}

