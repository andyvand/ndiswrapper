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
#include <limits.h>

#include "../driver/wrapper.h"
#include "loadndisdriver.h"

/* prototype for function found in inf-parser */
extern void read_inf(FILE *input);

/* need to keep the driver as a global so the parser calls can use it */
static int device = -1, dumpinf = 0;

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
 * Taint the kernel
 */
static int dotaint(void)
{
	FILE *f = fopen("/proc/sys/kernel/tainted", "w");
	if(!f)
		return -1;
	fputs("1\n", f);
	fclose(f);
	return 0;
}


static char provider[80] = {0};
static char manufacturer[80] = {0};

void found_setting(char *name, char *value)
{
	if (strcmp(name, "Provider") == 0)
		strncpy(provider, value, 80);
	else if (strcmp(name, provider) == 0)
		strncpy(manufacturer, value, 80);
	else if (strcmp(name, "DriverVer") == 0)
		printf("Driver version: %s\n", value);
	else if (strcmp(name, "NetworkAddress") == 0)
		return;
	else if (dumpinf)
		printf("Setting found: %s = %s\n", name, value);
	else
	{
		struct put_setting setting;
		struct setting_payload payload;
	
		if (strcmp(name, "Locale") == 0)
			value = "0";

		payload.data = atoi(value);
		setting.type = 0;
		setting.name_len = strlen(name);
		setting.name = name;
		setting.payload = &payload;
		setting.payload_len = sizeof(payload);

		printf("Adding setting: %s\t= %s\n", name, value);
		if(ioctl(device, NDIS_PUTSETTING, &setting))
		{
			perror("Unable to put setting (check dmesg for more info)");
			exit(1);
		}
	}
}

unsigned int found_heading(char *name)
{
	int x, start = 0;
	for(x = 0; manufacturer[x] != '\0'; x++)
		if (manufacturer[x] == ',')
		{
			//	printf("%s == %s\n", name, manufacturer + start);

			if (strncmp(name, manufacturer + start, x - start) == 0)
				return FOUND_DEVICES;
			start = x + 1;
		}
	//	printf("%s == %s\n", name, manufacturer + start);
	if (strcmp(name, manufacturer + start) == 0)
		return FOUND_DEVICES;
	return IGNORE_SECTION;
}

void found_pci_id(unsigned short vendor, unsigned short device)
{
	if (dumpinf)
		printf("PCI ID: %4.4X:%4.4X\n", vendor, device);
}

/*
 * Read an inf-file and extract things needed. This is very primitive right now
 * so don't be suprised if some files are misinterpreted right now...
 */
static int loadsettings(char *inf_name)
{
	FILE *inf = fopen(inf_name, "r");
	if(!inf)
	{
		perror("Unable to load inf-file");
		return 1;
	}

	/* call the lex generated parser */
	printf("Parsing the inf file.\n");
	read_inf(inf);

	fclose(inf);
	return 0;
}

	
/*
 * Open a windows driver and pass it to the kernel module.
 */
static int load(int pci_vendor, int pci_device, char *driver_name, char *inf_name, int device)
{
	struct put_driver put_driver;
	int driver, size;
	char *driver_basename;
	void * image;

	driver = open(driver_name, O_RDONLY);
	if(driver == -1)
	{
		perror("Unable to open driver");
		return 1;
	}

	size = get_filesize(driver);
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

	dotaint();
	printf("Calling putdriver ioctl\n");
	if(ioctl(device, NDIS_PUTDRIVER, &put_driver))
	{
		perror("Unable to put driver (check dmesg for more info)");
		return 1;

	}

	if(!loadsettings(inf_name))
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
			if(i != LONG_MAX && i != LONG_MIN)
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
	if (sscanf(s, "%x", &i) != 1)
		return -1;
	return i;
}

int main(int argc, char* argv[])
{
	int x, vendorid = -1, deviceid = -1, retval = 1;
	char *driver = NULL, *information = NULL;

	for(x = 1; x < argc; x++)
		if (strcmp(argv[x], "-d") == 0 ||
			strcmp(argv[x], "--dump-info") == 0)
			dumpinf = 1;
		else if (strcasecmp(argv[x] + strlen(argv[x]) - 4, ".sys") == 0)
			driver = argv[x];
		else if (strcasecmp(argv[x] + strlen(argv[x]) - 4, ".inf") == 0)
			information = argv[x];
		else
		{
			int temp = hexatoi(argv[x]);
			if (temp != -1)
			{
				if (vendorid == -1)
					vendorid = temp;
				else if (deviceid == -1)
					deviceid = temp;
				else
				{
					fprintf(stderr, "Vendor and device ids already specified.  Useless number: %s", argv[x]);
					vendorid = -1;
					break;
				}
			}
		}

	if (dumpinf &&
		information != NULL)
		loadsettings(information);
	else if (vendorid == -1 ||
			 deviceid == -1 ||
			 driver == NULL ||
			 information == NULL)
		fprintf(stderr, "Usage: %s [OPTIONS] pci_vendor pci_device windowsdriver.sys windowsdriver.inf \n", argv[0]);
	else
	{
		int misc_minor = get_misc_minor();
		if(misc_minor == -1)
			fprintf(stderr, "Cannot find minor for kernel module. Module loaded?\n");
		else
		{
			device = open_misc_device(misc_minor);
			if(device == -1)
				perror("Unable to open kernel driver");
			else
			{
				load(vendorid, deviceid, driver, information, device);
				close(device);
				retval = 0;
			}
		}
	}
	return retval;
}
