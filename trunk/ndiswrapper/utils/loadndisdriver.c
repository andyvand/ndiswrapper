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
#include <ctype.h>

#include "../driver/wrapper.h"

#define SETTING_LEN 1024
#define NAME_LEN 200
#define TYPE_LEN 200
#define VAL_LEN 200

static char *def_config = "/etc/ndiswrapper/config";

void read_conf(FILE *input);

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

/*
 * Open a windows driver and pass it to the kernel module.
 */
static int load(int device, char *config_file_name)
{
	int driver, size;
	FILE *config;
	void * image = NULL;
	char setting_line[SETTING_LEN];

	if ((config = fopen(config_file_name, "r")) == NULL)
	{
		perror("unable to open config file");
		return -EINVAL;
	}

	while (fgets(setting_line, SETTING_LEN-1, config))
	{
		char *equals, *val, *s, *end;
		char setting_name[NAME_LEN],
			setting_type[TYPE_LEN], setting_val[VAL_LEN];
		int i;

		setting_line[SETTING_LEN-1] = 0;

		// We try to be really paranoid parsing settings
		for (s = setting_line; isspace(*s); s++)
			;
		// ignore comments and blank lines
		if (*s == '#' || *s == ';' || *s == '\0')
			continue;
		if ((equals = strchr(s, '=')) == NULL ||
		    (val = strchr(s, '|')) == NULL ||
		     (end = strchr(s, '\n')) == NULL)
		{
			printf("invalid setting: %s\n", setting_line);
			goto unload;
		}
		for (i = 0; s != equals && i < NAME_LEN; s++, i++)
			setting_name[i] = *s;
		setting_name[i] = 0;
		if (*s != '=')
		{
			printf("invalid setting: %s\n", setting_line);
			goto unload;
		}
		for (i = 0, s++; s != val && i < TYPE_LEN; s++, i++)
			setting_type[i] = *s;
		setting_type[i] = 0;
		if (*s != '|')
		{
			printf("invalid setting: %s\n", setting_line);
			goto unload;
		}
		for (i = 0, s++; s != end && i < VAL_LEN ; s++, i++)
			setting_val[i] = *s;
		setting_val[i] = 0;
		if (*s != '\n')
		{
			printf("invalid setting: %s\n", setting_line);
			goto unload;
		}
		printf("Found setting: name=%s, type=%s, val=\"%s\"\n",
		       setting_name, setting_type, setting_val);

		// setting_val can be empty, but not others
		if (strlen(setting_name) == 0 || strlen(setting_type) == 0)
		{
			printf("invalid setting: \"%s\"\n", setting_line);
			goto unload;
		}

		if (strcmp(setting_name, "ndis_driver") == 0)
		{
			driver = open(setting_val, O_RDONLY);
			if(driver == -1)
			{
				perror("Unable to open driver");
				return -EINVAL;
			}
			size = get_filesize(driver);
			image = mmap(0, size, PROT_READ, MAP_PRIVATE,
				     driver, 0);
			if((int)image == -1)
			{
				perror("Unable to mmap driver");
				fclose(config);
				close(driver);
				return -EINVAL;
			}
		}
		else if (strcmp(setting_name, "ndis_pci_id") == 0)
		{
			struct put_driver put_driver;
	
			strncpy(put_driver.name, "ndiswrapper",
				sizeof(put_driver.name));
			put_driver.name[sizeof(put_driver.name)-1] = 0;
			put_driver.pci_vendor = strtol(setting_type, NULL, 16);
			put_driver.pci_device = strtol(setting_val, NULL, 16);
			put_driver.size = size;
			if (!image)
			{
				printf("Unable to locate driver, config file corrupted?\n");
				return -EINVAL;
			}

			put_driver.data = image;
			printf("Calling putdriver ioctl\n");
			if (ioctl(device, NDIS_PUTDRIVER, &put_driver))
			{
				perror("Unable to put driver (check dmesg for more info)");
				return -EINVAL;
			}
		}
		else if (strcmp(setting_name, "ndis_provider") == 0)
			printf("Provider: %s\n", setting_val);
		else if (strcmp(setting_name, "ndis_version") == 0)
			printf("Version: %s\n", setting_val);
		else {
			struct put_setting setting;
			
			setting.name_len = strlen(setting_name);
			setting.val_str_len = strlen(setting_val);
			setting.name = setting_name;
			setting.val_str = setting_val;

			if (ioctl(device, NDIS_PUTSETTING, &setting))
			{
				printf("Error adding setting: %s\n", setting_name);
				goto unload;
			}
		}
	}
	fclose(config);
	close(driver);

	printf("Calling startdriver ioctl\n");
	
	if(ioctl(device, NDIS_STARTDRIVER, 0))
	{
		perror("Unable to start driver (check dmesg for more info)");
		goto unload;
	}

	return 0;
unload:
	ioctl(device, NDIS_CANCELLOAD, 0);
	printf("Driver loading is canceled\n");
	return -EINVAL;
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


int main(int argc, char *argv[0])
{
	int device, misc_minor, res;
	char conf_file_name[200];

	misc_minor = get_misc_minor();
	if(misc_minor == -1)
	{
		printf("%s: cannot find minor for kernel module. Module loaded?\n",
			   argv[0]);
		return -EINVAL;
	}
	
	device = open_misc_device(misc_minor);
	if(device == -1)
	{
		perror("Unable to open kernel driver");
		return -EINVAL;
	}

	if (argc > 1)
	{
		if (*argv[1] == '/') // assume it is full path
			strncpy(conf_file_name, argv[1], sizeof(conf_file_name));
		else
			snprintf(conf_file_name, sizeof(conf_file_name), "%s/%s",
					 "/etc/ndiswrapper", argv[1]);
	}
	else
		strncpy(conf_file_name, def_config, sizeof(conf_file_name));

	res = load(device, conf_file_name);
	if (!res)
	{
		printf("driver loaded successfully\n");
		dotaint();
	}
	close(device);

	return res;
}
