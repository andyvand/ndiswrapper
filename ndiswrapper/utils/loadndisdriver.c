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
#include <dirent.h>

#include "../driver/wrapper.h"

#define SETTING_LEN 1024
#define NAME_LEN 200
#define TYPE_LEN 200
#define VAL_LEN 200

void read_conf(FILE *input);

const char *confdir = "/etc/ndiswrapper";

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

static int put_file(int device, char *filename, int ioctl_nr)
{
	int fd, size;
	struct put_file put_file;
	void * image = NULL;

	char *file_basename = basename(strdup(filename));

	fd = open(filename, O_RDONLY);
	if(fd == -1)
	{
		perror("Unable to open file");
		return -EINVAL;
	}
	size = get_filesize(fd);
	image = mmap(0, size, PROT_READ, MAP_PRIVATE,
		     fd, 0);
	if((int)image == -1)
	{
		perror("Unable to mmap driver");
		close(fd);
		return -EINVAL;
	}

	strncpy(put_file.name, file_basename, sizeof(put_file.name));
	put_file.name[sizeof(put_file.name)-1] = 0;
	put_file.size = size;
	if (!image)
	{
		printf("Unable to locate file.\n");
		return -EINVAL;
	}

	put_file.data = image;
	if (ioctl(device, ioctl_nr, &put_file))
	{
		perror("Unable to put file (check dmesg for more info)");
		return -EINVAL;
	}
	return 0;
}


static int confname_to_put_device(const char *name_orig, struct put_device *put_device)
{
	char *s;
	char *name = strdup(name_orig);
		
	s = basename(name);
	s[strlen(s)-5] = 0;

	if(strlen(s) == 9)
	{
		sscanf(s, "%04x:%04x", &put_device->pci_vendor, &put_device->pci_device);
		put_device->pci_subdevice = -1;
		put_device->pci_subvendor = -1;
	}
	else if(strlen(s) == 19) 
	{
		sscanf(s, "%04x:%04x:%04x:%04x", &put_device->pci_vendor, &put_device->pci_device, &put_device->pci_subvendor, &put_device->pci_subdevice);
	}
	
	free(name);
	return 0;
}


static int put_pci_device(int device, char *conf_file_name)
{

	struct put_device put_device;
	char setting_line[SETTING_LEN];
	struct stat statbuf;
	
	if(lstat(conf_file_name, &statbuf))
	{
		perror("unable to open config file");
		return -EINVAL;
	}

	put_device.fuzzy = 0;
	if(S_ISLNK(statbuf.st_mode))
		put_device.fuzzy = 1;

	FILE *config;
	if ((config = fopen(conf_file_name, "r")) == NULL)
	{
		perror("unable to open config file");
		return -EINVAL;
	}

	confname_to_put_device(conf_file_name, &put_device);
	printf("%04x:%04x:%04x:%04x\n", put_device.pci_vendor, put_device.pci_device, put_device.pci_subvendor, put_device.pci_subdevice);

	if (ioctl(device, NDIS_PUTDEVICE, &put_device))
	{
		perror("Unable to put device (check dmesg for more info)");
		return -EINVAL;
	}

	while (fgets(setting_line, SETTING_LEN-1, config))
	{
		char *val, *s, *end;
		char setting_name[NAME_LEN], setting_val[VAL_LEN];
		int i;

		setting_line[SETTING_LEN-1] = 0;

		// We try to be really paranoid parsing settings
		for (s = setting_line; isspace(*s); s++)
			;
		// ignore comments and blank lines
		if (*s == '#' || *s == ';' || *s == '\0')
			continue;
		if ((val = strchr(s, '|')) == NULL ||
		     (end = strchr(s, '\n')) == NULL)
		{
			printf("invalid setting1: %s\n", setting_line);
			goto unload;
		}
		for (i = 0; s != val && i < NAME_LEN; s++, i++)
			setting_name[i] = *s;
		setting_name[i] = 0;
		if (*s != '|')
		{
			printf("invalid setting2: %s\n", setting_line);
			goto unload;
		}

		for (i = 0, s++; s != end && i < VAL_LEN ; s++, i++)
			setting_val[i] = *s;
		setting_val[i] = 0;
		if (*s != '\n')
		{
			printf("invalid setting3: %s\n", setting_line);
			goto unload;
		}
		printf("Found setting: name=%s, val=\"%s\"\n",
		       setting_name, setting_val);

		// setting_val can be empty, but not value
		if (strlen(setting_name) == 0)
		{
			printf("invalid setting: \"%s\"\n", setting_line);
			goto unload;
		}

		if (strcmp(setting_name, "ndis_provider") == 0)
			printf("Provider: %s\n", setting_val);
		else if (strcmp(setting_name, "ndis_version") == 0)
			printf("Version: %s\n", setting_val);
		else {
			struct put_setting setting;
			
			setting.name_len = strlen(setting_name);
			setting.val_str_len = strlen(setting_val);
			setting.name = setting_name;
			setting.value = setting_val;

			if (ioctl(device, NDIS_PUTSETTING, &setting))
			{
				printf("Error adding setting: %s\n", setting_name);
				goto unload;
			}
		}
	}
	fclose(config);

	printf("Calling startdriver ioctl\n");
	
	return 0;
unload:
	return -EINVAL;
}

/*
 * Make sure the ndiswrapper module is loaded.
 */
static void loadmod(void)
{
	if(!system("/sbin/modprobe ndiswrapper 2>/dev/null"))
		return;
	if(!system("/usr/sbin/modprobe ndiswrapper 2>/dev/nul"))
		return;
	if(!system("modprobe ndiswrapper 2>/dev/nul"))
		return;
}


/*
 * Open a windows driver and pass it to the kernel module.
 */
static int load(int device, char *confdir)
{
	int err;
	struct dirent *dirent;
	
	if(chdir(confdir))
	{
		fprintf(stderr, "Unable to open config dir %s\n", confdir);
		return -1;
	}
	
	DIR *dir = opendir(".");
	if(!dir)
	{
		fprintf(stderr, "Unable to open config dir %s\n", confdir);
		chdir("..");
		return -1;
	}
	
	/* Locate the .sys first */
	while((dirent = readdir(dir)))
	{
		int len;
		len = strlen(dirent->d_name);
		if(len > 4 && strcmp(&dirent->d_name[len-4], ".sys") == 0)
		{
			if((err = put_file(device, dirent->d_name, NDIS_PUTDRIVER)) != 0)
			{
				chdir("..");
				return err;
			}
			break;
		}
	}
	rewinddir(dir);	

	/* Now add all .conf and other files */
	while((dirent = readdir(dir)))
	{
		int len;
		len = strlen(dirent->d_name);
		if(len > 5 && strcmp(&dirent->d_name[len-5], ".conf") == 0)
		{
			put_pci_device(device, dirent->d_name);
		}
		else
		{
			if(strcmp(dirent->d_name, ".") == 0)
				continue;
			if(strcmp(dirent->d_name, "..") == 0)
				continue;
			if(len > 4 && strcmp(&dirent->d_name[len-4], ".sys") == 0)
				continue;
			if(len > 4 && strcmp(&dirent->d_name[len-4], ".inf") == 0)
				continue;
			put_file(device, dirent->d_name, NDIS_PUTFILE);
		}
	}
	closedir(dir);
	if(ioctl(device, NDIS_STARTDRIVER, 0))
	{
		perror("Unable to start driver (check dmesg for more info)");
		chdir("..");
		return -1;
	}
	chdir("..");
	return 0;
}

/*
 * Load all installed drivers
 */
static int loadall(int device)
{
	struct stat statbuf;
	struct dirent  *dirent;

	DIR *dir = opendir(".");

	while((dirent = readdir(dir)))
	{
		if(strcmp(dirent->d_name, ".") == 0)
			continue;
		if(strcmp(dirent->d_name, "..") == 0)
			continue;

		if(stat(dirent->d_name, &statbuf))
			continue;

		if(!S_ISDIR(statbuf.st_mode))
			continue;

		load(device, dirent->d_name);
	}
	closedir(dir);	
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


int main(int argc, char *argv[0])
{
	int device, misc_minor, res;

	if(argc != 2)
	{
		printf("Usage: %s [-a] [driver]\n", argv[0]);
		return -EINVAL;
	}

	if((res = chdir(confdir)))
	{
		fprintf(stderr, "%s does not exist\n", confdir);
		return res;
	}
	
	loadmod();
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

	dotaint();
	if(strcmp(argv[1], "-a") == 0)
		res = loadall(device);
	else
		res = load(device, argv[1]); 	

	if (!res)
	{
		printf("driver loaded successfully\n");
	}
	
	close(device);
	return res;
}
