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
#include <syslog.h>
#include <stdlib.h>

#include "../driver/wrapper.h"

#define PROG_NAME "loadndisdriver"

#define SETTING_LEN 1024
#define NAME_LEN 200
#define TYPE_LEN 200
#define VAL_LEN 200

void read_conf(FILE *input);

static const char *confdir = "/etc/ndiswrapper";

static int debug;

#ifndef NDISWRAPPER_VERSION
#error Compile this file with 'make' in the 'utils' \
	directory only
#endif

#define error(fmt, args...) do {					\
		syslog(LOG_KERN | LOG_ERR, "%s: %s(%d): " fmt "\n",	\
		       PROG_NAME, __FUNCTION__, __LINE__, ## args);	\
	} while (0)
#define info(fmt, args...) do {						\
		syslog(LOG_KERN | LOG_INFO, "%s: %s(%d): " fmt "\n",	\
		       PROG_NAME, __FUNCTION__, __LINE__, ## args);	\
	} while (0)

#define dbg(fmt, args...) do { if (debug)				\
			syslog(LOG_KERN | LOG_DEBUG, "%s: %s(%d): " fmt "\n", \
			       PROG_NAME, __FUNCTION__, __LINE__, ## args); \
	} while (0)

static size_t get_filesize(int fd)
{
	struct stat statbuf;
	if (!fstat(fd, &statbuf))
		return statbuf.st_size;
	return 0;
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

static int read_file(int device, char *filename, struct put_file *put_file)
{
	int fd;
	size_t size;
	void * image = NULL;

	char *file_basename = basename(filename);

	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		error("unable to open file: %s", strerror(errno));
		return -EINVAL;
	}
	if ((size = get_filesize(fd)) == 0) {
		error("incorrect driver file '%s'", filename);
		close(fd);
		return -EINVAL;
	}
	image = mmap(0, size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (image == MAP_FAILED) {
		error("unable to mmap driver: %s", strerror(errno));
		close(fd);
		return -EINVAL;
	}

	strncpy(put_file->name, file_basename, sizeof(put_file->name));
	put_file->name[sizeof(put_file->name)-1] = 0;
	put_file->size = size;
	put_file->data = image;
	return 0;
}


static int confname_to_put_device(const char *name_orig,
				  struct put_device *put_device)
{
	char *s;
	char *name = strdup(name_orig);

	s = basename(name);
	s[strlen(s)-5] = 0;

	if(strlen(s) == 9)
	{
		sscanf(s, "%04x:%04x", &put_device->vendor,
		       &put_device->device);
		put_device->pci_subdevice = -1;
		put_device->pci_subvendor = -1;
	}
	else if(strlen(s) == 19)
	{
		sscanf(s, "%04x:%04x:%04x:%04x", &put_device->vendor,
		       &put_device->device, &put_device->pci_subvendor,
		       &put_device->pci_subdevice);
	}

	free(name);
	return 0;
}


static int parse_setting_line(const char *setting_line, char *setting_name,
			      char *setting_val)
{
	const char *s;
	char *val, *end;
	int i;

	// We try to be really paranoid parsing settings
	for (s = setting_line; isspace(*s); s++)
		;

	// ignore comments and blank lines
	if (*s == '#' || *s == ';' || *s == '\0')
		return 0;
	if ((val = strchr(s, '|')) == NULL ||
	     (end = strchr(s, '\n')) == NULL)
	{
		error("invalid setting: %s", setting_line);
		return -EINVAL;
	}
	for (i = 0; s != val && i < NAME_LEN; s++, i++)
		setting_name[i] = *s;
	setting_name[i] = 0;
	if (*s != '|')
	{
		error("invalid setting: %s", setting_line);
		return -EINVAL;
	}

	for (i = 0, s++; s != end && i < VAL_LEN ; s++, i++)
		setting_val[i] = *s;
	setting_val[i] = 0;
	if (*s != '\n')
	{
		error("invalid setting: %s", setting_line);
		return -EINVAL;
	}
//	info("Found setting: name=%s, val=\"%s\"\n",
//	       setting_name, setting_val);

	// setting_val can be empty, but not value
	if (strlen(setting_name) == 0)
	{
		error("invalid setting: \"%s\"", setting_line);
		return -EINVAL;
	}

	return 1;
}


static int put_device(int device, char *conf_file_name)
{

	struct put_device put_device;
	char setting_line[SETTING_LEN];
	struct stat statbuf;
	FILE *config;
	char setting_name[NAME_LEN], setting_val[VAL_LEN];
	int ret;

	if(lstat(conf_file_name, &statbuf))
	{
		error("unable to open config file: %s", strerror(errno));
		return -EINVAL;
	}

	put_device.fuzzy = 0;
	if(S_ISLNK(statbuf.st_mode))
		put_device.fuzzy = 1;

	if ((config = fopen(conf_file_name, "r")) == NULL)
	{
		error("unable to open config file: %s", strerror(errno));
		return -EINVAL;
	}

	confname_to_put_device(conf_file_name, &put_device);

	put_device.bustype = -1;
	while (fgets(setting_line, SETTING_LEN-1, config))
	{
		setting_line[SETTING_LEN-1] = 0;
		ret = parse_setting_line(setting_line, setting_name,
					 setting_val);
		if (ret == 0)
			continue;
		if (ret < 0)
			return -EINVAL;

		if (strcmp(setting_name, "BusType") == 0) {
			put_device.bustype = strtol(setting_val, NULL, 10);
			if (put_device.bustype != 0 &&
			    put_device.bustype != 5) {
				error("invalid bustype: %s", strerror(errno));
				return -EINVAL;
			}
			if (ioctl(device, NDIS_PUTDEVICE, &put_device)) {
				error("unable to put device: %s",
				      strerror(errno));
				return -EINVAL;
			}
			rewind(config);
			break;
		}
	}

	if (put_device.bustype == -1)
		return -EINVAL;

	while (fgets(setting_line, SETTING_LEN-1, config))
	{
		struct put_setting setting;

		setting_line[SETTING_LEN-1] = 0;
		ret = parse_setting_line(setting_line, setting_name,
					 setting_val);
		if (ret == 0)
			continue;
		if (ret < 0)
			return -EINVAL;

		setting.name_len = strlen(setting_name);
		setting.val_str_len = strlen(setting_val);
		setting.name = setting_name;
		setting.value = setting_val;

		if (ioctl(device, NDIS_PUTSETTING, &setting))
		{
			error("Error adding setting: %s", setting_name);
			return -EINVAL;
		}
	}
	fclose(config);

	return 0;
}

/*
 * Open a windows driver and pass it to the kernel module.
 */
static int load_driver(int device, DIR *dir, char *driver_name)
{
	int i, err;
	struct dirent *dirent;
	struct driver_files driver_files;

	if (!dir)
		return -1;

	/* Locate all the .sys first */
	for (i = 0; (dirent = readdir(dir)) && i < MAX_PE_IMAGES; ) {
		int len;

		if (strcmp(dirent->d_name, ".") == 0 ||
		    strcmp(dirent->d_name, "..") == 0)
			continue;

		len = strlen(dirent->d_name);
		if (len > 4 && strcmp(&dirent->d_name[len-4], ".sys") == 0) {
			if ((err = read_file(device, dirent->d_name,
					     &driver_files.file[i])) != 0) {
				return -1;
			}
			i++;
		}
	}

	if (i == 0) {
		error("%s doesn't have valid .sys files", confdir);
		return -1;
	}
		
	driver_files.count = i;
	strncpy(driver_files.name, driver_name, DRIVERNAME_MAX);
	dbg("number of files = %d", i);
	if ((err = ioctl(device, NDIS_PUTDRIVER, &driver_files))) {
		error("unable to load system files: %s", strerror(errno));
		return -EINVAL;
	}
	rewinddir(dir);

	/* Now add all .conf and other files */
	while ((dirent = readdir(dir))) {
		int len;

		if (strcmp(dirent->d_name, ".") == 0 ||
		    strcmp(dirent->d_name, "..") == 0)
			continue;

		len = strlen(dirent->d_name);

		if (len > 4 &&
		    (strcmp(&dirent->d_name[len-4], ".sys") == 0 ||
		     strcmp(&dirent->d_name[len-4], ".inf") == 0))
			continue;

		if (len > 5 &&
		    strcmp(&dirent->d_name[len-5], ".conf") == 0) {
			put_device(device, dirent->d_name);
		} else if (len > 4 &&
			   (strcmp(&dirent->d_name[len-4], ".bin") == 0)) {
			struct put_file fw_file;
			/* put only .bin files; are there other extensions
			   used for firmware files? */

			read_file(device, dirent->d_name, &fw_file);
			if (ioctl(device, NDIS_PUTFILE, &fw_file)) {
				error("unable to put file: %s",
				      strerror(errno));
				return -EINVAL;
			}
		} else
			dbg("file %s is ignored", dirent->d_name);
	}

	if (ioctl(device, NDIS_STARTDRIVER, 0)) {
		error("unable to start driver: %s", strerror(errno));
		return -EINVAL;
	}

	return 0;
}

/*
 * Load all installed drivers
 */
static int load_all_drivers(int device)
{
	struct stat statbuf;
	struct dirent  *dirent;
	DIR *dir, *driver;
	int loaded;

	if ((dir = opendir(confdir)) == NULL) {
		error("Unable to open configuration directory %s", confdir);
		return -1;
	}

	loaded = 0;
	chdir(confdir);
	while((dirent = readdir(dir))) {
		if (strcmp(dirent->d_name, ".") == 0 ||
		    strcmp(dirent->d_name, "..") == 0 ||
		    strcmp(dirent->d_name, "modules.ndiswrapper") == 0)
			continue;

		if (stat(dirent->d_name, &statbuf) ||
		    (!S_ISDIR(statbuf.st_mode)) ||
		    ((driver = opendir(dirent->d_name)) == NULL)) {
			error("Unable to open driver directory %s",
			      dirent->d_name);
			continue;
		}
		chdir(dirent->d_name);
		if (load_driver(device, driver, dirent->d_name))
			info("couldn't load driver '%s'", dirent->d_name);
		else
			loaded++;
		chdir("..");
		closedir(driver);
	}
	closedir(dir);
	return loaded;
}


/*
 * Open a misc device without having a /dev/ entry
 */
static int open_misc_device(int minor)
{
	char *path = "/dev/ndiswrapper";
	int fd;

	unlink(path);
	if (mknod(path, S_IFCHR | 0600, 10 << 8 | minor) == -1)
		return -1;

	fd = open(path, O_RDONLY);
	unlink(path);

	if (fd == -1)
		return -1;
	return fd;
}

/*
 * Parse /proc/misc to get the minor of out kernel driver
 */
static int get_misc_minor()
{
	char line[64];
	FILE *misc = fopen("/proc/misc", "r");
	int minor = -1;

	if(!misc)
		return -1;
	while(fgets(line, sizeof(line), misc))
	{
		if(strstr(line, "ndiswrapper"))
		{
			long i = strtol(line, 0, 10);
			if (i != LONG_MAX && i != LONG_MIN)
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
	int i, device, misc_minor, res;

	device = -1;
	debug = 1;

	openlog(PROG_NAME, LOG_PERROR | LOG_CONS, LOG_KERN | LOG_DEBUG);

	dbg("version %s started", NDISWRAPPER_VERSION);

	if (argc != 4) {
		error("Usage: %s <debug> <version> [-a] [driver]", argv[0]);
		res = 1;
		goto out;
	}

	i = -1;
	i = atoi(argv[1]);
	if (i < 0) {
		error("invalid debug value %d", i);
		res = 2;
		goto out;
	}
	else
		debug = i;

	misc_minor = get_misc_minor();
	if (misc_minor == -1) {
		error("%s", "cannot find minor for kernel module.");
		res = 4;
		goto out;
	}

	device = open_misc_device(misc_minor);
	if (device == -1) {
		error("unable to open misc device in /dev (%d)", errno);
		res = 5;
		goto out;
	}

	dotaint();

	if (strcmp(argv[2], NDISWRAPPER_VERSION)) {
		error("version %s doesn't match driver version %s",
				NDISWRAPPER_VERSION, argv[2]);
		res = 6;
		goto out;
	}

	if (strcmp(argv[3], "-a") == 0) {
		if (load_all_drivers(device) > 0)
			res = 0;
		else {
			error("%s", "no useable drivers found, aborting");
			res = 7;
			goto out;
		}
	} else {
		DIR *driver_dir;
		char driver_name[MAXNAMLEN];

		strcpy(driver_name, confdir);
		strcat(driver_name, "/");
		if (strlen(driver_name) + strlen(argv[3]) >= MAXNAMLEN) {
			error("Invalid directory %s", argv[3]);
			res = 7;
			goto out;
		}

		strcat(driver_name, argv[3]);
		if ((driver_dir = opendir(driver_name)) == NULL) {
			error("Unable to open driver directory %s",
			      driver_name);
			res = 8;
			goto out;
		} else {
			res = load_driver(device, driver_dir, driver_name);
			closedir(driver_dir);
		}
	}
out:
	if (device != -1)
		close(device);
	closelog();
	return res;
}
