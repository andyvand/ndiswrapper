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

#include <linux/ioctl.h>

#include "../driver/loader.h"

#define PROG_NAME "loadndisdriver"

#define SETTING_LEN (MAX_NDIS_SETTING_NAME_LEN+MAX_NDIS_SETTING_VALUE_LEN + 2)

static const char *confdir = "/etc/ndiswrapper";
static const char *ioctl_file = "/dev/ndiswrapper";
static int debug;

#ifndef NDISWRAPPER_VERSION
#error Compile this file with 'make' in the 'utils' \
	directory only
#endif

#define error(fmt, ...) do {					\
		syslog(LOG_KERN | LOG_ERR, "%s: %s(%d): " fmt "\n",	\
		       PROG_NAME, __FUNCTION__, __LINE__ , ## __VA_ARGS__); \
	} while (0)
#define info(fmt, ...) do {						\
		syslog(LOG_KERN | LOG_INFO, "%s: %s(%d): " fmt "\n",	\
		       PROG_NAME, __FUNCTION__, __LINE__ , ## __VA_ARGS__); \
	} while (0)

#define dbg(fmt, ...) do { if (debug)					\
		syslog(LOG_KERN | LOG_DEBUG, "%s: %s(%d): " fmt "\n", \
		       PROG_NAME, __FUNCTION__, __LINE__ , ## __VA_ARGS__); \
	} while (0)

/* read system file (either .sys or .bin) */
static int read_file(char *filename, struct load_driver_file *driver_file)
{
	int fd;
	size_t size;
	void * image = NULL;
	struct stat statbuf;

	char *file_basename = basename(filename);

	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		error("unable to open file: %s", strerror(errno));
		return -EINVAL;
	}

	if (fstat(fd, &statbuf)) {
		error("incorrect driver file '%s'", filename);
		close(fd);
		return -EINVAL;
	}
	size = statbuf.st_size;

	image = mmap(0, size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (image == MAP_FAILED) {
		error("unable to mmap driver: %s", strerror(errno));
		close(fd);
		return -EINVAL;
	}

	strncpy(driver_file->name, file_basename, sizeof(driver_file->name));
	driver_file->name[sizeof(driver_file->name)-1] = 0;
	driver_file->size = size;
	driver_file->data = image;
	return 0;
}

/* split setting into name and value pair */
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
	    (end = strchr(s, '\n')) == NULL) {
		error("invalid setting: %s", setting_line);
		return -EINVAL;
	}
	for (i = 0; s != val && i < MAX_NDIS_SETTING_NAME_LEN; s++, i++)
		setting_name[i] = *s;
	setting_name[i] = 0;
	if (*s != '|') {
		error("invalid setting: %s", setting_line);
		return -EINVAL;
	}

	for (i = 0, s++; s != end && i < MAX_NDIS_SETTING_VALUE_LEN ; s++, i++)
		setting_val[i] = *s;
	setting_val[i] = 0;
	if (*s != '\n') {
		error("invalid setting: %s", setting_line);
		return -EINVAL;
	}
	dbg("Found setting: name=%s, val=\"%s\"", setting_name, setting_val);

	// setting_val can be empty, but not value
	if (strlen(setting_name) == 0) {
		error("invalid setting: \"%s\"", setting_line);
		return -EINVAL;
	}

	return 1;
}

/* read .conf file and store info in device */
static int read_conf_file(char *conf_file_name, struct load_device *device)
{
	char setting_line[SETTING_LEN];
	struct stat statbuf;
	FILE *config;
	char setting_name[MAX_NDIS_SETTING_NAME_LEN];
	char setting_value[MAX_NDIS_SETTING_VALUE_LEN];
	int ret, nr_settings;
	char *file_name, *s;

	if (lstat(conf_file_name, &statbuf)) {
		error("unable to open config file: %s", strerror(errno));
		goto err;
	}

	if (S_ISLNK(statbuf.st_mode))
		device->fuzzy = 1;
	else
		device->fuzzy = 0;

	if ((config = fopen(conf_file_name, "r")) == NULL) {
		error("unable to open config file: %s", strerror(errno));
		goto err;
	}

	file_name = strdup(conf_file_name);
	s = basename(file_name);
	/* remove ".conf" */
	s[strlen(s)-5] = 0;

	if (strlen(s) == 9) {
		sscanf(s, "%04x:%04x", &device->vendor, &device->device);
		device->pci_subdevice = -1;
		device->pci_subvendor = -1;
	} else if (strlen(s) == 19) {
		sscanf(s, "%04x:%04x:%04x:%04x", &device->vendor,
		       &device->device, &device->pci_subvendor,
		       &device->pci_subdevice);
	} else
		goto err;

	free(file_name);

	device->bustype = -1;
	nr_settings = 0;

	while (fgets(setting_line, SETTING_LEN-1, config)) {
		struct load_device_setting *setting;

		setting_line[SETTING_LEN-1] = 0;
		ret = parse_setting_line(setting_line, setting_name,
					 setting_value);
		if (ret == 0)
			continue;
		if (ret < 0)
			goto err;

		if (strcmp(setting_name, "BusType") == 0) {
			device->bustype = strtol(setting_value, NULL, 10);
			if (device->bustype != 0 && device->bustype != 5) {
				error("invalid bustype: %d", device->bustype);
				goto err;
			}
		} 
		setting = &device->settings[nr_settings];
		strncpy(setting->name, setting_name,
			MAX_NDIS_SETTING_NAME_LEN);
		strncpy(setting->value, setting_value,
			MAX_NDIS_SETTING_VALUE_LEN);

		nr_settings++;
		if (nr_settings >= MAX_NDIS_SETTINGS) {
			error("too many settings");
			goto err;
		}
	}

	fclose(config);

	if (device->bustype == -1) {
		error("coudn't find device type in settings");
		goto err;
	}

	device->nr_settings = nr_settings;
	return 0;
err:
	device->nr_settings = 0;
	return -EINVAL;
}

/*
 * open a windows driver and pass it to the kernel module.
 * returns 0: on success, -1 on error
 */
static int load_driver(int ioctl_device, DIR *dir, char *driver_name)
{
	int i;
	struct dirent *dirent;
	struct load_driver *driver;
	int nr_sys_files, nr_devices, nr_bin_files;

	if (!dir || !driver_name) {
		error("invalid driver");
		return -1;
	}

	if ((driver = malloc(sizeof(*driver))) == NULL) {
		error("couldn't allocate memory for driver %s", driver_name);
		return -1;
	}
	memset(driver, 0, sizeof(*driver));
	strncpy(driver->name, driver_name, MAX_DRIVER_NAME_LEN);

	nr_sys_files = 0;
	nr_devices = 0;
	nr_sys_files = 0;
	nr_bin_files = 0;

	dbg("loading driver %s", driver_name);
	while ((dirent = readdir(dir))) {
		int len;

		if (strcmp(dirent->d_name, ".") == 0 ||
		    strcmp(dirent->d_name, "..") == 0)
			continue;

		len = strlen(dirent->d_name);
		if (len > 4 &&
		     strcmp(&dirent->d_name[len-4], ".inf") == 0)
			continue;

		if (len > 4 && strcmp(&dirent->d_name[len-4], ".sys") == 0) {
			if (read_file(dirent->d_name,
				      &driver->sys_files[nr_sys_files])) {
				error("couldn't load .sys file %s",
				      dirent->d_name);
				goto err;
			} else
				nr_sys_files++;
		} else if (len > 5 &&
			   strcmp(&dirent->d_name[len-5], ".conf") == 0) {
			if (read_conf_file(dirent->d_name,
					   &driver->devices[nr_devices])) {
				error("couldn't load .conf file %s",
				      dirent->d_name);
				goto err;
			} else
				nr_devices++;
		} else if (len > 4 &&
			   strcmp(&dirent->d_name[len-4], ".bin") == 0) {
			if (read_file(dirent->d_name,
				      &driver->bin_files[nr_bin_files])) {
				error("coudln't load .bin file %s",
				      dirent->d_name);
				goto err;
			} else
				nr_bin_files++;
		} else
			error("file %s is ignored", dirent->d_name);

		if (nr_sys_files == MAX_PE_IMAGES) {
			error("too many .sys files for driver %s",
			      driver_name);
			goto err;
		}
		if (nr_devices == MAX_NDIS_DEVICES) {
			error("too many .conf files for driver %s",
			      driver_name);
			goto err;
		}
		if (nr_bin_files == MAX_NDIS_BIN_FILES) {
			error("too many .bin files for driver %s",
			      driver_name);
			goto err;
		}
	}

	if (nr_sys_files == 0 || nr_devices == 0) {
		error("coudln't find valid drivers files for driver %s",
		      driver_name);
		goto err;
	}
	driver->nr_sys_files = nr_sys_files;
	driver->nr_devices = nr_devices;
	driver->nr_bin_files = nr_bin_files;

	if (ioctl(ioctl_device, NDIS_ADD_DRIVER, driver))
		goto err;

	dbg("driver %s loaded", driver_name);
	free(driver);
	return 0;

err:
	for (i = 0; i < nr_sys_files; i++)
		free(driver->sys_files[i].data);
	for (i = 0; i < nr_bin_files; i++)
		free(driver->bin_files[i].data);
	error("couldn't load driver %s", driver_name);
	free(driver);
	return -1;
}

/*
 * load all installed drivers
 * returns: number of drivers loadeed successfully
 */
static int load_all_drivers(int ioctl_device)
{
	struct stat statbuf;
	struct dirent  *dirent;
	DIR *dir, *driver;
	int loaded;

	if (chdir(confdir)) {
		error("directory %s is not valid: %s",
		      confdir, strerror(errno));
		return 0;
	}
	if ((dir = opendir(confdir)) == NULL) {
		error("directory %s is not valid: %s",
		      confdir, strerror(errno));
		return 0;
	}

	loaded = 0;
	while((dirent = readdir(dir))) {
		if (strcmp(dirent->d_name, ".") == 0 ||
		    strcmp(dirent->d_name, "..") == 0 ||
		    strcmp(dirent->d_name, "modules.ndiswrapper") == 0)
			continue;

		if (stat(dirent->d_name, &statbuf) ||
		    (!S_ISDIR(statbuf.st_mode)) ||
		    ((driver = opendir(dirent->d_name)) == NULL)) {
			error("directory %s is not valid: %s",
			      dirent->d_name, strerror(errno));
			continue;
		}
		if (chdir(dirent->d_name)) {
			error("directory %s is not valid: %s",
			      dirent->d_name, strerror(errno));
			closedir(driver);
			continue;
		}
		if (!load_driver(ioctl_device, driver, dirent->d_name))
			loaded++;
		chdir("..");
		closedir(driver);
	}
	closedir(dir);
	return loaded;
}

/*
  * we need a device to use ioctl to communicate with ndiswrapper module
  * we create a device in /dev instead of /tmp as some distributions don't
  * allow creation of devices in /tmp
  */
static int get_ioctl_device()
{
	int fd, minor_dev;
	char line[64];
	FILE *proc_misc;

	/* get minor device number used by ndiswrapper driver */
	proc_misc = fopen("/proc/misc", "r");
	if (!proc_misc)
		return -1;
	minor_dev = -1;
	while (fgets(line, sizeof(line), proc_misc)) {
		if (strstr(line, "ndiswrapper")) {
			long i = strtol(line, 0, 10);
			if (i != LONG_MAX && i != LONG_MIN) {
				minor_dev = i;
				break;
			}
		}
	}
	fclose(proc_misc);

	if (minor_dev == -1) {
		error("couldn't find ndiswrapper in /proc/misc; "
		      "is ndiswrapper module loaded?");
		return -1;
	}

	unlink(ioctl_file);
	if (mknod(ioctl_file, S_IFCHR | 0600, 10 << 8 | minor_dev) == -1) {
		error("couldn't create file %s: %s",
		      ioctl_file, strerror(errno));
		return -1;
	}

	fd = open(ioctl_file, O_RDONLY);
	unlink(ioctl_file);

	if (fd == -1) {
		error("couldn't open file %s: %s",
		      ioctl_file, strerror(errno));
		return -1;
	}
	return fd;
}

int main(int argc, char *argv[0])
{
	int i, ioctl_device, res;
	FILE *taint;

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
	} else
		debug = i;

	ioctl_device = get_ioctl_device();
	if (ioctl_device == -1) {
		error("unable to open ioctl device %s", ioctl_file);
		res = 5;
		goto out;
	}

	/* taint kernel */
	taint = fopen("/proc/sys/kernel/tainted", "w");
	if (taint) {
		fputs("1\n", taint);
		fclose(taint);
	}

	if (strcmp(argv[2], NDISWRAPPER_VERSION)) {
		error("version %s doesn't match driver version %s",
		      NDISWRAPPER_VERSION, argv[2]);
		res = 6;
		goto out;
	}

	if (strcmp(argv[3], "-a") == 0) {
		if (load_all_drivers(ioctl_device) > 0)
			res = 0;
		else {
			error("no useable drivers found, aborting");
			res = 7;
		}
	} else {
		DIR *driver_dir;
		if (chdir(confdir)) {
			error("directory %s is not valid: %s",
			      confdir, strerror(errno));
			res = 8;
			goto out;
		}
		if ((driver_dir = opendir(argv[3])) == NULL) {
			error("couldn't open driver directory %s: %s",
			      argv[3], strerror(errno));
			res = 9;
			goto out;
		} else {
			if (chdir(argv[3])) {
				error("directory %s is not valid: %s",
				      argv[3], strerror(errno));
				res = 10;
				goto out;
			}
			res = load_driver(ioctl_device, driver_dir,
					  argv[3]);
			closedir(driver_dir);
		}
	}
out:
	if (ioctl_device != -1)
		close(ioctl_device);
	closelog();
	return res;
}
