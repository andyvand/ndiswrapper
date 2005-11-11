/*
 *  Copyright (C) 2003-2005 Pontus Fuchs, Giridhar Pemmasani
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

#ifndef UTILS_VERSION
#error Compile this file with 'make' in the 'utils' \
	directory only
#endif

#define ERROR(fmt, ...) do {					\
		syslog(LOG_KERN | LOG_ERR, "%s: %s(%d): " fmt "\n",	\
		       PROG_NAME, __FUNCTION__, __LINE__ , ## __VA_ARGS__); \
	} while (0)
#define INFO(fmt, ...) do {						\
		syslog(LOG_KERN | LOG_INFO, "%s: %s(%d): " fmt "\n",	\
		       PROG_NAME, __FUNCTION__, __LINE__ , ## __VA_ARGS__); \
	} while (0)

#define DBG(fmt, ...) do { if (debug)					\
		syslog(LOG_KERN | LOG_DEBUG, "%s: %s(%d): " fmt "\n", \
		       PROG_NAME, __FUNCTION__, __LINE__ , ## __VA_ARGS__); \
	} while (0)

/* load .sys or .bin file */
static int load_file(char *filename, struct load_driver_file *driver_file)
{
	int fd;
	size_t size;
	void * image = NULL;
	struct stat statbuf;

	char *file_basename = basename(filename);

	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		ERROR("unable to open file: %s", strerror(errno));
		return -EINVAL;
	}

	if (fstat(fd, &statbuf)) {
		ERROR("incorrect driver file '%s'", filename);
		close(fd);
		return -EINVAL;
	}
	size = statbuf.st_size;

	image = mmap(0, size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (image == MAP_FAILED) {
		ERROR("unable to mmap driver: %s", strerror(errno));
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
		ERROR("invalid setting: %s", setting_line);
		return -EINVAL;
	}
	for (i = 0; s != val && i < MAX_NDIS_SETTING_NAME_LEN; s++, i++)
		setting_name[i] = *s;
	setting_name[i] = 0;
	if (*s != '|') {
		ERROR("invalid setting: %s", setting_line);
		return -EINVAL;
	}

	for (i = 0, s++; s != end && i < MAX_NDIS_SETTING_VALUE_LEN ; s++, i++)
		setting_val[i] = *s;
	setting_val[i] = 0;
	if (*s != '\n') {
		ERROR("invalid setting: %s", setting_line);
		return -EINVAL;
	}
	DBG("Found setting: name=%s, val=\"%s\"", setting_name, setting_val);

	// setting_val can be empty, but not name
	if (strlen(setting_name) == 0) {
		ERROR("invalid setting: \"%s\"", setting_line);
		return -EINVAL;
	}

	return 1;
}

/* read .conf file and store info in driver */
static int read_conf_file(char *conf_file_name, struct load_driver *driver)
{
	char setting_line[SETTING_LEN];
	struct stat statbuf;
	FILE *config;
	char setting_name[MAX_NDIS_SETTING_NAME_LEN];
	char setting_value[MAX_NDIS_SETTING_VALUE_LEN];
	int ret, nr_settings;
	int i, vendor, device, subvendor, subdevice, dev_bustype, conf_bustype;

	if (lstat(conf_file_name, &statbuf)) {
		ERROR("unable to open config file: %s", strerror(errno));
		return -EINVAL;
	}

	if (strlen(conf_file_name) == 16) {
		i = sscanf(conf_file_name, "%04X:%04X.%d.conf",
			   &vendor, &device, &dev_bustype);
		if (i != 3) {
			ERROR("unable to parse conf file name %s (%d)",
			      conf_file_name, i);
			return -EINVAL;
		}
	} else {
		i = sscanf(conf_file_name, "%04X:%04X:%04X:%04X.%d.conf",
			   &vendor, &device, &subvendor, &subdevice,
			   &dev_bustype);
		if (i != 5) {
			ERROR("unable to parse conf file name %s (%d)",
			      conf_file_name, i);
			return -EINVAL;
		}
	}

	nr_settings = 0;
	driver->nr_settings = 0;

	if ((config = fopen(conf_file_name, "r")) == NULL) {
		ERROR("unable to open config file: %s", strerror(errno));
		return -EINVAL;
	}
	while (fgets(setting_line, SETTING_LEN-1, config)) {
		struct load_device_setting *setting;

		setting_line[SETTING_LEN-1] = 0;
		ret = parse_setting_line(setting_line, setting_name,
					 setting_value);
		if (ret == 0)
			continue;
		if (ret < 0)
			return -EINVAL;

		if (strcmp(setting_name, "BusType") == 0) {
			conf_bustype = strtol(setting_value, NULL, 10);
			if (dev_bustype != conf_bustype) {
				ERROR("invalid bustype: %d(%d)",
				      dev_bustype, conf_bustype);
				return -EINVAL;
			}
		}
		setting = &driver->settings[nr_settings];
		strncpy(setting->name, setting_name,
			MAX_NDIS_SETTING_NAME_LEN);
		strncpy(setting->value, setting_value,
			MAX_NDIS_SETTING_VALUE_LEN);

		nr_settings++;
		if (nr_settings >= MAX_NDIS_SETTINGS) {
			ERROR("too many settings");
			return -EINVAL;
		}
				
	}

	fclose(config);

	if (conf_bustype == -1) {
		ERROR("coudn't find device type in settings");
		return -EINVAL;
	}			

	driver->nr_settings = nr_settings;
	return 0;
}

/*
 * open a windows driver and pass it to the kernel module.
 * returns 0: on success, -1 on error
 */
static int load_driver(int ioctl_device, char *driver_name,
		       char *conf_file_name)
{
	int i;
	struct dirent *dirent;
	struct load_driver *driver;
	int nr_sys_files, nr_bin_files;
	DIR *driver_dir;

	driver_dir = NULL;
	nr_sys_files = 0;
	nr_bin_files = 0;

	DBG("loading driver %s", driver_name);
	if (chdir(confdir) || chdir(driver_name)) {
		ERROR("couldn't change to directory %s: %s",
		      driver_name, strerror(errno));
		return -EINVAL;
	}
	if ((driver_dir = opendir(".")) == NULL) {
		ERROR("couldn't open driver directory %s: %s",
		      driver_name, strerror(errno));
		return -EINVAL;
	}
		
	if ((driver = malloc(sizeof(*driver))) == NULL) {
		ERROR("couldn't allocate memory for driver %s", driver_name);
		goto err;
	}
	memset(driver, 0, sizeof(*driver));
	strncpy(driver->name, driver_name, MAX_DRIVER_NAME_LEN);

	if (read_conf_file(conf_file_name, driver) ||
	    driver->nr_settings == 0) {
		ERROR("couldn't read conf file %s for driver %s",
		      conf_file_name, driver_name);
		goto err;
	}
	while ((dirent = readdir(driver_dir))) {
		int len;
		struct stat statbuf;

		if (strcmp(dirent->d_name, ".") == 0 ||
		    strcmp(dirent->d_name, "..") == 0)
			continue;

		if (stat(dirent->d_name, &statbuf) ||
		    !S_ISREG(statbuf.st_mode)) {
			ERROR("%s in %s is not a valid file: %s",
			      dirent->d_name, driver_name, strerror(errno));
			continue;
		}

		len = strlen(dirent->d_name);
		if (len > 4 &&
		     strcmp(&dirent->d_name[len-4], ".inf") == 0)
			continue;
		if (len > 5 &&
		     strcmp(&dirent->d_name[len-5], ".conf") == 0)
			continue;

		if (len > 4 && strcmp(&dirent->d_name[len-4], ".sys") == 0) {
			if (load_file(dirent->d_name,
				      &driver->sys_files[nr_sys_files])) {
				ERROR("couldn't load .sys file %s",
				      dirent->d_name);
				goto err;
			} else
				nr_sys_files++;
		} else if (len > 4 &&
			   ((strcmp(&dirent->d_name[len-4], ".bin") == 0) ||
			     (strcmp(&dirent->d_name[len-4], ".out") == 0))) {
			if (load_file(dirent->d_name,
				      &driver->bin_files[nr_bin_files])) {
				ERROR("coudln't load .bin file %s",
				      dirent->d_name);
				goto err;
			} else
				nr_bin_files++;
		} else
			ERROR("file %s is ignored", dirent->d_name);

		if (nr_sys_files == MAX_PE_IMAGES) {
			ERROR("too many .sys files for driver %s",
			      driver_name);
			goto err;
		}
		if (nr_bin_files == MAX_NDIS_BIN_FILES) {
			ERROR("too many .bin files for driver %s",
			      driver_name);
			goto err;
		}
	}

	if (nr_sys_files == 0) {
		ERROR("coudln't find valid drivers files for driver %s",
		      driver_name);
		goto err;
	}
	driver->nr_sys_files = nr_sys_files;
	driver->nr_bin_files = nr_bin_files;
	strncpy(driver->conf_file_name, conf_file_name,
		sizeof(driver->conf_file_name));

	if (ioctl(ioctl_device, NDIS_LOAD_DRIVER, driver))
		goto err;

	closedir(driver_dir);
	DBG("driver %s loaded", driver_name);
	free(driver);
	return 0;

err:
	if (driver_dir)
		closedir(driver_dir);
	for (i = 0; i < nr_sys_files; i++)
		munmap(driver->sys_files[i].data, driver->sys_files[i].size);
	for (i = 0; i < nr_bin_files; i++)
		munmap(driver->bin_files[i].data, driver->bin_files[i].size);
	ERROR("couldn't load driver %s", driver_name);
	free(driver);
	return -1;
}

/* check if a device is already in devices */
static int duplicate_device(struct load_device *device, int n,
			    struct load_device devices[])
{
	int i;

	for (i = 0; i < n; i++)
		if (device->vendor == devices[i].vendor &&
		    device->device == devices[i].device &&
		    device->subvendor == devices[i].subvendor &&
		    device->subdevice == devices[i].subdevice)
			return 1;

	return 0;
}

/* add all devices (based on conf files) for a given driver */
static int add_driver_devices(DIR *dir, char *driver_name,
			      int from, struct load_device devices[])
{
	struct dirent *dirent;
	int n;

	n = from;
	if (!dir || !driver_name) {
		ERROR("invalid driver");
		return n;
	}

	DBG("adding devices for driver %s", driver_name);
	while ((dirent = readdir(dir))) {
		int len;

		if (strcmp(dirent->d_name, ".") == 0 ||
		    strcmp(dirent->d_name, "..") == 0)
			continue;

		len = strlen(dirent->d_name);
		if (len > 5 &&
			   strcmp(&dirent->d_name[len-5], ".conf") == 0) {
			struct stat statbuf;
			char *s;
			struct load_device *device;

			if (lstat(dirent->d_name, &statbuf)) {
				ERROR("unable to open config file: %s",
				      strerror(errno));
				continue;
			}

			s = basename(dirent->d_name);
			/* remove ".conf" */
			s[strlen(s)-5] = 0;

			device = &devices[n];
			if (strlen(s) == 11 &&
			    sscanf(s, "%04x:%04x.%1d", &device->vendor,
				   &device->device, &device->bustype) == 3) {
				device->subvendor = DEV_ANY_ID;
				device->subdevice = DEV_ANY_ID;
			} else if (strlen(s) == 21 &&
				   sscanf(s, "%04x:%04x:%04x:%04x.%1d",
					  &device->vendor, &device->device,
					  &device->subvendor,
					  &device->subdevice,
					  &device->bustype) == 5) {
				;
			} else {
				ERROR("file %s is not valid - ignored",
				      dirent->d_name);
				continue;
			}
			if (device->bustype != NDIS_PCI_BUS &&
			    device->bustype != NDIS_USB_BUS) {
				ERROR("incorrect bus type %d",
				      device->bustype);
				continue;
			}
			if (duplicate_device(device, n, devices))
				DBG("device %04X:%04X is duplicate - ignored",
				    device->vendor, device->device);
			else {
				strncpy(device->driver_name, driver_name,
					sizeof(device->driver_name));
				strncpy(device->conf_file_name, dirent->d_name,
					sizeof(device->conf_file_name));
				strncat(device->conf_file_name, ".conf",
					sizeof(device->conf_file_name) -
					strlen(device->conf_file_name));
				DBG("device %04X:%04X:%04X:%04X is added",
				    device->vendor, device->device,
				    device->subvendor, device->subdevice);
				n++;
			}
		}
	}
	DBG("total number of devices added: %d", n);
	return n;
}

/*
 * load all installed drivers
 * returns: number of drivers loadeed successfully
 */
static int load_all_devices(int ioctl_device)
{
	struct stat statbuf;
	struct dirent  *dirent;
	DIR *dir, *driver;
	int loaded, res;
	struct load_device *devices;
	struct load_devices load_devices;

	if (chdir(confdir)) {
		ERROR("directory %s is not valid: %s",
		      confdir, strerror(errno));
		return -EINVAL;
	}
	if ((dir = opendir(confdir)) == NULL) {
		ERROR("directory %s is not valid: %s",
		      confdir, strerror(errno));
		return -EINVAL;
	}

	devices = malloc(sizeof(*devices) * MAX_NDIS_DEVICES);
	if (!devices) {
		ERROR("couldn't allocate memory");
		return -EINVAL;
	}
	loaded = 0;
	while((dirent = readdir(dir))) {
		if (strcmp(dirent->d_name, ".") == 0 ||
		    strcmp(dirent->d_name, "..") == 0)
			continue;

		if (stat(dirent->d_name, &statbuf) ||
		    (!S_ISDIR(statbuf.st_mode)))
			continue;

		if ((driver = opendir(dirent->d_name)) == NULL) {
			ERROR("directory %s is not valid: %s",
			      dirent->d_name, strerror(errno));
			continue;
		}
		if (chdir(dirent->d_name)) {
			ERROR("directory %s is not valid: %s",
			      dirent->d_name, strerror(errno));
			closedir(driver);
			continue;
		}
		loaded = add_driver_devices(driver, dirent->d_name,
					    loaded, devices);
		chdir("..");
		closedir(driver);
	}
	closedir(dir);

	if (loaded == 0) {
		ERROR("no valid NDIS drives found in %s; you may need to"
		      " reinstall Windows drivers", confdir);
		free(devices);
		return -1;
	}
	load_devices.count = loaded;
	load_devices.devices = devices;

	res = ioctl(ioctl_device, NDIS_REGISTER_DEVICES, &load_devices);
	free(devices);

	if (res) {
		ERROR("couldn't load devices");
		return -1;
	}

	return 0;
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
		if (strstr(line, DRIVER_NAME)) {
			long i = strtol(line, 0, 10);
			if (i != LONG_MAX && i != LONG_MIN) {
				minor_dev = i;
				break;
			}
		}
	}
	fclose(proc_misc);

	if (minor_dev == -1) {
		ERROR("couldn't find ndiswrapper in /proc/misc; "
		      "is ndiswrapper module loaded?");
		return -1;
	}

	unlink(ioctl_file);
	if (mknod(ioctl_file, S_IFCHR | 0600, 10 << 8 | minor_dev) == -1) {
		ERROR("couldn't create file %s: %s",
		      ioctl_file, strerror(errno));
		return -1;
	}

	fd = open(ioctl_file, O_RDONLY);
	unlink(ioctl_file);

	if (fd == -1) {
		ERROR("couldn't open file %s: %s",
		      ioctl_file, strerror(errno));
		return -1;
	}
	return fd;
}

/* two ways to call this program:
 *  first, to load all devices, use "-a" argument
 *  later, load a specific driver and device (i.e., conf file) with
 *  arguments driver name, vendor, device, subvendor, subdevice
*/
int main(int argc, char *argv[0])
{
	int i, ioctl_device, res;

	openlog(PROG_NAME, LOG_PERROR | LOG_CONS, LOG_KERN | LOG_DEBUG);

	if (argc < 4) {
		res = 1;
		goto out;
	}

	i = -1;
	i = atoi(argv[1]);
	if (i < 0) {
		ERROR("invalid debug value %d", i);
		res = 2;
		goto out;
	} else
		debug = i;

	ioctl_device = get_ioctl_device();
	if (ioctl_device == -1) {
		ERROR("unable to open ioctl device %s", ioctl_file);
		res = 5;
		goto out;
	}

	if (atof(argv[2]) != atof(UTILS_VERSION)) {
		ERROR("version %s doesn't match driver version %s",
		      UTILS_VERSION, argv[2]);
		res = 6;
		goto out;
	}

	if (strcmp(argv[3], "-a") == 0) {
		if (load_all_devices(ioctl_device))
			res = 7;
		else
			res = 0;
	} else {
		/* load specific driver and conf file */
		if (argc != 5) {
			ERROR("incorrect usage of %s (%d)", argv[0], argc);
			res = 11;
			goto out;
		}
		res = load_driver(ioctl_device, argv[3], argv[4]);
	}

out:
	if (ioctl_device != -1)
		close(ioctl_device);
	closelog();
	return res;
}

