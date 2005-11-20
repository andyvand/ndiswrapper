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

#ifndef _LOADER_H_
#define _LOADER_H_

#include "ndiswrapper.h"

struct load_driver_file {
	char name[MAX_DRIVER_NAME_LEN];
	size_t size;
	void *data;
};

struct load_device_setting {
	char name[MAX_SETTING_NAME_LEN];
	char value[MAX_SETTING_VALUE_LEN];
};
		
struct load_device {
	int dev_bus_type;
	int vendor;
	int device;
	int subvendor;
	int subdevice;
	char conf_file_name[MAX_DRIVER_NAME_LEN];
	char driver_name[MAX_DRIVER_NAME_LEN];
};

struct load_devices {
	int count;
	struct load_device *devices;
};

struct load_driver {
	char name[MAX_DRIVER_NAME_LEN];
	char conf_file_name[MAX_DRIVER_NAME_LEN];
	unsigned int nr_sys_files;
	struct load_driver_file sys_files[MAX_PE_IMAGES];
	unsigned int nr_settings;
	struct load_device_setting settings[MAX_DEVICE_SETTINGS];
	unsigned int nr_bin_files;
	struct load_driver_file bin_files[MAX_DRIVER_BIN_FILES];
};

#define WRAP_REGISTER_DEVICES	_IOW(('N' + 'd' + 'i' + 'S'), 0,	\
				     struct load_devices *)
#define WRAP_LOAD_DRIVER	_IOW(('N' + 'd' + 'i' + 'S'), 1,	\
				     struct load_driver *)

int loader_init(void);
void loader_exit(void);
struct wrap_driver *load_wrap_driver(struct wrap_device *device);

#endif /* LOADER_H */

