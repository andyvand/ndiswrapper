/*
 *  Copyright (C) 2003-2004 Pontus Fuchs, Giridhar Pemmasani
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

#ifndef LOADER_H
#define LOADER_H

#define MAX_DRIVER_NAME_LEN 32
#define MAX_NDIS_VERSION_STRING_LEN 64
#define MAX_NDIS_SETTING_NAME_LEN 128
#define MAX_NDIS_SETTING_VALUE_LEN 256

#define MAX_PE_IMAGES 4
#define MAX_NDIS_DEVICES 20
#define MAX_NDIS_BIN_FILES 5
#define MAX_NDIS_SETTINGS 256

struct load_driver_file {
	char name[MAX_DRIVER_NAME_LEN];
	size_t size;
	void *data;
};

struct load_device_setting {
	char name[MAX_NDIS_SETTING_NAME_LEN];
	char value[MAX_NDIS_SETTING_VALUE_LEN];
};
		
struct load_device {
	int bustype;
	int vendor;
	int device;
	int pci_subvendor;
	int pci_subdevice;
	int fuzzy;
	unsigned int nr_settings;
	struct load_device_setting settings[MAX_NDIS_SETTINGS];
};

struct load_driver {
	char name[MAX_DRIVER_NAME_LEN];
	unsigned int nr_sys_files;
	struct load_driver_file sys_files[MAX_PE_IMAGES];
	unsigned int nr_devices;
	struct load_device devices[MAX_NDIS_DEVICES];
	unsigned int nr_bin_files;
	struct load_driver_file bin_files[MAX_NDIS_BIN_FILES];
};

#define NDIS_ADD_DRIVER     _IOW('N', 0, struct load_driver *)

int loader_init(void);
void loader_exit(void);

#endif /* LOADER_H */

