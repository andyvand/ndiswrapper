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
#ifndef WRAPPER_H
#define WRAPPER_H


#include <linux/ioctl.h>

#define DRIVERNAME_MAX 32

struct put_driver {
	char name[DRIVERNAME_MAX];
	size_t size;
	void *data;
};

struct del_driver {
	char name[DRIVERNAME_MAX];
};

struct put_device {
	int pci_vendor;
	int pci_device;
	int pci_subvendor;
	int pci_subdevice;
	int fuzzy;
};

struct put_setting
{
	size_t name_len;
	size_t val_str_len;
	char *name;
	char *val_str;
};

#define NDIS_PUTDRIVER     _IOWR('N', 0, struct put_driver*)
#define NDIS_PUTSETTING    _IOWR('N', 1, struct put_setting*)
#define NDIS_STARTDRIVER   _IOWR('N', 2, int)
#define NDIS_DELDRIVER     _IOWR('N', 4, struct del_driver *)
#define NDIS_PUTDEVICE     _IOWR('N', 5, struct put_device*)
#define NDIS_PUTDEVICEDONE _IOWR('N', 6, void)
#endif /* WRAPPER_H */
