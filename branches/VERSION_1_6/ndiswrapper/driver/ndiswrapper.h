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

#ifndef _NDISWRAPPER_H_
#define _NDISWRAPPER_H_

#define DRIVER_NAME "ndiswrapper"

#define SSID_MAX_WPA_IE_LEN 40
#define NDIS_ESSID_MAX_SIZE 32
#define NDIS_ENCODING_TOKEN_MAX 32
#define MAX_ENCR_KEYS 4
#define XMIT_RING_SIZE 32
#define NDIS_MAX_RATES 8
#define NDIS_MAX_RATES_EX 16
#define WLAN_EID_GENERIC 221
#define MAX_WPA_IE_LEN 64
#define MAX_STR_LEN 512

#define WRAP_PCI_BUS 5
#define WRAP_PCMCIA_BUS 8
/* some USB devices, e.g., DWL-G120 have BusType as 0 */
#define WRAP_INTERNAL_BUS 0
/* documentation at msdn says 15 is PNP bus, but inf files from all
 * vendors say 15 is USB; which is correct? */
#define WRAP_USB_BUS 15

/* NDIS device must be 0, for compatability with old versions of
 * ndiswrapper where device type for NDIS drivers is 0 */
#define WRAP_NDIS_DEVICE 0
#define WRAP_USB_DEVICE 1

#define WRAP_DEVICE_BUS_TYPE(dev, bus) ((dev) << 8 | (bus))
#define WRAP_BUS_TYPE(dev_bus_type) ((dev_bus_type) & 0x000FF)
#define WRAP_DEVICE_TYPE(dev_bus_type) ((dev_bus_type) >> 8)

#define wrap_is_pci_bus(dev_bus_type)				\
	(WRAP_BUS_TYPE(dev_bus_type) == WRAP_PCI_BUS)
/* earlier versions of ndiswrapper used 0 as USB_BUS */
#define wrap_is_usb_bus(dev_bus_type)				\
	(WRAP_BUS_TYPE(dev_bus_type) == WRAP_USB_BUS ||		\
	 WRAP_BUS_TYPE(dev_bus_type) == 0)

#define MAX_DRIVER_NAME_LEN 32
#define MAX_VERSION_STRING_LEN 64
#define MAX_SETTING_NAME_LEN 128
#define MAX_SETTING_VALUE_LEN 256

#define MAX_DRIVER_PE_IMAGES 4
#define MAX_DRIVER_BIN_FILES 5
#define MAX_DEVICE_SETTINGS 512
#define MAX_WRAP_DEVICES 128

#define DEV_ANY_ID -1

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#define MACINTADR(a) (int*)&((a)[0]), (int*)&((a)[1]), (int*)&((a)[2]), \
		(int*)&((a)[3]), (int*)&((a)[4]), (int*)&((a)[5])

#endif // NDISWRAPPER_H
