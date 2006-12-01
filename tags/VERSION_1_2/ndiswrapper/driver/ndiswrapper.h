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

#ifndef NDISWRAPPER_H
#define NDISWRAPPER_H

#define DRIVER_NAME "ndiswrapper"

#define SSID_MAX_WPA_IE_LEN 40
#define NDIS_ESSID_MAX_SIZE 32
#define NDIS_ENCODING_TOKEN_MAX 32
#define MAX_ENCR_KEYS 4
#define XMIT_RING_SIZE 32
#define NDIS_MAX_RATES 8
#define NDIS_MAX_RATES_EX 16
#define WLAN_EID_RSN 48
#define WLAN_EID_GENERIC 221
#define MAX_WPA_IE_LEN 64
#define MAX_STR_LEN 512

#define NDIS_PCI_BUS 5
#define NDIS_USB_BUS 0

#define MAX_DRIVER_NAME_LEN 32
#define MAX_NDIS_VERSION_STRING_LEN 64
#define MAX_NDIS_SETTING_NAME_LEN 128
#define MAX_NDIS_SETTING_VALUE_LEN 256

#define MAX_PE_IMAGES 4
#define MAX_NDIS_DEVICES 20
#define MAX_NDIS_BIN_FILES 5
#define MAX_NDIS_SETTINGS 512
#define MAX_DEVICES 128

#define DEV_ANY_ID -1

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#define MACINTADR(a) (int*)&((a)[0]), (int*)&((a)[1]), (int*)&((a)[2]), \
		(int*)&((a)[3]), (int*)&((a)[4]), (int*)&((a)[5])

#endif // NDISWRAPPER_H
