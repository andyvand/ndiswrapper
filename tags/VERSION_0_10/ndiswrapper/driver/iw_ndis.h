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
#ifndef IW_NDIS_H
#define IW_NDIS_H

#include "ndis.h"

extern const struct iw_handler_def ndis_handler_def;

int set_essid(struct ndis_handle *handle, const char *ssid, int ssid_len);
int set_mode(struct ndis_handle *handle, enum op_mode mode);
struct iw_statistics *get_wireless_stats(struct net_device *dev);
int get_ap_address(struct ndis_handle *handle, mac_address mac);
int set_auth_mode(struct ndis_handle *handle, int auth_mode);
int set_encr_mode(struct ndis_handle *handle, int encr_mode);
int set_privacy_filter(struct ndis_handle *handle, int flags);

#endif // IW_NDIS_H
