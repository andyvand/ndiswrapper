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

int ndis_set_mode(struct net_device *dev, struct iw_request_info *info,
				  union iwreq_data *wrqu, char *extra);
struct iw_statistics *ndis_get_wireless_stats(struct net_device *dev);
int ndis_set_essid(struct net_device *dev, struct iw_request_info *info,
		   union iwreq_data *wrqu, char *extra);

int ndis_set_priv_filter(struct net_device *dev,
			 struct iw_request_info *info,
			 union iwreq_data *wrqu, char *extra);
int ndis_get_ap_address(struct net_device *dev, struct iw_request_info *info,
			union iwreq_data *wrqu, char *extra);

#endif // IW_NDIS_H
