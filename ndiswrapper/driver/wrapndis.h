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

#ifndef _WRAPNDIS_H_
#define _WRAPNDIS_H_

#include "ndis.h"
#include "pnp.h"

NDIS_STATUS miniport_reset(struct wrap_ndis_device *wnd);
NDIS_STATUS miniport_query_info_needed(struct wrap_ndis_device *wnd,
				       ndis_oid oid, void *buf,
				       ULONG bufsize, ULONG *needed);
NDIS_STATUS miniport_query_info(struct wrap_ndis_device *wnd, ndis_oid oid,
				void *buf, ULONG bufsize);
NDIS_STATUS miniport_set_info(struct wrap_ndis_device *wnd, ndis_oid oid,
			      void *buf, ULONG bufsize);
NDIS_STATUS miniport_query_int(struct wrap_ndis_device *wnd, ndis_oid oid,
			       ULONG *data);
NDIS_STATUS miniport_set_int(struct wrap_ndis_device *wnd, ndis_oid oid,
			     ULONG data);
void sendpacket_done(struct wrap_ndis_device *wnd, struct ndis_packet *packet);
int init_ndis_driver(struct driver_object *drv_obj);
NDIS_STATUS ndis_reinit(struct wrap_ndis_device *wnd);

void check_capa(struct wrap_ndis_device *wnd);
void hangcheck_add(struct wrap_ndis_device *wnd);
void hangcheck_del(struct wrap_ndis_device *wnd);

driver_dispatch_t NdisDispatchPnp;
driver_dispatch_t NdisDispatchPower;
driver_dispatch_t NdisDispatchDeviceControl;

struct iw_statistics *get_wireless_stats(struct net_device *dev);

#endif
