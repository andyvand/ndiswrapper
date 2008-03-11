/*
 *  Copyright (C) 2006-2007 Giridhar Pemmasani
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

int wrapndis_init(void);
void wrapndis_exit(void);

NDIS_STATUS mp_reset(struct ndis_device *wnd);
NDIS_STATUS mp_query_info(struct ndis_device *wnd, ndis_oid oid, void *buf,
			  ULONG bufsize, UINT *needed, UINT *written);
NDIS_STATUS mp_set_info(struct ndis_device *wnd, ndis_oid oid, void *buf,
			ULONG bufsize, UINT *needed, UINT *written);
NDIS_STATUS mp_request_method(struct ndis_device *wnd, ndis_oid oid,
			      void *buf, ULONG buf_len, UINT *needed,
			      UINT *written);
static inline NDIS_STATUS mp_query(struct ndis_device *wnd, ndis_oid oid,
				   void *buf, ULONG buf_len)
{
	return mp_query_info(wnd, oid, buf, buf_len, NULL, NULL);
}

static inline NDIS_STATUS mp_query_int(struct ndis_device *wnd,
				       ndis_oid oid, UINT *value)
{
	return mp_query_info(wnd, oid, (void *)value, sizeof(UINT), NULL, NULL);
}

static inline NDIS_STATUS mp_set(struct ndis_device *wnd,
				 ndis_oid oid, void *buf, ULONG buf_len)
{
	return mp_set_info(wnd, oid, buf, buf_len, NULL, NULL);
}

static inline NDIS_STATUS mp_set_int(struct ndis_device *wnd,
				     ndis_oid oid, UINT value)
{
	return mp_set_info(wnd, oid, (void *)&value, sizeof(UINT), NULL, NULL);
}

void free_tx_buffer_list(struct ndis_device *wnd,
			 struct net_buffer_list *buffer_list);
int init_ndis_driver(struct driver_object *drv_obj);
NDIS_STATUS ndis_reinit(struct ndis_device *wnd);

void get_encryption_capa(struct ndis_device *wnd);
void hangcheck_add(struct ndis_device *wnd);
void hangcheck_del(struct ndis_device *wnd);
NDIS_STATUS mp_pnp_event(struct ndis_device *wnd,
			 enum ndis_device_pnp_event event, ULONG profile);

driver_dispatch_t winNdisDispatchPnp;
driver_dispatch_t winNdisDispatchPower;
driver_dispatch_t winNdisDispatchDeviceControl;

struct iw_statistics *get_iw_stats(struct net_device *dev);

#endif
