/*
 *  Copyright (C) 2005 Giridhar Pemmasani
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

NDIS_STATUS miniport_reset(struct wrapper_dev *wd);
NDIS_STATUS miniport_query_info_needed(struct wrapper_dev *wd,
				       ndis_oid oid, void *buf,
				       ULONG bufsize, ULONG *needed);
NDIS_STATUS miniport_query_info(struct wrapper_dev *wd, ndis_oid oid,
				void *buf, ULONG bufsize);
NDIS_STATUS miniport_set_info(struct wrapper_dev *wd, ndis_oid oid,
			      void *buf, ULONG bufsize);
NDIS_STATUS miniport_query_int(struct wrapper_dev *wd, ndis_oid oid,
			       ULONG *data);
NDIS_STATUS miniport_set_int(struct wrapper_dev *wd, ndis_oid oid,
			     ULONG data);
NDIS_STATUS miniport_pnp_event(struct wrapper_dev *wd, 
			       enum ndis_device_pnp_event event);
void hangcheck_add(struct wrapper_dev *wd);
void hangcheck_del(struct wrapper_dev *wd);
void sendpacket_done(struct wrapper_dev *wd, struct ndis_packet *packet);

int wrap_pnp_suspend_ndis_pci(struct pci_dev *pdev, pm_message_t state);
int wrap_pnp_resume_ndis_pci(struct pci_dev *pdev);

#if defined(CONFIG_USB) && LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
int wrap_pnp_suspend_ndis_usb(struct usb_interface *intf, pm_message_t state);
int wrap_pnp_resume_ndis_usb(struct usb_interface *intf);
#endif

NDIS_STATUS ndis_reinit(struct wrapper_dev *wd);
NDIS_STATUS miniport_init(struct wrapper_dev *wd);
void miniport_halt(struct wrapper_dev *wd);

void check_capa(struct wrapper_dev *wd);

driver_dispatch_t NdisDispatchPnp;
driver_dispatch_t NdisDispatchPower;

struct net_device *wrap_alloc_netdev(struct wrapper_dev **pwd,
				     struct ndis_device *device,
				     struct ndis_driver *driver);

struct iw_statistics *get_wireless_stats(struct net_device *dev);
STDCALL NTSTATUS NdisAddDevice(struct driver_object *drv_obj,
			       struct device_object *pdo);

#endif
