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

#ifndef WRAPPER_H
#define WRAPPER_H

#include "ndis.h"

int miniport_reset(struct ndis_handle *handle);
int miniport_query_info(struct ndis_handle *handle, unsigned int oid,
			char *buf, unsigned int bufsize);
int miniport_query_info_needed(struct ndis_handle *handle, unsigned int oid,
			       char *buf, unsigned int bufsize,
			       unsigned int *needed);
int miniport_set_info(struct ndis_handle *handle, unsigned int oid,
		      char *buf, unsigned int bufsize);
int miniport_query_int(struct ndis_handle *handle, int oid, int *data);
int miniport_set_int(struct ndis_handle *handle, int oid, int data);
int miniport_init(struct ndis_handle *handle);
void miniport_halt(struct ndis_handle *handle);
void hangcheck_add(struct ndis_handle *handle);
void hangcheck_del(struct ndis_handle *handle);
void sendpacket_done(struct ndis_handle *handle, struct ndis_packet *packet);
int ndiswrapper_suspend_pci(struct pci_dev *pdev, u32 state);
int ndiswrapper_resume_pci(struct pci_dev *pdev);

void ndiswrapper_remove_one_dev(struct ndis_handle *handle);
int ndis_reinit(struct ndis_handle *handle);
int setup_dev(struct net_device *dev);

struct net_device *ndis_init_netdev(struct ndis_handle **phandle,
				    struct ndis_device *device,
				    struct ndis_driver *driver);

#endif /* WRAPPER_H */
