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
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/kmod.h>

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/miscdevice.h>
#include <linux/pci.h>

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/if_arp.h>
#include <net/iw_handler.h>
#include <linux/rtnetlink.h>

#include <asm/uaccess.h>

#include "wrapper.h"
#include "pe_loader.h"
#include "ndis.h"
#include "iw_ndis.h"

#ifndef NDISWRAPPER_VERSION
#error You must run make from the toplevel directory
#endif

/* Define this if you are developing and ndis_init_one crashes.
   When using the old PCI-API a reboot is not needed when this
   function crashes. A simple rmmod -f will do the trick and
   you can try again.
*/

/*#define DEBUG_CRASH_ON_INIT*/

static char *if_name = "wlan%d";
int proc_uid, proc_gid;
static int hangcheck_interval;
//static int resubmit_config;

NW_MODULE_PARM_STRING(if_name, 0400);
MODULE_PARM_DESC(if_name, "Network interface name or template (default: wlan%d)");
NW_MODULE_PARM_INT(proc_uid, 0600);
MODULE_PARM_DESC(proc_uid, "The uid of the files created in /proc (default: 0).");
NW_MODULE_PARM_INT(proc_gid, 0600);
MODULE_PARM_DESC(proc_gid, "The gid of the files created in /proc (default: 0).");
NW_MODULE_PARM_INT(hangcheck_interval, 0600);
/* 0 - default value provided by NDIS driver,
 * positive value - force hangcheck interval to that many seconds
 * negative value - disable hangcheck
 */
MODULE_PARM_DESC(hangcheck_interval, "The interval, in seconds, for checking if driver is hung. (default: 0)");
//MODULE_PARM(resubmit_config, "i");
//MODULE_PARM_DESC(resubmit_config, "Set to 1 for resubmitting device config after disassociation (default: 0)");

/* List of loaded drivers */
LIST_HEAD(ndis_driverlist);

/* Protects driver list */
static struct wrap_spinlock driverlist_lock;

extern struct list_head wrap_allocs;
extern struct wrap_spinlock wrap_allocs_lock;
extern struct wrap_spinlock dispatch_event_lock;

extern struct list_head handle_ctx_list;

void ndis_set_rx_mode(struct net_device *dev);

/*
 * MiniportReset
 */
int miniport_reset(struct ndis_handle *handle)
{
	unsigned int res = 0;
	KIRQL irql;
	struct miniport_char *miniport = &handle->driver->miniport_char;

	TRACEENTER2("%s", "");

	if (handle->reset_status)
		return NDIS_STATUS_PENDING;

	if (down_interruptible(&handle->ndis_comm_mutex))
		TRACEEXIT3(return NDIS_STATUS_FAILURE);

	/* reset_status is used for two purposes: to check if windows
	 * driver needs us to reset filters etc (as per NDIS) and to
	 * check if another reset is in progress */
	handle->reset_status = NDIS_STATUS_PENDING;
	handle->ndis_comm_res = NDIS_STATUS_PENDING;
	handle->ndis_comm_done = 0;
	irql = raise_irql(DISPATCH_LEVEL);
	res = miniport->reset(&handle->reset_status, handle->adapter_ctx);
	lower_irql(irql);

	DBGTRACE2("res = %08X, reset_status = %08X",
		  res, handle->reset_status);
	if (res == NDIS_STATUS_PENDING)
	{
		DBGTRACE2("%s", "waiting for reset_complete");
		/* reset is supposed to run at DISPATCH_LEVEL, so we busy wait
		 * for a while before sleeping, hoping reset will be done in
		 * 1 ms */
		mdelay(1);
		/* wait for NdisMResetComplete upto 1 s */
		if (!wait_event_interruptible_timeout(
			    handle->ndis_comm_wq,
			    (handle->ndis_comm_done == 1), 1*HZ))
			handle->ndis_comm_res = NDIS_STATUS_FAILURE;
		res = handle->ndis_comm_res;
		DBGTRACE2("res = %08X, reset_status = %08X",
			  res, handle->reset_status);
	}
	up(&handle->ndis_comm_mutex);
	DBGTRACE2("reset: res = %08X, reset status = %08X",
		  res, handle->reset_status);

	if (res == NDIS_STATUS_SUCCESS && handle->reset_status)
	{
		handle->rx_packet = &NdisMIndicateReceivePacket;
		handle->send_complete = &NdisMSendComplete;
		handle->send_resource_avail = &NdisMSendResourcesAvailable;
		handle->status = &NdisMIndicateStatus;
		handle->status_complete = &NdisMIndicateStatusComplete;
		handle->query_complete = &NdisMQueryInformationComplete;
		handle->set_complete = &NdisMSetInformationComplete;
		handle->reset_complete = &NdisMResetComplete;
		ndis_set_rx_mode(handle->net_dev);
	}
	handle->reset_status = 0;

	TRACEEXIT3(return res);
}

/*
 * MiniportQueryInformation
 * Perform a sync query and deal with the possibility of an async operation.
 * This function must be called from process context as it will sleep.
 */
int miniport_query_info(struct ndis_handle *handle, unsigned int oid,
			char *buf, int bufsize, unsigned int *written,
			unsigned int *needed)
{
	unsigned int res;
	KIRQL irql;
	struct miniport_char *miniport = &handle->driver->miniport_char;

	TRACEENTER3("query is at %p", miniport->query);

	if (down_interruptible(&handle->ndis_comm_mutex))
		TRACEEXIT3(return NDIS_STATUS_FAILURE);

	handle->ndis_comm_done = 0;
	irql = raise_irql(DISPATCH_LEVEL);
	res = miniport->query(handle->adapter_ctx, oid, buf, bufsize,
			      written, needed);
	lower_irql(irql);

	DBGTRACE3("res = %08x", res);
	if (res == NDIS_STATUS_PENDING)
	{
		/* wait for NdisMQueryInformationComplete upto HZ */
		if (!wait_event_interruptible_timeout(
			    handle->ndis_comm_wq,
			    (handle->ndis_comm_done == 1), 1*HZ))
			handle->ndis_comm_res = NDIS_STATUS_FAILURE;
		res = handle->ndis_comm_res;
	}
	up(&handle->ndis_comm_mutex);
	TRACEEXIT3(return res);
}

/*
 * MiniportSetInformation
 * Perform a sync setinfo and deal with the possibility of an async operation.
 * This function must be called from process context as it will sleep.
 */
int miniport_set_info(struct ndis_handle *handle, unsigned int oid, char *buf,
		      int bufsize, unsigned int *written, unsigned int *needed)
{
	unsigned int res;
	KIRQL irql;
	struct miniport_char *miniport = &handle->driver->miniport_char;

	TRACEENTER3("setinfo is at %p", miniport->setinfo);

	if (down_interruptible(&handle->ndis_comm_mutex))
		TRACEEXIT3(return NDIS_STATUS_FAILURE);

	handle->ndis_comm_done = 0;
	irql = raise_irql(DISPATCH_LEVEL);
	res = miniport->setinfo(handle->adapter_ctx, oid, buf, bufsize,
			       written, needed);
	DBGTRACE3("res = %08x", res);
	lower_irql(irql);

	if (res == NDIS_STATUS_PENDING)
	{
		/* wait for NdisMSetInformationComplete upto HZ */
		if (!wait_event_interruptible_timeout(
			    handle->ndis_comm_wq,
			    (handle->ndis_comm_done == 1), 1*HZ))
			handle->ndis_comm_res = NDIS_STATUS_FAILURE;
		res = handle->ndis_comm_res;
	}
	up(&handle->ndis_comm_mutex);
	TRACEEXIT3(return res);
}

/* Make a query that has an int as the result. */
int miniport_query_int(struct ndis_handle *handle, int oid, int *data)
{
	unsigned int res, written, needed;

	res = miniport_query_info(handle, oid, (char*)data, sizeof(int),
				  &written, &needed);
	if (!res)
		return 0;
	*data = 0;
	return res;
}

/* Set an int */
int miniport_set_int(struct ndis_handle *handle, int oid, int data)
{
	unsigned int written, needed;

	return miniport_set_info(handle, oid, (char*)&data, sizeof(int),
				 &written, &needed);
}

#ifdef HAVE_ETHTOOL
static u32 ndis_get_link(struct net_device *dev)
{
	struct ndis_handle *handle = dev->priv;
	return handle->link_status;
}

static struct ethtool_ops ndis_ethtool_ops = {
	.get_link		= ndis_get_link,
};
#endif

/*
 * MiniportInitialize
 */
int miniport_init(struct ndis_handle *handle)
{
	__u32 res, res2;
	__u32 selected_medium;
	__u32 mediumtypes[] = {0,1,2,3,4,5,6,7,8,9,10,11,12};
	struct miniport_char *miniport = &handle->driver->miniport_char;

	TRACEENTER1("driver init routine is at %p", miniport->init);
	if (miniport->init == NULL)
	{
		ERROR("%s", "initialization function is not setup correctly");
		return -EINVAL;
	}
	res = miniport->init(&res2, &selected_medium, mediumtypes, 13, handle,
			     handle);
	if (res)
		return res;
	return 0;
}

/*
 * MiniportHalt
 */
void miniport_halt(struct ndis_handle *handle)
{
	struct miniport_char *miniport = &handle->driver->miniport_char;
	TRACEENTER1("driver halt is at %p", miniport->halt);

	miniport_set_int(handle, NDIS_OID_PNP_SET_POWER, NDIS_PM_STATE_D3);

	miniport->halt(handle->adapter_ctx);

	ndis_cleanup_handle(handle);

	if (handle->device->bustype == 5)
		pci_set_power_state(handle->dev.pci, 3);
	TRACEEXIT1(return);
}

static unsigned int call_entry(struct ndis_driver *driver)
{
	int i, ret, res;
	struct ustring reg_string;
	char *reg_path = "\0\0t0m0p0";
	
	reg_string.buf = reg_path;
	reg_string.buflen = reg_string.len = strlen(reg_path);
	for (ret = res = 0, i = 0; i < driver->num_pe_images; i++)
		/* dlls are already started by loader */
		if (driver->pe_images[i].type == COFF_CHAR_IMAGE) {
			unsigned int (*entry)(void *obj,
					      struct ustring *p2) STDCALL;
			entry = driver->pe_images[i].entry;
			TRACEENTER1("Calling NDIS driver entry at %08X "
				    "rva(%08X)",
				    (int)entry,
				    (int)entry -
				    (int)driver->pe_images[i].image);
			DBGTRACE("entry: %p, %p", entry, *entry);
			res = entry((void*)driver, &reg_string);
			ret |= res;
			DBGTRACE1("entry returns %08X", res);
			DBGTRACE1("Past entry: Version: %d.%dn",
				  driver->miniport_char.majorVersion,
				  driver->miniport_char.minorVersion);
			/* Dump addresses of driver suppoled callbacks */
#if defined DEBUG && DEBUG >= 1
			if(res == 0) {
				int j;
				int *adr;
				char *name[] = {
					"CheckForHangTimer",
					"DisableInterruptHandler",
					"EnableInterruptHandler",
					"halt",
					"HandleInterruptHandler",
					"init",
					"ISRHandler",
					"query",
					"ReconfigureHandler",
					"ResetHandler",
					"SendHandler",
					"SetInformationHandler",
					"TransferDataHandler",
					"ReturnPacketHandler",
					"SendPacketsHandler",
					"AllocateCompleteHandler",
				};

				adr = (int*) &driver->miniport_char.hangcheck;

				for(j = 0; j < 16; j++)
					DBGTRACE1("%08X (rva %08X):%s", adr[j],
						  adr[j] ? adr[j] - 
						  (int)driver->pe_images[i].image : 0,
						  name[j]);
			}
#endif
		}
	return ret;
}

static void hangcheck_proc(unsigned long data)
{
	struct ndis_handle *handle = (struct ndis_handle *)data;

	TRACEENTER3("%s", "");
	/* MiniportCheckForHang runs at DISPATCH_LEVEL */
	/* since hangcheck_proc function is bh, it already runs at
	 * DISPATCH_LEVEL, so no need to raise irql */
	if (handle->reset_status == 0 &&
	    handle->driver->miniport_char.hangcheck(handle->adapter_ctx)) {
		int res;
		WARNING("Hangcheck returned true. Resetting %s!",
			handle->net_dev->name);
		res = miniport_reset(handle);
		DBGTRACE3("reset returns %08X, %d", res, handle->reset_status);
	}

	spin_lock(&handle->timers_lock);
	if (handle->hangcheck_active) {
		handle->hangcheck_timer.expires = 
			jiffies + handle->hangcheck_interval;
		add_timer(&handle->hangcheck_timer);
	}
	spin_unlock(&handle->timers_lock);

	TRACEEXIT3(return);
}

void hangcheck_add(struct ndis_handle *handle)
{
	if (!handle->driver->miniport_char.hangcheck ||
	    handle->hangcheck_interval <= 0) {
		handle->hangcheck_active = 0;
		return;
	}

	init_timer(&handle->hangcheck_timer);
	handle->hangcheck_timer.data = (unsigned long) handle;
	handle->hangcheck_timer.function = &hangcheck_proc;

	add_timer(&handle->hangcheck_timer);
	handle->hangcheck_active = 1;
	return;
}

void hangcheck_del(struct ndis_handle *handle)
{
	if (!handle->driver->miniport_char.hangcheck ||
	    handle->hangcheck_interval <= 0)
		return;

	spin_lock_bh(&handle->timers_lock);
	handle->hangcheck_active = 0;
	del_timer(&handle->hangcheck_timer);
	spin_unlock_bh(&handle->timers_lock);
}


static void statcollector_reinit(struct ndis_handle *handle);

static void statcollector_proc(void *data)
{
	struct ndis_handle *handle = (struct ndis_handle *)data;
	unsigned int res, written, needed;
	struct iw_statistics *iw_stats = &handle->wireless_stats;
	struct ndis_wireless_stats ndis_stats;
	long rssi;

	res = miniport_query_info(handle, NDIS_OID_RSSI, (char *)&rssi,
				  sizeof(rssi), &written, &needed);
	iw_stats->qual.level = rssi;

	memset(&ndis_stats, 0, sizeof(ndis_stats));
	res = miniport_query_info(handle, NDIS_OID_STATISTICS,
				  (char *)&ndis_stats,
				  sizeof(ndis_stats), &written, &needed);
	if (res == NDIS_STATUS_NOT_SUPPORTED)
		iw_stats->qual.qual = ((rssi & 0x7F) * 100) / 154;
	else {
		iw_stats->discard.retries = (__u32)ndis_stats.retry +
			(__u32)ndis_stats.multi_retry;
		iw_stats->discard.misc = (__u32)ndis_stats.fcs_err +
			(__u32)ndis_stats.rtss_fail +
			(__u32)ndis_stats.ack_fail +
			(__u32)ndis_stats.frame_dup;

		if ((__u32)ndis_stats.tx_frag)
			iw_stats->qual.qual = 100 - 100 *
				((__u32)ndis_stats.retry +
				 2 * (__u32)ndis_stats.multi_retry +
				 3 * (__u32)ndis_stats.failed) /
				(6 * (__u32)ndis_stats.tx_frag);
		else
			iw_stats->qual.qual = 100;
	}
}

static void statcollector_timer(unsigned long data)
{
	struct ndis_handle *handle = (struct ndis_handle *)data;
	if (handle->reset_status == 0)
		schedule_work(&handle->statcollector_work);
	statcollector_reinit(handle);
}

static void statcollector_reinit(struct ndis_handle *handle)
{
	handle->statcollector_timer.data = (unsigned long) handle;
	handle->statcollector_timer.function = &statcollector_timer;
	handle->statcollector_timer.expires = jiffies + 1*HZ;
	add_timer(&handle->statcollector_timer);
}

static void statcollector_add(struct ndis_handle *handle)
{
	INIT_WORK(&handle->statcollector_work, &statcollector_proc, handle);
	init_timer(&handle->statcollector_timer);
	statcollector_reinit(handle);
}

static void statcollector_del(struct ndis_handle *handle)
{
	del_timer_sync(&handle->statcollector_timer);
}

static int ndis_open(struct net_device *dev)
{
	TRACEENTER1("%s", "");
	netif_start_queue(dev);
	return 0;
}

static int ndis_close(struct net_device *dev)
{
	TRACEENTER1("%s", "");
	netif_stop_queue(dev);
	return 0;
}

/*
 * query functions may not be called from this function as
 * they might sleep which is not allowed from the context this function
 * is running in.
 */
static struct net_device_stats *ndis_get_stats(struct net_device *dev)
{
	struct ndis_handle *handle = dev->priv;
	return &handle->stats;
}


static int ndis_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	int rc = -ENODEV;
	return rc;
}

static void set_multicast_list(struct net_device *dev,
			       struct ndis_handle *handle)
{
	unsigned int written, needed;
	struct dev_mc_list *mclist;
	int i;
	char *list = handle->multicast_list;
	int size = 0, res;

	for (i = 0, mclist = dev->mc_list; mclist && i < dev->mc_count;
	     i++, mclist = mclist->next)
	{
		memcpy(list, mclist->dmi_addr, 6);
		list += 6;
		size += 6;
	}
	DBGTRACE1("%d entries. size=%d", dev->mc_count, size);

	res = miniport_set_info(handle, OID_802_3_MULTICAST_LIST, list,
				size, &written, &needed);
	if (res)
		ERROR("Unable to set multicast list (%08X)", res);
}

/*
 * Like ndis_set_rx_mode but this one will sleep.
 */
static void ndis_set_rx_mode_proc(void *param)
{
	struct net_device *dev = (struct net_device*) param;
	struct ndis_handle *handle = dev->priv;
	unsigned long packet_filter;
	int res;
	unsigned int written, needed;

	TRACEENTER1("%s", "");
	packet_filter = (NDIS_PACKET_TYPE_DIRECTED |
	                 NDIS_PACKET_TYPE_BROADCAST |
	                 NDIS_PACKET_TYPE_ALL_MULTICAST);

	if (dev->flags & IFF_PROMISC) {
		DBGTRACE1("%s", "Going into promiscuous mode");
		printk(KERN_WARNING "promiscuous mode is not supported by NDIS"
		       ";only packets sent from/to this host will be seen\n");
		packet_filter |= NDIS_PACKET_TYPE_ALL_LOCAL;
	}
	else if ((dev->mc_count > handle->multicast_list_size) ||
	         (dev->flags & IFF_ALLMULTI) ||
	         (handle->multicast_list == 0))
	{
		/* Too many to filter perfectly -- accept all multicasts. */
		DBGTRACE1("%s", "Multicast list to long. Accepting all\n");
		packet_filter |= NDIS_PACKET_TYPE_ALL_MULTICAST;
	}
	else if(dev->mc_count > 0)
	{
		packet_filter |= NDIS_PACKET_TYPE_MULTICAST;
		set_multicast_list(dev, handle);
	}

	res = miniport_set_info(handle, NDIS_OID_PACKET_FILTER,
				(char *)&packet_filter,
				sizeof(packet_filter), &written, &needed);
	if (res)
		ERROR("Unable to set packet filter (%08X)", res);
}

/*
 * This function is called fom BH context...no sleep!
 */
void ndis_set_rx_mode(struct net_device *dev)
{
	struct ndis_handle *handle = dev->priv;
	schedule_work(&handle->set_rx_mode_work);
}

/*
 * This function should be called while holding send_packet_lock
 */
static struct ndis_packet *init_packet(struct ndis_handle *handle,
				       struct ndis_buffer *buffer)
{
	struct ndis_packet *packet;

	packet = kmalloc(sizeof(struct ndis_packet), GFP_ATOMIC);
	if(!packet)
	{
		return NULL;
	}

	memset(packet, 0, sizeof(*packet));


/* Enable this if you want to poison the packet-info during debugging.
 * This is not enabled when debug is defined because one card I have
 * silently faild if this was on.
 */
#if 0
	{
		int i = 0;
		/* Poison extra packet info */
		int *x = (int*) &packet->ext1;
		for(i = 0; i <= 12; i++)
		{
			x[i] = i;
		}
	}
#endif

	if(handle->use_scatter_gather)
	{
		/* FIXME: do USB drivers call this? */
		packet->dataphys =
			PCI_DMA_MAP_SINGLE(handle->dev.pci,
					   buffer->data, buffer->len,
					   PCI_DMA_TODEVICE);
		packet->scatterlist.len = 1;
		packet->scatterlist.entry.physlo = packet->dataphys;
		packet->scatterlist.entry.physhi = 0;
		packet->scatterlist.entry.len = buffer->len;
		packet->scatter_gather_ext = &packet->scatterlist;
	}

	packet->oob_offset = offsetof(struct ndis_packet, timesent1);

	packet->nr_pages = NDIS_BUFFER_TO_SPAN_PAGES(buffer);
	packet->len = buffer->len;
	packet->count = 1;
	packet->valid_counts = 1;

	packet->buffer_head = buffer;
	packet->buffer_tail = buffer;

//	DBGTRACE4("Buffer: %08X, data %08X, len %d\n", (int)buffer,
//		  (int)buffer->data, (int)buffer->len);
	return packet;
}

/*
 * This function should be called while holding send_packet_lock
 */
static void free_packet(struct ndis_handle *handle, struct ndis_packet *packet)
{
	if(packet->dataphys)
	{
		/* FIXME: do USB drivers call this? */
		PCI_DMA_UNMAP_SINGLE(handle->dev.pci, packet->dataphys,
				     packet->len, PCI_DMA_TODEVICE);
	}

	kfree(packet);
}

/*
 * This function should be called while holding send_packet_lock
 */
static void free_buffer(struct ndis_handle *handle, struct ndis_packet *packet)
{
	kfree(packet->buffer_head->data);
	kfree(packet->buffer_head);
	free_packet(handle, packet);
}

/*
 * MiniportSend and MiniportSendPackets
 */
static int send_packet(struct ndis_handle *handle, struct ndis_packet *packet)
{
	int res;
	KIRQL irql = DISPATCH_LEVEL;
	struct miniport_char *miniport = &handle->driver->miniport_char;

	TRACEENTER3("packet = %p", packet);

	if (miniport->send_packets)
	{
		struct ndis_packet *packets[1];

		packets[0] = packet;
		if (test_bit(ATTR_SERIALIZED, &handle->attributes))
			irql = raise_irql(DISPATCH_LEVEL);
		miniport->send_packets(handle->adapter_ctx, &packets[0], 1);
		if (test_bit(ATTR_SERIALIZED, &handle->attributes)) {
			lower_irql(irql);
			/* serialized miniports set packet->status */
			res = packet->status;
		}
		else
		{
			/* deserialized miniports call NdisMSendComplete */
			res = NDIS_STATUS_PENDING;
		}
	}
	else if (miniport->send)
	{
		if (test_bit(ATTR_SERIALIZED, &handle->attributes))
			irql = raise_irql(DISPATCH_LEVEL);
		res = miniport->send(handle->adapter_ctx, packet, 0);
		if (test_bit(ATTR_SERIALIZED, &handle->attributes))
			lower_irql(irql);
	}
	else
	{
		DBGTRACE3("%s", "No send handler");
		res = NDIS_STATUS_FAILURE;
	}

	DBGTRACE3("send_packets returning %08X", res);

	TRACEEXIT3(return res);
}

static void xmit_bh(void *param)
{
	struct ndis_handle *handle = (struct ndis_handle*) param;
	struct ndis_buffer *buffer;
	int res;

	TRACEENTER3("send status is %08X", handle->send_status);

	if (down_interruptible(&handle->ndis_comm_mutex))
		TRACEEXIT3(return);

	while (handle->send_status == 0)
	{
		wrap_spin_lock(&handle->xmit_ring_lock);
		if (!handle->xmit_ring_pending)
		{
			wrap_spin_unlock(&handle->xmit_ring_lock);
			break;
		}
		buffer = handle->xmit_ring[handle->xmit_ring_start];
		wrap_spin_unlock(&handle->xmit_ring_lock);

		wrap_spin_lock(&handle->send_packet_lock);
		/* if we are resending a packet due to NDIS_STATUS_RESOURCES
		 * then just pick up the packet already created
		 */
		if (!handle->send_packet)
		{
			/* otherwise, get a new packet */
			handle->send_packet = init_packet(handle, buffer);
			if (!handle->send_packet)
			{
				wrap_spin_unlock(&handle->send_packet_lock);
				ERROR("%s", "couldn't get a packet");
				up(&handle->ndis_comm_mutex);
				return;
			}
		}

		res = send_packet(handle, handle->send_packet);
		/* If the driver returns...
		 * NDIS_STATUS_SUCCESS - we own the packet and
		 *    driver will not call NdisMSendComplete.
		 * NDIS_STATUS_PENDING - the driver owns the packet
		 *    and will return it using NdisMSendComplete.
		 * NDIS_STATUS_RESOURCES - (driver is serialized)
		 *    Requeue it when resources are available.
		 * NDIS_STATUS_FAILURE - drop the packet?
		 */
		switch (res)
		{
		case NDIS_STATUS_SUCCESS:
			sendpacket_done(handle, handle->send_packet);
			handle->send_status = 0;
			break;
		case NDIS_STATUS_PENDING:
			break;
		case NDIS_STATUS_RESOURCES:
			/* should be serialized driver */
			if (!test_bit(ATTR_SERIALIZED, &handle->attributes))
				ERROR("%s", "deserialized driver returning "
				      "NDIS_STATUS_RESOURCES!");
			handle->send_status = res;
			wrap_spin_unlock(&handle->send_packet_lock);
			/* this packet will be tried again */
			up(&handle->ndis_comm_mutex);
			return;

			/* free buffer, drop the packet */
		case NDIS_STATUS_FAILURE:
			free_buffer(handle, handle->send_packet);
			break;
		default:
			ERROR("Unknown status code %08X", res);
			free_buffer(handle, handle->send_packet);
			break;
		}

		handle->send_packet = NULL;
		wrap_spin_unlock(&handle->send_packet_lock);

		wrap_spin_lock(&handle->xmit_ring_lock);
		handle->xmit_ring_start =
			(handle->xmit_ring_start + 1) % XMIT_RING_SIZE;
		handle->xmit_ring_pending--;
		wrap_spin_unlock(&handle->xmit_ring_lock);
		if (netif_queue_stopped(handle->net_dev))
			netif_wake_queue(handle->net_dev);
	}
	up(&handle->ndis_comm_mutex);
	TRACEEXIT3(return);
}

/*
 * Free and unmap a packet created in xmit
 * This function should be called while holding send_packet_lock
 */
void sendpacket_done(struct ndis_handle *handle, struct ndis_packet *packet)
{
	TRACEENTER3("%s", "");
	/* is this lock necessary? */
	wrap_spin_lock(&handle->send_packet_done_lock);
	handle->stats.tx_bytes += packet->len;
	handle->stats.tx_packets++;

	free_buffer(handle, packet);
	wrap_spin_unlock(&handle->send_packet_done_lock);
	TRACEEXIT3(return);
}

/*
 * This function is called in BH disabled context and ndis drivers
 * must have their send-functions called from sleepeable context so we
 * just queue the packets up here and schedule a workqueue to run
 * later.
 */
static int start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ndis_handle *handle = dev->priv;
	struct ndis_buffer *buffer;
	unsigned int xmit_ring_next_slot;

	char *data = kmalloc(skb->len, GFP_ATOMIC);
	if(!data)
	{
		return 1;
	}

	buffer = kmalloc(sizeof(struct ndis_buffer), GFP_ATOMIC);
	if(!buffer)
	{
		kfree(data);
		return 1;
	}

	skb_copy_and_csum_dev(skb, data);
	buffer->data = data;
	buffer->next = 0;
	buffer->len = skb->len;
	dev_kfree_skb(skb);

	wrap_spin_lock(&handle->xmit_ring_lock);
	xmit_ring_next_slot =
		(handle->xmit_ring_start + handle->xmit_ring_pending) % XMIT_RING_SIZE;
	handle->xmit_ring[xmit_ring_next_slot] = buffer;
	handle->xmit_ring_pending++;
	wrap_spin_unlock(&handle->xmit_ring_lock);
	if (handle->xmit_ring_pending == XMIT_RING_SIZE)
		netif_stop_queue(handle->net_dev);

	schedule_work(&handle->xmit_work);

	return 0;
}

int ndis_suspend_pci(struct pci_dev *pdev, u32 state)
{
	struct net_device *dev;
	struct ndis_handle *handle;
	int res, i, pm_state;

	if (!pdev)
		return -1;
	handle = pci_get_drvdata(pdev);
	if (!handle)
		return -1;
	dev = handle->net_dev;

	if (test_bit(HW_SUSPENDED, &handle->hw_status) ||
	    test_bit(HW_HALTED, &handle->hw_status))
		return 0;

	DBGTRACE2("%s: detaching device", dev->name);
	netif_device_detach(dev);
	hangcheck_del(handle);
	statcollector_del(handle);

	if (test_bit(ATTR_HALT_ON_SUSPEND, &handle->attributes))
	{
		DBGTRACE2("%s", "driver requests halt_on_suspend");
		miniport_halt(handle);
		set_bit(HW_HALTED, &handle->hw_status);
	}
	else
	{
		/* some drivers don't support D2, so force them to and D3 */
		pm_state = NDIS_PM_STATE_D3;
		/* use copy; query_power changes this value */
		i = pm_state;
		res = miniport_query_int(handle, NDIS_OID_PNP_QUERY_POWER, &i);
		DBGTRACE2("%s: query power to state %d returns %08X",
			  dev->name, pm_state, res);
		if (res)
		{
			WARNING("No pnp capabilities for pm (%08X); halting",
				res);
			miniport_halt(handle);
			set_bit(HW_HALTED, &handle->hw_status);
		}
		else
		{
			res = miniport_set_int(handle, NDIS_OID_PNP_SET_POWER,
					       pm_state);
			DBGTRACE2("suspending returns %08X", res);
			set_bit(HW_SUSPENDED, &handle->hw_status);
		}
	}
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,9)
	pci_save_state(pdev);
#else
	pci_save_state(pdev, handle->pci_state);
#endif
	pci_set_power_state(pdev, state);

	DBGTRACE2("%s: device suspended", dev->name);
	return 0;
}

int ndis_resume_pci(struct pci_dev *pdev)
{
	struct net_device *dev;
	struct ndis_handle *handle;
	struct miniport_char *miniport;
	int res;
//	unsigned long profile_inf = NDIS_POWER_PROFILE_AC;

	if (!pdev)
		return -1;
	handle = pci_get_drvdata(pdev);
	if (!handle)
		return -1;
	dev = handle->net_dev;

	if (!(test_bit(HW_SUSPENDED, &handle->hw_status) ||
	      test_bit(HW_HALTED, &handle->hw_status)))
		return 0;

	pci_set_power_state(pdev, 0);
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,9)
	pci_restore_state(pdev);
#else
	pci_restore_state(pdev, handle->pci_state);
#endif
	if (test_bit(HW_HALTED, &handle->hw_status))
		res = miniport_init(handle);
	else
	{
		res = miniport_set_int(handle, NDIS_OID_PNP_SET_POWER,
				       NDIS_PM_STATE_D0);
		DBGTRACE2("%s: setting power to state %d returns %d",
			 dev->name, NDIS_PM_STATE_D0, res);
		if (res)
			WARNING("No pnp capabilities for pm (%08X)", res);

		miniport = &handle->driver->miniport_char;
		/*
		if (miniport->pnp_event_notify)
		{
			INFO("%s", "calling pnp_event_notify");
			miniport->pnp_event_notify(handle,
			NDIS_PNP_PROFILE_CHANGED,
			&profile_inf, sizeof(profile_inf));
		}
		*/

		/* this is ugly; calling hangcheck outside of
		   hangcheck timer bh is not correct - why do we need
		   reset here? */
		if (miniport->hangcheck) {
			KIRQL irql;
			int need_reset;

			irql = raise_irql(DISPATCH_LEVEL);
			need_reset = miniport->hangcheck(handle->adapter_ctx);
			lower_irql(irql);
			if (need_reset) {
				DBGTRACE2("%s", "resetting device");
				miniport_reset(handle);
			}
		}
	}
	miniport_set_int(handle, NDIS_OID_BSSID_LIST_SCAN, 0);
	/* TODO: set encryption too? */
	set_bit(SET_ESSID, &handle->wrapper_work);
	schedule_work(&handle->wrapper_worker);

	netif_device_attach(dev);

	hangcheck_add(handle);
	statcollector_add(handle);
	clear_bit(HW_HALTED, &handle->hw_status);
	clear_bit(HW_SUSPENDED, &handle->hw_status);
	DBGTRACE2("%s: device resumed", dev->name);
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0) && defined(CONFIG_USB)
int ndis_suspend_usb(struct usb_interface *intf, u32 state)
{
	struct net_device *dev;
	struct ndis_handle *handle =
		(struct ndis_handle *)usb_get_intfdata(intf);
	int i, pm_state;

	if (!handle)
		return -1;
	dev = handle->net_dev;

	if (test_bit(HW_SUSPENDED, &handle->hw_status))
		return 0;

	DBGTRACE2("%s: detaching device", dev->name);
//	netif_device_detach(dev);
	hangcheck_del(handle);
	statcollector_del(handle);

	/* some drivers don't support D2, so force them state = 3 and D3 */
	pm_state = NDIS_PM_STATE_D3;
	/* use copy; query_power changes this value */
	i = pm_state;
	/*
	res = miniport_query_int(handle, NDIS_OID_PNP_QUERY_POWER, &i);
	DBGTRACE2("%s: query power to state %d returns %08X",
		  dev->name, pm_state, res);
	if (res)
		WARNING("No pnp capabilities for pm (%08X)", res);
	*/

	/*
	res = set_int(handle, NDIS_OID_PNP_SET_POWER, pm_state);
	DBGTRACE2("%s: setting power to state %d returns %08X",
		  dev->name, pm_state, res);
	if (res)
		WARNING("No pnp capabilities for pm (%08X)", res);
	*/
	set_bit(HW_SUSPENDED, &handle->hw_status);

	DBGTRACE2("%s: device suspended", dev->name);
	return 0;
}

int ndis_resume_usb(struct usb_interface *intf)
{
	struct net_device *dev;
	struct ndis_handle *handle =
		(struct ndis_handle *)usb_get_intfdata(intf);
	struct miniport_char *miniport;
//	unsigned long profile_inf = NDIS_POWER_PROFILE_AC;

	if (!handle)
		return -1;
	dev = handle->net_dev;

	if (!test_bit(HW_SUSPENDED, &handle->hw_status))
		return 0;

	/*
	res = set_int(handle, NDIS_OID_PNP_SET_POWER, NDIS_PM_STATE_D0);
	DBGTRACE2("%s: setting power to state %d returns %d",
	     dev->name, NDIS_PM_STATE_D0, res);
	if (res)
		WARNING("No pnp capabilities for pm (%08X)", res);
	*/

	miniport = &handle->driver->miniport_char;
	/*
	if (miniport->pnp_event_notify)
	{
		INFO("%s", "calling pnp_event_notify");
		miniport->pnp_event_notify(handle, NDIS_PNP_PROFILE_CHANGED,
					 &profile_inf, sizeof(profile_inf));
	}
	*/

	/*
	if (miniport->hangcheck && miniport->hangcheck(handle->adapter_ctx))
	{
		DBGTRACE2("%s", "resetting device");
		miniport_reset(handle);
	}
	*/
	miniport_set_int(handle, NDIS_OID_BSSID_LIST_SCAN, 0);

	set_bit(SET_ESSID, &handle->wrapper_work);
	schedule_work(&handle->wrapper_worker);

	//netif_device_attach(dev);

	hangcheck_add(handle);
	statcollector_add(handle);
	clear_bit(HW_SUSPENDED, &handle->hw_status);
	DBGTRACE2("%s: device resumed", dev->name);
	return 0;
}
#endif

#if 0
static void resubmit_device_config(struct ndis_handle *handle)
{
	unsigned int i, written, needed;

	for (i = 0; i < MAX_ENCR_KEYS; i++)
		if (handle->encr_info.keys[i].length != 0) {
			miniport_set_info(handle, NDIS_OID_ADD_WEP,
					  (char *)&handle->encr_info.keys[i],
					  sizeof(struct encr_key),
					  &written, &needed);
			set_encr_mode(handle, ENCR1_ENABLED);
		}

	set_auth_mode(handle, handle->auth_mode);
	set_essid(handle, handle->essid.essid,
	          handle->essid.length);
}
#endif

/* worker procedure to take care of setting/checking various states */
static void wrapper_worker_proc(void *param)
{
	struct ndis_handle *handle = (struct ndis_handle *)param;

	DBGTRACE("%lu\n", handle->wrapper_work);

	if (test_bit(SHUTDOWN, &handle->wrapper_work))
		return;

	if (test_and_clear_bit(SET_OP_MODE, &handle->wrapper_work))
		set_mode(handle, handle->op_mode);

	if (test_and_clear_bit(WRAPPER_LINK_STATUS, &handle->wrapper_work))
	{
		struct ndis_assoc_info *ndis_assoc_info;
		unsigned char *wpa_assoc_info, *assoc_info, *p, *ies;
		union iwreq_data wrqu;
		unsigned int i, res, written, needed;
		const int assoc_size = sizeof(*ndis_assoc_info) +
			 IW_CUSTOM_MAX;

		if (handle->link_status == 0) {
//			for (i = 0; i < MAX_ENCR_KEYS; i++)
//				handle->encr_info.keys[i].length = 0;

			memset(&wrqu, 0, sizeof(wrqu));
			wrqu.ap_addr.sa_family = ARPHRD_ETHER;
			wireless_send_event(handle->net_dev, SIOCGIWAP, &wrqu,
					    NULL);
			DBGTRACE1("%s", "disassociate_event");
			return;
		}

		if (!test_bit(CAPA_WPA, &handle->capa))
			return;

		assoc_info = kmalloc(assoc_size, GFP_KERNEL);
		if (!assoc_info)
		{
			ERROR("%s", "couldn't allocate memory");
			return;
		}
		memset(assoc_info, 0, assoc_size);

		ndis_assoc_info = (struct ndis_assoc_info *)assoc_info;
		ndis_assoc_info->length = sizeof(*ndis_assoc_info);
		ndis_assoc_info->offset_req_ies = sizeof(*ndis_assoc_info);
		ndis_assoc_info->req_ie_length = IW_CUSTOM_MAX / 2;
		ndis_assoc_info->offset_resp_ies = sizeof(*ndis_assoc_info) +
			ndis_assoc_info->req_ie_length;
		ndis_assoc_info->resp_ie_length = IW_CUSTOM_MAX / 2;

		res = miniport_query_info(handle, NDIS_OID_ASSOC_INFO,
					  assoc_info,
					  assoc_size, &written, &needed);
		if (res || !written)
		{
			DBGTRACE("query assoc_info failed (%08X)", res);
			kfree(assoc_info);
			return;
		}

		/* we need 28 extra bytes for the format strings */
		if ((ndis_assoc_info->req_ie_length +
		     ndis_assoc_info->resp_ie_length + 28) > IW_CUSTOM_MAX)
		{
			WARNING("information element is too long! (%lu,%lu),"
				"association information dropped",
				ndis_assoc_info->req_ie_length,
				ndis_assoc_info->resp_ie_length);
			kfree(assoc_info);
			return;
		}

		wpa_assoc_info = kmalloc(IW_CUSTOM_MAX, GFP_KERNEL);
		if (!wpa_assoc_info)
		{
			ERROR("%s", "couldn't allocate memory");
			kfree(assoc_info);
			return;
		}
		p = wpa_assoc_info;
		p += sprintf(p, "ASSOCINFO(ReqIEs=");
		ies = ((char *)ndis_assoc_info) +
			ndis_assoc_info->offset_req_ies;
		for (i = 0; i < ndis_assoc_info->req_ie_length; i++)
			p += sprintf(p, "%02x", ies[i]);

		p += sprintf(p, " RespIEs=");
		ies = ((char *)ndis_assoc_info) +
			ndis_assoc_info->offset_resp_ies;
		for (i = 0; i < ndis_assoc_info->resp_ie_length; i++)
			p += sprintf(p, "%02x", ies[i]);

		p += sprintf(p, ")");

		memset(&wrqu, 0, sizeof(wrqu));
		wrqu.data.length = p - wpa_assoc_info;
		DBGTRACE("adding %d bytes", wrqu.data.length);
		wireless_send_event(handle->net_dev, IWEVCUSTOM, &wrqu,
				    wpa_assoc_info);

		kfree(wpa_assoc_info);
		kfree(assoc_info);

		get_ap_address(handle, (char *)&wrqu.ap_addr.sa_data);
		wrqu.ap_addr.sa_family = ARPHRD_ETHER;
		wireless_send_event(handle->net_dev, SIOCGIWAP, &wrqu, NULL);

		DBGTRACE1("%s", "associate_event");
	}

	if (test_and_clear_bit(SET_ESSID, &handle->wrapper_work))
		set_essid(handle, handle->essid.essid, handle->essid.length);
}

/* check capabilites - mainly for WPA */
static void check_capa(struct ndis_handle *handle)
{
	int i, mode;
	unsigned int res, written, needed;
	struct ndis_assoc_info ndis_assoc_info;
	struct ndis_wpa_key ndis_key;

	TRACEENTER1("%s", "");

	/* check if WEP is supported */
	if (set_encr_mode(handle, ENCR1_ENABLED) ||
	    miniport_query_int(handle, NDIS_OID_ENCR_STATUS, &i))
		;
	else
		set_bit(CAPA_WEP, &handle->capa);

	/* check if WPA is supported */
	set_encr_mode(handle, ENCR_DISABLED);
	DBGTRACE2("%s", "");
	if (set_auth_mode(handle, AUTHMODE_WPA) ||
	    miniport_query_int(handle, NDIS_OID_AUTH_MODE, &i) ||
	    i != AUTHMODE_WPA)
		TRACEEXIT1(return);

	/* check for highest encryption */
	for (mode = ENCR3_ENABLED; mode != ENCR_DISABLED; )
	{
		DBGTRACE("checking encryption mode %d", mode);
		if (set_encr_mode(handle, mode) ||
		    miniport_query_int(handle, NDIS_OID_ENCR_STATUS, &i))
			i = ENCR_DISABLED;

		if (mode == ENCR3_ENABLED)
		{
			if (i == mode || i == ENCR3_ABSENT)
				break;
			else
				mode = ENCR2_ENABLED;
		}
		else if (mode == ENCR2_ENABLED)
		{
			if (i == mode || i == ENCR2_ABSENT)
				break;
			else
				mode = ENCR1_ENABLED;
		}
		else
			mode = ENCR_DISABLED;
	}
	DBGTRACE("highest encryption mode supported = %d", mode);
	set_encr_mode(handle, mode);

	if (mode == ENCR_DISABLED)
		TRACEEXIT1(return);

	set_bit(CAPA_WEP, &handle->capa);
	if (mode == ENCR1_ENABLED)
		TRACEEXIT1(return);

	ndis_key.length = 32;
	ndis_key.index = 0xC0000001;
	ndis_key.struct_size = sizeof(ndis_key);
	res = miniport_set_info(handle, NDIS_OID_ADD_KEY, (char *)&ndis_key,
				ndis_key.struct_size, &written, &needed);

	DBGTRACE("add key returns %08X, needed = %d, size = %d\n",
		 res, needed, sizeof(ndis_key));
	if (res != NDIS_STATUS_INVALID_DATA)
		TRACEEXIT1(return);
	res = miniport_query_info(handle, NDIS_OID_ASSOC_INFO,
				  (char *)&ndis_assoc_info,
				  sizeof(ndis_assoc_info), &written, &needed);
	DBGTRACE("assoc info returns %d", res);
	if (res == NDIS_STATUS_NOT_SUPPORTED)
		TRACEEXIT1(return);

	set_bit(CAPA_WPA, &handle->capa);
	if (mode == ENCR3_ENABLED)
		set_bit(CAPA_AES, &handle->capa);
	set_bit(CAPA_TKIP, &handle->capa);

	TRACEEXIT1(return);
}

int ndis_reinit(struct ndis_handle *handle)
{
	/* instead of implementing full shutdown/restart, we (ab)use
	 * suspend/resume functionality */

	int i = test_bit(ATTR_HALT_ON_SUSPEND, &handle->attributes);
	set_bit(ATTR_HALT_ON_SUSPEND, &handle->attributes);
	if (handle->device->bustype == 5) {
		ndis_suspend_pci(handle->dev.pci, 3);
		ndis_resume_pci(handle->dev.pci);
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0) && defined(CONFIG_USB)
	else {
		ndis_suspend_usb(handle->intf, 3);
		ndis_resume_usb(handle->intf);
	}
#endif
	if (!i)
		clear_bit(ATTR_HALT_ON_SUSPEND, &handle->attributes);
	return 0;
}

int ndis_set_mac_addr(struct net_device *dev, void *p)
{
	struct ndis_handle *handle = netdev_priv(dev);
	struct sockaddr *addr = p;
	struct ndis_config_param param;
	struct ustring key, ansi;
	unsigned int ret;
	unsigned char mac_string[3 * ETH_ALEN];
	
	/* string <-> ansi <-> unicode conversion is driving me nuts */
	ansi.buf = "mac_address";
	ansi.buflen = ansi.len = strlen(ansi.buf);
	if (RtlAnsiStringToUnicodeString(&key, &ansi, 1))
		TRACEEXIT1(return -EINVAL);

	if (mac_to_string(mac_string, addr->sa_data, sizeof(mac_string))) {
		RtlFreeUnicodeString(&key);
		TRACEEXIT1(return -EINVAL);
	}
	ansi.buf = mac_string;
	ansi.buflen = ansi.len = sizeof(mac_string);
	if (RtlAnsiStringToUnicodeString(&param.data.ustring, &ansi, 1) !=
	    NDIS_STATUS_SUCCESS) {
		RtlFreeUnicodeString(&key);
		TRACEEXIT1(return -EINVAL);
	}
	param.type = NDIS_SETTING_STRING;
	NdisWriteConfiguration(&ret, handle, &key, &param);
	if (ret != NDIS_STATUS_SUCCESS)
		TRACEEXIT1(return -EINVAL);
	ndis_reinit(handle);
	memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);
	RtlFreeUnicodeString(&key);
	RtlFreeUnicodeString(&param.data.ustring);
	TRACEEXIT1(return 0);
}

static int setup_dev(struct net_device *dev)
{
	struct ndis_handle *handle = dev->priv;
	unsigned int i, res, written, needed;
	mac_address mac;
	union iwreq_data wrqu;

	if (strlen(if_name) > (IFNAMSIZ-1))
	{
		ERROR("interface name '%s' is too long", if_name);
		return -1;
	}
	strncpy(dev->name, if_name, IFNAMSIZ-1);
	dev->name[IFNAMSIZ-1] = '\0';

	DBGTRACE1("%s: Querying for mac", DRV_NAME);
	res = miniport_query_info(handle, OID_802_3_CURRENT_ADDRESS,
				  &mac[0], sizeof(mac), &written, &needed);
	DBGTRACE1("mac:" MACSTR, MAC2STR(mac));
	if (res) {
		ERROR("%s", "unable to get mac address from driver");
		return -EINVAL;
	}
	memcpy(&dev->dev_addr, mac, ETH_ALEN);

	memset(&wrqu, 0, sizeof(wrqu));

	miniport_set_int(handle, NDIS_OID_POWER_MODE, NDIS_POWER_OFF);
	set_mode(handle, NDIS_MODE_INFRA);
	set_essid(handle, handle->essid.essid, handle->essid.length);

	res = miniport_query_int(handle, OID_802_3_MAXIMUM_LIST_SIZE, &i);
	if(res == NDIS_STATUS_SUCCESS)
	{
		DBGTRACE1("Multicast list size is %d", i);
		handle->multicast_list_size = i;
	}

	if(handle->multicast_list_size)
		handle->multicast_list =
			kmalloc(handle->multicast_list_size * 6, GFP_KERNEL);

	if (set_privacy_filter(handle, NDIS_PRIV_ACCEPT_ALL))
		WARNING("%s", "Unable to set privacy filter");

	ndis_set_rx_mode_proc(dev);

	dev->open = ndis_open;
	dev->hard_start_xmit = start_xmit;
	dev->stop = ndis_close;
	dev->get_stats = ndis_get_stats;
	dev->do_ioctl = ndis_ioctl;
	dev->get_wireless_stats = get_wireless_stats;
	dev->wireless_handlers	= (struct iw_handler_def *)&ndis_handler_def;
	dev->set_multicast_list = ndis_set_rx_mode;
	dev->set_mac_address = ndis_set_mac_addr;
#ifdef HAVE_ETHTOOL
	dev->ethtool_ops = &ndis_ethtool_ops;
#endif
	if (handle->ndis_irq)
		dev->irq = handle->ndis_irq->irq;
	dev->mem_start = handle->mem_start;
	dev->mem_end = handle->mem_end;

	res = register_netdev(dev);
	if (res)
	{
		ERROR("cannot register net device %s", dev->name);
		return res;
	}

	printk(KERN_INFO "%s: %s ethernet device " MACSTR " using driver %s\n",
	       dev->name, DRV_NAME, MAC2STR(dev->dev_addr),
	       handle->driver->name);

	check_capa(handle);

	DBGTRACE("capbilities = %ld", handle->capa);
	printk(KERN_INFO "%s: encryption modes supported: %s%s%s\n",
	       dev->name,
	       test_bit(CAPA_WEP, &handle->capa) ? "WEP" : "none",
	       test_bit(CAPA_TKIP, &handle->capa) ? ", WPA with TKIP" : "",
	       test_bit(CAPA_AES, &handle->capa) ? ", WPA with AES/CCMP" : "");

	/* check_capa changes auth_mode and encr_mode, so set them again */
	set_mode(handle, NDIS_MODE_INFRA);
	set_auth_mode(handle, AUTHMODE_OPEN);
	set_encr_mode(handle, ENCR_DISABLED);

	/* some cards (e.g., RaLink) need a scan before they can associate */
	miniport_set_int(handle, NDIS_OID_BSSID_LIST_SCAN, 0);

	return 0;
}

static struct net_device *ndis_init_netdev(struct ndis_handle **phandle,
                                           struct ndis_device *device,
                                           struct ndis_driver *driver,
					   void *netdev)
{
	int i, *ip;
	struct net_device *dev;
	struct ndis_handle *handle;

	dev = alloc_etherdev(sizeof(*handle));
	if(!dev) {
		ERROR("%s", "Unable to alloc etherdev");
		return NULL;
	}

	SET_MODULE_OWNER(dev);
	if (netdev)
		SET_NETDEV_DEV(dev, netdev);

	handle = dev->priv;
	/* Poision the fileds as they may contain function pointers
	 * which my be called by the driver */
	for (i = 0, ip = (int *)handle->fill1;
	     (void *)&ip[i] < (void *)&handle->dev.pci; i++)
		ip[i] = 0x1000+i;

	handle->driver = driver;
	handle->device = device;
	handle->net_dev = dev;
	handle->ndis_irq = NULL;

	init_MUTEX(&handle->ndis_comm_mutex);
	init_waitqueue_head(&handle->ndis_comm_wq);
	handle->ndis_comm_done = 0;

	handle->send_status = 0;
	handle->send_packet = NULL;

	wrap_spin_lock_init(&handle->send_packet_lock);
	wrap_spin_lock_init(&handle->send_packet_done_lock);

	INIT_WORK(&handle->xmit_work, xmit_bh, handle);
	wrap_spin_lock_init(&handle->xmit_ring_lock);
	handle->xmit_ring_start = 0;
	handle->xmit_ring_pending = 0;

	handle->encr_mode = ENCR_DISABLED;
	handle->auth_mode = AUTHMODE_OPEN;
	handle->capa = 0;
	handle->attributes = 0;

	wrap_spin_lock_init(&handle->recycle_packets_lock);
	INIT_LIST_HEAD(&handle->recycle_packets);

	handle->reset_status = 0;

	INIT_WORK(&handle->recycle_packets_work, packet_recycler, handle);

	INIT_WORK(&handle->set_rx_mode_work, ndis_set_rx_mode_proc, dev);

	INIT_LIST_HEAD(&handle->timers);
	spin_lock_init(&handle->timers_lock);

	handle->rx_packet = &NdisMIndicateReceivePacket;
	handle->send_complete = &NdisMSendComplete;
	handle->send_resource_avail = &NdisMSendResourcesAvailable;
	handle->status = &NdisMIndicateStatus;
	handle->status_complete = &NdisMIndicateStatusComplete;
	handle->query_complete = &NdisMQueryInformationComplete;
	handle->set_complete = &NdisMSetInformationComplete;
	handle->reset_complete = &NdisMResetComplete;
	handle->eth_rx_indicate = &EthRxIndicateHandler;
	handle->eth_rx_complete = &EthRxComplete;
	handle->td_complete = &NdisMTransferDataComplete;
	handle->driver->miniport_char.adapter_shutdown = NULL;

	handle->map_count = 0;
	handle->map_dma_addr = NULL;

	handle->nick[0] = 0;

	handle->hangcheck_interval = hangcheck_interval;
	handle->hangcheck_active = 0;
	handle->scan_timestamp = 0;

	memset(&handle->essid, 0, sizeof(handle->essid));
	memset(&handle->encr_info, 0, sizeof(handle->encr_info));

	handle->op_mode = IW_MODE_INFRA;

	INIT_WORK(&handle->wrapper_worker, wrapper_worker_proc, handle);

	handle->phys_device_obj = NULL;

	*phandle = handle;
	return dev;
}

/*
 * Called by PCI-subsystem for each PCI-card found.
 *
 * This function should not be marked __devinit because ndiswrapper
 * adds PCI_id's dynamically.
 */
static int ndis_init_one_pci(struct pci_dev *pdev,
                             const struct pci_device_id *ent)
{
	int res = 0;
	struct ndis_device *device = (struct ndis_device *) ent->driver_data;
	struct ndis_driver *driver = device->driver;
	struct ndis_handle *handle;
	struct net_device *dev;
	struct miniport_char *miniport;

	TRACEENTER1("%04x:%04x:%04x:%04x", ent->vendor, ent->device,
		    ent->subvendor, ent->subdevice);
	if(device->fuzzy)
	{
		printk(KERN_WARNING "This driver (%s) is not for your "
		       "hardware. It's likely to work anyway but have it in "
		       "mind if you have problem.\n", device->driver->name);
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	dev = ndis_init_netdev(&handle, device, driver, &pdev->dev);
#else
	dev = ndis_init_netdev(&handle, device, driver, NULL);
#endif
	if(!dev)
	{
		printk(KERN_ERR "Unable to alloc etherdev\n");
		res = -ENOMEM;
		goto out_nodev;
	}

	handle->dev.pci = pdev;
	pci_set_drvdata(pdev, handle);

	res = pci_enable_device(pdev);
	if(res)
		goto out_enable;

	res = pci_request_regions(pdev, driver->name);
	if(res)
		goto out_regions;

	pci_set_power_state(pdev, 0);
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,9)
	pci_restore_state(pdev, NULL);
#endif

	DBGTRACE1("%s", "Calling ndis init routine");
	if((res = miniport_init(handle)))
	{
		ERROR("Windows driver couldn't initialize the device (%08X)",
			res);
		res = -EINVAL;
		goto out_start;
	}

	handle->hw_status = 0;
	handle->wrapper_work = 0;

	/* do we need to power up the card explicitly? */
	miniport_set_int(handle, NDIS_OID_PNP_SET_POWER, NDIS_PM_STATE_D0);
	miniport = &handle->driver->miniport_char;
	/* According NDIS, pnp_event_notify should be called whenever power
	 * is set to D0
	 * Only NDIS 5.1 drivers are required to supply this function; some
	 * drivers don't seem to support it (at least Orinoco)
	 */
	/*
	if (miniport->pnp_event_notify)
	{
		INFO("%s", "calling pnp_event_notify");
		miniport->pnp_event_notify(handle, NDIS_PNP_PROFILE_CHANGED,
					 &profile_inf, sizeof(profile_inf));
	}
	*/

	miniport_reset(handle);

	/* Wait a little to let card power up otherwise ifup might fail after
	   boot */
	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(HZ);

	if(setup_dev(handle->net_dev))
	{
		ERROR("%s", "Couldn't setup interface");
		res = -EINVAL;
		goto out_setup;
	}
	hangcheck_add(handle);
	statcollector_add(handle);
	ndiswrapper_procfs_add_iface(handle);
	TRACEEXIT1(return 0);

out_setup:
	miniport_halt(handle);
out_start:
	pci_release_regions(pdev);
out_regions:
	pci_disable_device(pdev);
out_enable:
	free_netdev(dev);
out_nodev:
	TRACEEXIT1(return res);
}

/*
 * Called by USB-subsystem for each USB device found.
 *
 * This function should not be marked __devinit because ndiswrapper
 * adds id's dynamically.
 */
#ifdef CONFIG_USB
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
static int ndis_init_one_usb(struct usb_interface *intf,
                             const struct usb_device_id *usb_id)
#else
static void *ndis_init_one_usb(struct usb_device *udev, unsigned int ifnum,
                               const struct usb_device_id *usb_id)
#endif
{
	int res;
	struct ndis_device *device =
		(struct ndis_device *)usb_id->driver_info;
	struct ndis_driver *driver = device->driver;
	struct ndis_handle *handle;
	struct net_device *dev;
	struct miniport_char *miniport;
//	unsigned long profile_inf = NDIS_POWER_PROFILE_AC;

	TRACEENTER1("%04x:%04x\n", usb_id->idVendor, usb_id->idProduct);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	dev = ndis_init_netdev(&handle, device, driver, &intf->dev);
#else
	dev = ndis_init_netdev(&handle, device, driver, NULL);
#endif
	if(!dev) {
		ERROR("%s", "Unable to alloc etherdev\n");
		res = -ENOMEM;
		goto out_nodev;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	handle->dev.usb = interface_to_usbdev(intf);
	handle->intf    = intf;
	usb_set_intfdata(intf, handle);
#else
	handle->dev.usb = udev;
#endif

	TRACEENTER1("%s", "Calling ndis init routine");
	if((res = miniport_init(handle)))
	{
		ERROR("Windows driver couldn't initialize the device (%08X)",
			res);
		res = -EINVAL;
		goto out_start;
	}

	handle->hw_status = 0;
	handle->wrapper_work = 0;

	/* do we need to power up the card explicitly? */
	miniport_set_int(handle, NDIS_OID_PNP_SET_POWER, NDIS_PM_STATE_D0);
	miniport = &handle->driver->miniport_char;
	/*
	if (miniport->pnp_event_notify)
	{
		INFO("%s", "calling pnp_event_notify");
		miniport->pnp_event_notify(handle->adapter_ctx, NDIS_PNP_PROFILE_CHANGED,
					 &profile_inf, sizeof(profile_inf));
		INFO("%s", "done");
	}
	*/

	miniport_reset(handle);
	/* wait here seems crucial; without this delay, at least 
	 * prism54 driver crashes (why?) */
	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(3*HZ);
	
	if(setup_dev(handle->net_dev)) {
		ERROR("%s", "Couldn't setup interface");
		res = -EINVAL;
		goto out_setup;
	}
	hangcheck_add(handle);
	statcollector_add(handle);
	ndiswrapper_procfs_add_iface(handle);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	TRACEEXIT1(return 0);
#else
	TRACEEXIT1(return handle);
#endif

out_setup:
	miniport_halt(handle);
out_start:
	free_netdev(dev);
out_nodev:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	TRACEEXIT1(return res);
#else
	TRACEEXIT1(return NULL);
#endif
}
#endif /* CONFIG_USB */

static void ndis_remove_one(struct ndis_handle *handle)
{
	struct miniport_char *miniport = &handle->driver->miniport_char;

	ndiswrapper_procfs_remove_iface(handle);
	statcollector_del(handle);
	hangcheck_del(handle);

	if (!netif_queue_stopped(handle->net_dev))
	{
		netif_stop_queue(handle->net_dev);
		DBGTRACE1("%d, %p",
			  test_bit(ATTR_SURPRISE_REMOVE, &handle->attributes),
			  miniport->pnp_event_notify);
		if (test_bit(ATTR_SURPRISE_REMOVE, &handle->attributes) &&
		    miniport->pnp_event_notify)
		{
			miniport->pnp_event_notify(handle->adapter_ctx,
						   NDIS_PNP_SURPRISE_REMOVED,
						   NULL, 0);
		}
	}

	wrap_spin_lock(&handle->xmit_ring_lock);
	while (handle->xmit_ring_pending)
	{
		struct ndis_buffer *buffer;

		buffer = handle->xmit_ring[handle->xmit_ring_start];
		kfree(buffer->data);
		kfree(buffer);
		handle->xmit_ring_start =
			(handle->xmit_ring_start + 1) % XMIT_RING_SIZE;
		handle->xmit_ring_pending--;
	}
	wrap_spin_unlock(&handle->xmit_ring_lock);
		
	/* Make sure all queued packets have been pushed out from
	 * xmit_bh before we call halt */
//	flush_scheduled_work();
	
	netif_carrier_off(handle->net_dev);

	if (handle->phys_device_obj)
		kfree(handle->phys_device_obj);

	set_bit(SHUTDOWN, &handle->wrapper_work);

#ifndef DEBUG_CRASH_ON_INIT
	miniport_set_int(handle, NDIS_OID_DISASSOCIATE, 0);
	miniport_halt(handle);

	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(HZ);
	printk(KERN_INFO "%s: device %s removed\n", DRV_NAME,
	       handle->net_dev->name);
	if (handle->net_dev)
		unregister_netdev(handle->net_dev);

	if (handle->multicast_list)
		kfree(handle->multicast_list);
	if (handle->net_dev)
		free_netdev(handle->net_dev);
#endif
}

/*
 * Remove one PCI-card.
 */
static void __devexit ndis_remove_one_pci(struct pci_dev *pdev)
{
	struct ndis_handle *handle =
		(struct ndis_handle *)pci_get_drvdata(pdev);

	DBGTRACE("\n%s\n", __FUNCTION__);

	ndis_remove_one(handle);

	pci_release_regions(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
}

/*
 * Remove one USB device.
 */
#ifdef CONFIG_USB
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
static void __devexit ndis_remove_one_usb(struct usb_interface *intf)
{
	struct ndis_handle *handle =
		(struct ndis_handle *)usb_get_intfdata(intf);

	DBGTRACE("\n%s\n", __FUNCTION__);

	ndis_remove_one(handle);
}
#else
static void __devexit ndis_remove_one_usb(struct usb_device *udev, void *ptr)
{
	struct ndis_handle *handle = (struct ndis_handle *)ptr;

	DBGTRACE("\n%s\n", __FUNCTION__);

	ndis_remove_one(handle);
}
#endif
#endif /* CONFIG_USB */

/* Register one ndis driver with pci subsystem. */
static int start_driver(struct ndis_driver *driver)
{
	int res = 0;
	int i;
	struct ndis_device *device;

	if(call_entry(driver))
	{
		ERROR("%s", "Driver entry returns error");
		return -EINVAL;
	}

	DBGTRACE1("Nr devices: %d", driver->nr_devices);

	if (driver->bustype == 5) { /* PCI */
		driver->idtable.pci = kmalloc(
			sizeof(struct pci_device_id)*(driver->nr_devices+1),
			GFP_KERNEL);
		if(!driver->idtable.pci)
			return -ENOMEM;
		memset(driver->idtable.pci, 0,
			sizeof(struct pci_device_id)*(driver->nr_devices+1));

		device = (struct ndis_device*) driver->devices.next;
		for(i = 0; i < driver->nr_devices; i++) {
			driver->idtable.pci[i].vendor = device->vendor;
			driver->idtable.pci[i].device = device->device;
			driver->idtable.pci[i].subvendor =
				device->pci_subvendor;
			driver->idtable.pci[i].subdevice =
				device->pci_subdevice;
			driver->idtable.pci[i].class = 0;
			driver->idtable.pci[i].class_mask = 0;
			driver->idtable.pci[i].driver_data =
				(unsigned long) device;

			DBGTRACE1("Adding %04x:%04x:%04x:%04x to pci idtable",
			          device->vendor, device->device,
			          device->pci_subvendor,
			          device->pci_subdevice);

			device = (struct ndis_device*) device->list.next;
		}

		memset(&driver->driver.pci, 0, sizeof(driver->driver.pci));
		driver->driver.pci.name = driver->name;
		driver->driver.pci.id_table = driver->idtable.pci;
		driver->driver.pci.probe = ndis_init_one_pci;
		driver->driver.pci.remove = __devexit_p(ndis_remove_one_pci);
		driver->driver.pci.suspend = ndis_suspend_pci;
		driver->driver.pci.resume = ndis_resume_pci;
#ifndef DEBUG_CRASH_ON_INIT
		res = pci_module_init(&driver->driver.pci);
		if(!res)
			driver->dev_registered = 1;
#endif
	}
	else { /* USB */
#ifdef CONFIG_USB
		driver->idtable.usb =
			kmalloc(sizeof(struct usb_device_id) * 
			        (driver->nr_devices+1), GFP_KERNEL);
		if(!driver->idtable.usb)
			return -ENOMEM;
		memset(driver->idtable.usb, 0,
		       sizeof(struct usb_device_id)*(driver->nr_devices+1));

		device = (struct ndis_device*) driver->devices.next;
		for(i = 0; i < driver->nr_devices; i++)
		{
			driver->idtable.usb[i].match_flags = USB_DEVICE_ID_MATCH_DEVICE;
			driver->idtable.usb[i].idVendor = device->vendor;
			driver->idtable.usb[i].idProduct = device->device;
			driver->idtable.usb[i].driver_info = (unsigned long) device;

			DBGTRACE1("Adding %04x:%04x to usb idtable\n",
			          device->vendor, device->device);

			device = (struct ndis_device*) device->list.next;
		}

		memset(&driver->driver.usb, 0, sizeof(driver->driver.usb));
		driver->driver.usb.name = driver->name;
		driver->driver.usb.id_table = driver->idtable.usb;
		driver->driver.usb.probe = ndis_init_one_usb;
		driver->driver.usb.disconnect =
			__devexit_p(ndis_remove_one_usb);
#if 0
/* Currently, suspend/resume is experimental for USB and therefore disabled.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)*/
		driver->driver.usb.suspend = ndis_suspend_usb;
		driver->driver.usb.resume = ndis_resume_usb;
#endif
		res = usb_register(&driver->driver.usb);
		if(!res)
			driver->dev_registered = 1;
#else  /* !CONFIG_USB */
		printk(KERN_ERR "Driver requires an unsupported bus type\n");
		return -EINVAL;
#endif /* CONFIG_USB */
	}

	return res;
}

/* Load the driver from userspace. */
static struct ndis_driver *load_driver(struct driver_files *driver_files)
{
	struct ndis_driver *driver;
	int i;

	TRACEENTER1("%p", driver_files);
	driver = kmalloc(sizeof(struct ndis_driver), GFP_KERNEL);
	if(!driver)
	{
		ERROR("unable to allocate memory for driver '%s'",
			driver_files->name);
		TRACEEXIT1(return 0);
	}
	memset(driver, 0, sizeof(struct ndis_driver));
	driver->bustype = -1;

	INIT_LIST_HEAD(&driver->devices);
	INIT_LIST_HEAD(&driver->files);

	driver->num_pe_images = driver_files->count;
	DBGTRACE1("num_pe_images = %d", driver->num_pe_images);
	if (driver->num_pe_images > MAX_PE_IMAGES)
		driver->num_pe_images = MAX_PE_IMAGES;
	DBGTRACE1("driver: %s", driver_files->name);
	strncpy(driver->name, driver_files->name,
				DRIVERNAME_MAX);
	DBGTRACE1("driver: %s", driver->name);
	for (i = 0; i < driver->num_pe_images; i++) {
		driver->pe_images[i].name = kmalloc(DRIVERNAME_MAX,
						    GFP_KERNEL);
		if (!driver->pe_images[i].name) {
			ERROR("couldn't allocate memory for driver '%s'",
				driver_files->name);
			goto out_image_fail;
		}
		memcpy(driver->pe_images[i].name, driver_files->file[i].name, 
			DRIVERNAME_MAX);
		driver->pe_images[i].name[DRIVERNAME_MAX-1] = 0;

		DBGTRACE1("image size: %d bytes", driver_files->file[i].size);

		driver->pe_images[i].image = 
			vmalloc(driver_files->file[i].size);
		DBGTRACE1("image is at %08X", (int)driver->pe_images[i].image);
		if(!driver->pe_images[i].image) {
			ERROR("couldn't allocate memory for driver '%s'",
				driver_files->name);
			goto out_image_fail;
		}

		if (copy_from_user(driver->pe_images[i].image,
				   driver_files->file[i].data,
				   driver_files->file[i].size)) {
			ERROR("failed to copy from user for driver '%s'",
				driver_files->name);
			goto out_image_fail;
		}
		driver->pe_images[i].size = driver_files->file[i].size;
	}

	if (load_pe_images(driver->pe_images, driver->num_pe_images)) {
		ERROR("unable to prepare driver '%s'", driver_files->name);
		goto out_image_fail;
	}

	TRACEEXIT1(return driver);

out_image_fail:
	for (i = 0; i < driver->num_pe_images; i++)
		if (driver->pe_images[i].image)
			vfree(driver->pe_images[i].image);
	kfree(driver);
	TRACEEXIT1(return 0);
}

/*
 * Add driver to list of loaded driver but make sure this driver is
 * not loaded before.
 */
static int add_driver(struct ndis_driver *driver)
{
	struct ndis_driver *tmp;
	int dup = 0;

	wrap_spin_lock(&driverlist_lock);
	list_for_each_entry(tmp, &ndis_driverlist, list)
	{
		if(strcmp(tmp->name, driver->name) == 0)
		{
			dup = 1;
			break;
		}
	}
	if(!dup)
		list_add(&driver->list, &ndis_driverlist);
	wrap_spin_unlock(&driverlist_lock);
	if(dup)
	{
		ERROR("%s", "Cannot add duplicate driver");
		return -EBUSY;
	}

	return 0;
}

/* Load a file from userspace and put on list of files. */
static int add_file(struct ndis_driver *driver, struct put_file *put_file)
{
	struct ndis_file *file;
	int namelen;

	TRACEENTER1("Putting file size %d", put_file->size);

	file = kmalloc(sizeof(struct ndis_file), GFP_KERNEL);
	if(!file)
	{
		ERROR("%s", "Unable to allocate memory");
		goto err;
	}
	memset(file, 0, sizeof(struct ndis_file));

	namelen = sizeof(put_file->name);
	if(sizeof(file->name) < namelen)
		namelen = sizeof(file->name);

	strncpy(file->name, put_file->name, namelen-1);
	file->name[namelen-1] = 0;
	file->size = put_file->size;

	file->data = vmalloc(put_file->size);
	if(!file->data)
	{
		ERROR("%s", "Unable to allocate memory");
		goto err;
	}

	if(copy_from_user(file->data, put_file->data, put_file->size))
	{
		ERROR("%s", "failed to copy from user");
		goto err;
	}

	list_add(&file->list, &driver->files);

	TRACEEXIT1(return 0);
err:
	if(file)
	{
		if(file->data)
			vfree(file->data);
		kfree(file);
	}
	TRACEEXIT1(return -ENOMEM);
}

/* Add a new device to a driver. */
static struct ndis_device *add_device(struct ndis_driver *driver,
				      struct put_device *put_device)
{
	struct ndis_device *device;

	if ((driver->bustype >= 0) &&
	    (driver->bustype != put_device->bustype)) {
		ERROR("%s", "Each driver can only support a single bustype");
		return NULL;
	}

	if (!(device = kmalloc(sizeof(*device), GFP_KERNEL)))
		return NULL;

	memset(device, 0, sizeof(*device));
	INIT_LIST_HEAD(&device->settings);

	device->bustype = put_device->bustype;
	device->vendor = put_device->vendor;
	device->device = put_device->device;
	device->pci_subvendor = put_device->pci_subvendor;
	device->pci_subdevice = put_device->pci_subdevice;
	device->fuzzy = put_device->fuzzy;

	if (device->bustype == 5)               /* 5: PCI */
	{
		DBGTRACE1("PCI:%04x:%04x:%04x:%04x %d", device->vendor,
		          device->device, device->pci_subvendor,
		          device->pci_subdevice, device->fuzzy);

		if (put_device->pci_subvendor == -1) {
			device->pci_subvendor = PCI_ANY_ID;
			device->pci_subdevice = PCI_ANY_ID;
			list_add_tail(&device->list, &driver->devices);
		} else {
			list_add(&device->list, &driver->devices);
		}
	} else if (device->bustype == 0) {      /* 0: USB */
		DBGTRACE1("USB:%04x:%04x\n", device->vendor, device->device);
		list_add(&device->list, &driver->devices);
	} else {
		kfree(device);
		return NULL;
	}

	driver->bustype = device->bustype;

	return device;
}

/* Add setting to the list of settings for the device. */
static int add_setting(struct ndis_device *device,
		       struct put_setting *put_setting)
{
	struct ndis_setting *setting;

	if (put_setting->val_str_len > MAX_NDIS_SETTING_VAL_LENGTH)
		return -EINVAL;

	setting = kmalloc(sizeof(*setting), GFP_KERNEL);
	if (!setting)
		return -ENOMEM;

	memset(setting, 0, sizeof(*setting));

	setting->name = kmalloc(put_setting->name_len+1, GFP_KERNEL);
	if (!setting->name) {
		kfree(setting);
		return -EINVAL;
	}

	setting->name[put_setting->name_len] = 0;
	if (copy_from_user(setting->name, put_setting->name,
			   put_setting->name_len) ||
	    copy_from_user(setting->value, put_setting->value,
			   put_setting->val_str_len)) {
		kfree(setting);
		kfree(setting->name);
		return -EINVAL;
	}

	setting->value[put_setting->val_str_len] = 0;
	setting->config_param.type = NDIS_SETTING_NONE;

	if (strcmp(setting->name, "ndis_version") == 0) {
		memcpy(device->driver->version, setting->value,
		       put_setting->val_str_len);
		device->driver->version[put_setting->val_str_len] = 0;
		kfree(setting->name);
		kfree(setting);
	}
	else
		list_add(&setting->list, &device->settings);
	return 0;
	
}

/* Delete a device and all info about it. */
static void delete_device(struct ndis_device *device)
{
	struct list_head *curr, *tmp2;

	TRACEENTER1("%s", "");
	list_for_each_safe(curr, tmp2, &device->settings)
	{
		struct ndis_setting *setting = (struct ndis_setting*) curr;
		if (setting->config_param.type == NDIS_SETTING_STRING &&
		    setting->config_param.data.ustring.buf)
			RtlFreeUnicodeString(&setting->config_param.data.ustring);
		kfree(setting->name);
		kfree(setting);
	}
	kfree(device);
	TRACEEXIT1(return);
}

/* Delete a driver. This implies deleting all cards for the handle too. */
static void unload_driver(struct ndis_driver *driver)
{
	struct list_head *curr, *tmp2;
	int i;

	if (driver->dev_registered) {
		if (driver->bustype == 5)
			pci_unregister_driver(&driver->driver.pci);
#ifdef CONFIG_USB
		else
			usb_deregister(&driver->driver.usb);
#endif
	}
#ifdef DEBUG_CRASH_ON_INIT
	if (driver->bustype == 5) {
		struct pci_dev *pdev = 0;
		pdev = pci_find_device(driver->idtable.pci[0].vendor,
				       driver->idtable.pci[0].device, pdev);
		if(pdev)
			ndis_remove_one_pci(pdev);
	}
#endif
	wrap_spin_lock(&driverlist_lock);
	if(driver->list.next)
		list_del(&driver->list);
	wrap_spin_unlock(&driverlist_lock);

	for (i = 0; i < driver->num_pe_images; i++)
		if(driver->pe_images[i].image)
			vfree(driver->pe_images[i].image);

	/* note: applies to all types of drivers */
	if (driver->idtable.pci)
		kfree(driver->idtable.pci);

	list_for_each_safe(curr, tmp2, &driver->files)
	{
		struct ndis_file *file = (struct ndis_file*) curr;
		DBGTRACE1("Deleting file %s", file->name);
		vfree(file->data);
		kfree(file);
	}

	list_for_each_safe(curr, tmp2, &driver->devices)
	{
		struct ndis_device *device = (struct ndis_device*) curr;
		delete_device(device);
	}
	kfree(driver);
}

/*
 * Called when userspace closes the filehandle for the misc device.
 * Check and remove any half-loaded drivers.
 */
static int misc_release(struct inode *inode, struct file *file)
{
	if(!file->private_data)
		return 0;

	TRACEENTER1("%s", "Removing partially loaded driver");
	unload_driver((struct ndis_driver *)file->private_data);
	file->private_data = 0;
	TRACEEXIT1(return 0);
}

static int misc_ioctl(struct inode *inode, struct file *file,
		      unsigned int cmd, unsigned long arg)
{
	struct put_file put_file;
	struct put_device put_device;
	int res = -1;
	struct ndis_device *device = NULL;
	struct ndis_driver *driver = (struct ndis_driver*) file->private_data;
	struct driver_files driver_files;

	TRACEENTER1("%u", cmd);
	if(driver)
		device = driver->current_device;

	switch(cmd) {
	case NDIS_PUTDRIVER:
		DBGTRACE1("%s", "putting driver");
		if (copy_from_user(&driver_files, (void*)arg,
				   sizeof(struct driver_files)))
			return -EINVAL;
		else
		{
			driver = load_driver(&driver_files);
			if(!driver)
				return -EINVAL;
			file->private_data = driver;

			driver->version[0] = 0;
			return add_driver(driver);
		}
		break;
	case NDIS_PUTFILE:
		if (!driver)
			return -EINVAL;
		DBGTRACE1("%s", "putting file");
		if(copy_from_user(&put_file, (void*)arg,
				  sizeof(struct put_file)))
			return -EINVAL;
		else
		{
			return add_file(driver, &put_file);
		}
		break;

	case NDIS_PUTDEVICE:
		if (!driver)
			return -EINVAL;

		DBGTRACE1("%s", "putting device");
		if(copy_from_user(&put_device, (void*)arg,
				  sizeof(struct put_device)))
			return -EINVAL;
		else
		{
			if (!(device = add_device(driver, &put_device)))
				return -EINVAL;
			driver->current_device = device;
			driver->nr_devices++;
			device->driver = driver;
		}
		break;

	case NDIS_STARTDRIVER:
		if (!driver)
			return -EINVAL;
		else
		{
			DBGTRACE1("%s", "starting driver");
			res = start_driver(driver);
#ifdef DEBUG_CRASH_ON_INIT
			if (driver->bustype == 5) {
				struct pci_dev *pdev = 0;
				pdev = pci_find_device(
					driver->idtable.pci[0].vendor,
					driver->idtable.pci[0].device, pdev);
				if (pdev)
					ndis_init_one_pci(pdev,
						&driver->idtable.pci[0]);
			}
#endif
			file->private_data = NULL;

			if (res)
				unload_driver(driver);
			else
				printk(KERN_INFO "%s: driver %s (%s) added\n",
				       DRV_NAME, driver->name, driver->version);
			return res;
		}
		break;
	case NDIS_PUTSETTING:
		if (!device)
			return -EINVAL;
		else
		{
			struct put_setting put_setting;
			if (copy_from_user(&put_setting, (void*)arg,
					  sizeof(struct put_setting)))
				return -EINVAL;
			return add_setting(device, &put_setting);
		}
		break;
	default:
		ERROR("Unknown ioctl %08X", cmd);
		return -EINVAL;
		break;
	}

	return 0;
}

static struct file_operations wrapper_fops = {
	.owner          = THIS_MODULE,
	.ioctl		= misc_ioctl,
	.release	= misc_release
};

static struct miscdevice wrapper_misc = {
	.name   = DRV_NAME,
	.fops   = &wrapper_fops
};

void module_cleanup(void)
{
	struct ndis_driver *driver;

	while (!list_empty(&ndis_driverlist))
	{
		driver = (struct ndis_driver*) ndis_driverlist.next;
		unload_driver(driver);
	}

	ndiswrapper_procfs_remove();
	misc_deregister(&wrapper_misc);
	wrap_kfree_all();
}

static int __init wrapper_init(void)
{
#if defined DEBUG && DEBUG >= 1
	char *argv[] = {"loadndisdriver", "1", NDISWRAPPER_VERSION, "-a", 0};
#else
	char *argv[] = {"loadndisdriver", "0", NDISWRAPPER_VERSION, "-a", 0};
#endif
	char *env[] = {0};
	int err;

	printk(KERN_INFO "%s version %s%s loaded (preempt=%s,smp=%s)\n",
	       DRV_NAME, NDISWRAPPER_VERSION, EXTRA_VERSION,
#if defined CONFIG_PREEMPT
	       "yes",
#else
	       "no",
#endif
#ifdef CONFIG_SMP
	       "yes"
#else
	       "no"
#endif
		);
	if ( (err = misc_register(&wrapper_misc)) < 0 ) {
		ERROR("misc_register failed (%d)", err);
		return err;
	}

	ndis_init();
	INIT_LIST_HEAD(&wrap_allocs);
	INIT_LIST_HEAD(&handle_ctx_list);
	wrap_spin_lock_init(&wrap_allocs_lock);
	wrap_spin_lock_init(&driverlist_lock);
	wrap_spin_lock_init(&dispatch_event_lock);
	ndiswrapper_procfs_init();
	DBGTRACE1("%s", "calling loadndisdriver");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	err = call_usermodehelper("/sbin/loadndisdriver", argv, env, 1);
#else
	err = call_usermodehelper("/sbin/loadndisdriver", argv, env);
#endif

	if (err)
	{
		ERROR("loadndiswrapper failed (%d); check system log "
		      "for messages from 'loadndisdriver'", err);
		module_cleanup();
		return -EPERM;
	}
	return 0;
}

static void __exit wrapper_exit(void)
{
	module_cleanup();
}

module_init(wrapper_init);
module_exit(wrapper_exit);

MODULE_LICENSE("GPL");
