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

#ifdef CONFIG_4K_STACKS
#warning Most windows drivers do not work with 4K stacks. \
	Disable 4K stack option (CONFIG_4K_STACKS) in the kernel; otherwise \
	most likely the kernel crashes.
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

MODULE_PARM(if_name, "s");
MODULE_PARM_DESC(if_name, "Network interface name or template (default: wlan%d)");
MODULE_PARM(proc_uid, "i");
MODULE_PARM_DESC(proc_uid, "The uid of the files created in /proc (default: 0).");
MODULE_PARM(proc_gid, "i");
MODULE_PARM_DESC(proc_gid, "The gid of the files created in /proc (default: 0).");
MODULE_PARM(hangcheck_interval, "i");
/* 0 - default value provided by NDIS driver,
 * positive value - force hangcheck interval to that many seconds
 * negative value - disable hangcheck
 */
MODULE_PARM_DESC(hangcheck_interval, "The interval, in seconds, for checking if driver is hung. (default: 0)");

/* List of loaded drivers */
LIST_HEAD(ndis_driverlist);

/* Protects driver list */
static struct wrap_spinlock driverlist_lock;

extern int image_offset;

extern struct list_head wrap_allocs;
extern struct wrap_spinlock wrap_allocs_lock;

extern struct list_head handle_ctx_list;

void ndis_set_rx_mode(struct net_device *dev);

int doreset(struct ndis_handle *handle)
{
	int res = 0;
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
	res = miniport->reset(&handle->reset_status, handle->adapter_ctx);

	DBGTRACE2("res = %08X, reset_status = %08X",
		  res, handle->reset_status);
	if (res == NDIS_STATUS_PENDING)
	{
		DBGTRACE2("%s", "waiting for reset_complete");
		/* reset is supposed to run at DISPATCH_LEVEL, so we busy wait
		 * for a while before sleeping, hoping reset will be done in
		 * 1 ms */
		mdelay(1);
		/* wait for NdisMResetComplete upto 30 s */
		if (!wait_event_interruptible_timeout(handle->ndis_comm_wq,
			   (handle->ndis_comm_done == 1), 30*HZ))
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
 * Perform a sync query and deal with the possibility of an async operation.
 * This function must be called from process context as it will sleep.
 */
int doquery(struct ndis_handle *handle, unsigned int oid, char *buf,
	    int bufsize, unsigned int *written , unsigned int *needed)
{
	int res;
	struct miniport_char *miniport = &handle->driver->miniport_char;

	TRACEENTER3("Calling query at %p rva(%08x)",
		    miniport->query, (int)miniport->query - image_offset);

	if (down_interruptible(&handle->ndis_comm_mutex))
		TRACEEXIT3(return NDIS_STATUS_FAILURE);

	handle->ndis_comm_done = 0;
	res = miniport->query(handle->adapter_ctx, oid, buf, bufsize,
			      written, needed);
	if (res == NDIS_STATUS_PENDING)
	{
		/* wait for NdisMQueryInformationComplete upto HZ */
		if (!wait_event_interruptible_timeout(handle->ndis_comm_wq,
			   (handle->ndis_comm_done == 1), HZ))
			handle->ndis_comm_res = NDIS_STATUS_FAILURE;
		res = handle->ndis_comm_res;
	}
	up(&handle->ndis_comm_mutex);
	TRACEEXIT3(return res);
}

/*
 * Perform a sync setinfo and deal with the possibility of an async operation.
 * This function must be called from process context as it will sleep.
 */
int dosetinfo(struct ndis_handle *handle, unsigned int oid, char *buf,
	      int bufsize, unsigned int *written , unsigned int *needed)
{
	int res;
	struct miniport_char *miniport = &handle->driver->miniport_char;

	TRACEENTER3("Calling setinfo at %p rva(%08x)",
		    miniport->setinfo, (int)miniport->setinfo - image_offset);

	if (down_interruptible(&handle->ndis_comm_mutex))
		TRACEEXIT3(return NDIS_STATUS_FAILURE);

	handle->ndis_comm_done = 0;
	res = miniport->setinfo(handle->adapter_ctx, oid, buf, bufsize,
			       written, needed);
	if (res == NDIS_STATUS_PENDING)
	{
		/* wait for NdisMSetInformationComplete upto HZ */
		if (!wait_event_interruptible_timeout(handle->ndis_comm_wq,
			   (handle->ndis_comm_done == 1), HZ))
			handle->ndis_comm_res = NDIS_STATUS_FAILURE;
		res = handle->ndis_comm_res;
	}
	up(&handle->ndis_comm_mutex);
	TRACEEXIT3(return res);
}

/* Make a query that has an int as the result. */
int query_int(struct ndis_handle *handle, int oid, int *data)
{
	unsigned int res, written, needed;

	res = doquery(handle, oid, (char*)data, sizeof(int),
		      &written, &needed);
	if (!res)
		return 0;
	*data = 0;
	return res;
}

/* Set an int */
int set_int(struct ndis_handle *handle, int oid, int data)
{
	unsigned int written, needed;

	return dosetinfo(handle, oid, (char*)&data, sizeof(int),
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

int call_init(struct ndis_handle *handle)
{
	__u32 res, res2;
	__u32 selected_medium;
	__u32 mediumtypes[] = {0,1,2,3,4,5,6,7,8,9,10,11,12};
	struct miniport_char *miniport = &handle->driver->miniport_char;

	TRACEENTER1("Calling NDIS driver init routine at %p rva(%08X)",
		    miniport->init, (int)miniport->init - image_offset);
	if (miniport->init == NULL)
	{
		ERROR("%s", "initialization function is not setup correctly");
		return -EINVAL;
	}
	res = miniport->init(&res2, &selected_medium, mediumtypes, 13, handle,
			     handle);
	DBGTRACE1("init returns %08X", res);
	return res != 0;
}

void call_halt(struct ndis_handle *handle)
{
	struct miniport_char *miniport = &handle->driver->miniport_char;
	TRACEENTER1("Calling NDIS driver halt at %p rva(%08X)",
		    miniport->halt, (int)miniport->halt - image_offset);

	set_int(handle, NDIS_OID_PNP_SET_POWER, NDIS_PM_STATE_D3);

	miniport->halt(handle->adapter_ctx);
	/* TI driver doesn't call NdisMDeregisterInterrupt during halt! */
	if (handle->ndis_irq)
	{
		if (miniport->disable_interrupts)
			miniport->disable_interrupts(handle->adapter_ctx);
		NdisMDeregisterInterrupt(handle->ndis_irq);
	}
	if (handle->device->bustype == 5)
		pci_set_power_state(handle->dev.pci, 3);
	TRACEEXIT1(return);
}

static void free_timers(struct ndis_handle *handle)
{
	char x;

	/* Cancel any timers left by bugyy windows driver
	 * Also free the memory for timers
	 */
	while (!list_empty(&handle->timers))
	{
		struct wrapper_timer *timer =
			(struct wrapper_timer*) handle->timers.next;
		DBGTRACE1("fixing up timer %p, timer->list %p",
			  timer, &timer->list);
		list_del(&timer->list);
		if (timer->active)
		{
			WARNING("%s", "Fixing an active timer left "
				" by buggy windows driver");
			wrapper_cancel_timer(timer, &x);
		}
		wrap_kfree(timer);
	}
}

static unsigned int call_entry(struct ndis_driver *driver)
{
	int res;
	char regpath[] = {'a', 0, 'b', 0, 0, 0};

	TRACEENTER1("Calling NDIS driver entry at %08X rva(%08X)",
		    (int)driver->entry, (int)driver->entry - image_offset);
	res = driver->entry((void*)driver, regpath);
	DBGTRACE1("Past entry: Version: %d.%dn",
		  driver->miniport_char.majorVersion,
		  driver->miniport_char.minorVersion);

	/* Dump addresses of driver suppoled callbacks */
#if defined DEBUG && DEBUG >= 1
	if(res == 0) {
		int i;
		int *adr = (int*) &driver->miniport_char.hangcheck;
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

		for(i = 0; i < 16; i++)
		{
			DBGTRACE1("%08X (rva %08X):%s", adr[i],
				  adr[i]?adr[i] - image_offset:0, name[i]);
		}
	}
#endif
	return res;
}

static void hangcheck_reinit(struct ndis_handle *handle);

static void hangcheck_bh(void *data)
{
	struct ndis_handle *handle = (struct ndis_handle *)data;

	TRACEENTER3("%s", "");
	if (handle->reset_status == 0 &&
	    handle->driver->miniport_char.hangcheck(handle->adapter_ctx))
	{
		int res;
		INFO("Hangcheck returned true. Resetting %s!",
		     handle->net_dev->name);
		res = doreset(handle);
		DBGTRACE3("reset returns %08X, %d", res, handle->reset_status);
	}
	TRACEEXIT3(return);
}

static void hangcheck_proc(unsigned long data)
{
	struct ndis_handle *handle = (struct ndis_handle *)data;
	schedule_work(&handle->hangcheck_work);
	hangcheck_reinit(handle);
}

static void hangcheck_reinit(struct ndis_handle *handle)
{
	handle->hangcheck_timer.data = (unsigned long) handle;
	handle->hangcheck_timer.function = &hangcheck_proc;
	handle->hangcheck_timer.expires = jiffies + handle->hangcheck_interval;
	add_timer(&handle->hangcheck_timer);

}

void hangcheck_add(struct ndis_handle *handle)
{
	if(!handle->driver->miniport_char.hangcheck ||
	   handle->hangcheck_interval <= 0)
		return;

	INIT_WORK(&handle->hangcheck_work, &hangcheck_bh, handle);
	init_timer(&handle->hangcheck_timer);
	hangcheck_reinit(handle);
}

void hangcheck_del(struct ndis_handle *handle)
{
	if(!handle->driver->miniport_char.hangcheck ||
	   handle->hangcheck_interval <= 0)
		return;

	del_timer_sync(&handle->hangcheck_timer);
}


static void statcollector_reinit(struct ndis_handle *handle);

static void statcollector_bh(void *data)
{
	struct ndis_handle *handle = (struct ndis_handle *)data;
	unsigned int res, written, needed;
	struct iw_statistics *iw_stats = &handle->wireless_stats;
	struct ndis_wireless_stats ndis_stats;
	long rssi;

	res = doquery(handle, NDIS_OID_RSSI, (char *)&rssi, sizeof(rssi),
		      &written, &needed);
	iw_stats->qual.level = rssi;

	memset(&ndis_stats, 0, sizeof(ndis_stats));
	res = doquery(handle, NDIS_OID_STATISTICS, (char *)&ndis_stats,
		      sizeof(ndis_stats), &written, &needed);
	if (res != NDIS_STATUS_NOT_SUPPORTED)
	{
		iw_stats->discard.retries = (__u32)ndis_stats.retry +
			(__u32)ndis_stats.multi_retry;
		iw_stats->discard.misc = (__u32)ndis_stats.fcs_err +
			(__u32)ndis_stats.rtss_fail +
			(__u32)ndis_stats.ack_fail +
			(__u32)ndis_stats.frame_dup;

		if (ndis_stats.tx_frag)
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
	INIT_WORK(&handle->statcollector_work, &statcollector_bh, handle);
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
 * doquery (or query_int) may not be called from this function as
 * it might sleep which is not allowed from the context this function
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

	res = dosetinfo(handle, OID_802_3_MULTICAST_LIST, list,
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

	res = dosetinfo(handle, NDIS_OID_PACKET_FILTER, (char *)&packet_filter,
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
		/* Poision extra packet info */
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

	packet->oob_offset = (int)(&packet->timesent1) - (int)packet;

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

static int send_packet(struct ndis_handle *handle, struct ndis_packet *packet)
{
	int res;
	struct miniport_char *miniport = &handle->driver->miniport_char;

	TRACEENTER3("packet = %p", packet);

	if (miniport->send_packets)
	{
		struct ndis_packet *packets[1];
		packets[0] = packet;
		miniport->send_packets(handle->adapter_ctx, &packets[0], 1);

		if (test_bit(ATTR_SERIALIZED, &handle->attributes))
		{
			/* Serialized miniports sets packet->status */
			res = packet->status;
		}
		else
		{
			/* Deserialized miniports always call NdisMSendComplete */
			res = NDIS_STATUS_PENDING;
		}
	}
	else if (miniport->send)
	{
		res = miniport->send(handle->adapter_ctx, packet, 0);
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
		call_halt(handle);
		set_bit(HW_HALTED, &handle->hw_status);
	}
	else
	{
		/* some drivers don't support D2, so force them to and D3 */
		pm_state = NDIS_PM_STATE_D3;
		/* use copy; query_power changes this value */
		i = pm_state;
		res = query_int(handle, NDIS_OID_PNP_QUERY_POWER, &i);
		DBGTRACE2("%s: query power to state %d returns %08X",
			  dev->name, pm_state, res);
		if (res)
		{
			WARNING("No pnp capabilities for pm (%08X); halting",
				res);
			call_halt(handle);
			set_bit(HW_HALTED, &handle->hw_status);
		}
		else
		{
			res = set_int(handle, NDIS_OID_PNP_SET_POWER,
				      pm_state);
			DBGTRACE2("suspending returns %08X", res);
			set_bit(HW_SUSPENDED, &handle->hw_status);
		}
	}
	pci_save_state(pdev, handle->pci_state);
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
	pci_restore_state(pdev, handle->pci_state);
	if (test_bit(HW_HALTED, &handle->hw_status))
		res = call_init(handle);
	else
	{
		res = set_int(handle, NDIS_OID_PNP_SET_POWER,
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

		if (miniport->hangcheck &&
		    miniport->hangcheck(handle->adapter_ctx))
		{
			DBGTRACE2("%s", "resetting device");
			doreset(handle);
		}
	}
	set_int(handle, NDIS_OID_BSSID_LIST_SCAN, 0);
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
	res = query_int(handle, NDIS_OID_PNP_QUERY_POWER, &i);
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
		doreset(handle);
	}
	*/
	set_int(handle, NDIS_OID_BSSID_LIST_SCAN, 0);

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

/* worker procedure to take care of setting/checking various states */
static void wrapper_worker_proc(void *param)
{
	struct ndis_handle *handle = (struct ndis_handle *)param;

	DBGTRACE("%lu\n", handle->wrapper_work);

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

		if (handle->link_status == 0)
		{
			int len;
			for (i = 0; i < MAX_ENCR_KEYS; i++)
			{
				len = sizeof(handle->encr_info.keys[i].length);
				handle->encr_info.keys[i].length = 0;
				memset(&handle->encr_info.keys[i].key[i], 0,
				       len);
			}
			return;
		}

		if (handle->auth_mode != AUTHMODE_WPA &&
		    handle->auth_mode != AUTHMODE_WPAPSK)
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

		res = doquery(handle, NDIS_OID_ASSOC_INFO, assoc_info,
			      assoc_size, &written, &needed);
		if (res || !written)
		{
			ERROR("query assoc_info failed (%08X)", res);
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
	if (set_auth_mode(handle, AUTHMODE_WPA) ||
	    query_int(handle, NDIS_OID_AUTH_MODE, &i) || i != AUTHMODE_WPA)
		TRACEEXIT1(return);

	/* check for highest encryption */
	for (mode = ENCR3_ENABLED; mode != ENCR_DISABLED; )
	{
		DBGTRACE("checking encryption mode %d", mode);
		if (set_encr_mode(handle, mode) ||
		    query_int(handle, NDIS_OID_ENCR_STATUS, &i))
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
	set_bit(mode, &handle->capa);
	set_encr_mode(handle, mode);

	if (handle->encr_mode == ENCR_DISABLED ||
	    handle->encr_mode == ENCR1_ENABLED)
	{
		printk(KERN_INFO "ndiswrapper device %s doesn't support WPA",
		       handle->net_dev->name);
		TRACEEXIT1(return);
	}

	ndis_key.length = 32;
	ndis_key.index = 0xC0000001;
	ndis_key.struct_size = sizeof(ndis_key);
	res = dosetinfo(handle, NDIS_OID_ADD_KEY, (char *)&ndis_key,
			ndis_key.struct_size, &written, &needed);

	DBGTRACE("add key returns %08X, needed = %d, size = %d\n",
		 res, needed, sizeof(ndis_key));
	if (res != NDIS_STATUS_INVALID_DATA)
		TRACEEXIT1(return);
	res = doquery(handle, NDIS_OID_ASSOC_INFO, (char *)&ndis_assoc_info,
		      sizeof(ndis_assoc_info), &written, &needed);
	DBGTRACE("assoc info returns %d", res);
	if (res == NDIS_STATUS_NOT_SUPPORTED)
		TRACEEXIT1(return);
	set_bit(CAPA_WPA, &handle->capa);

	DBGTRACE("capbilities = %ld", handle->capa);
	if (test_bit(CAPA_AES, &handle->capa))
		printk(KERN_INFO "ndiswrapper device %s supports WPA with "
		       "AES/CCMP and TKIP ciphers\n", handle->net_dev->name);
	else
		printk(KERN_INFO "ndiswrapper device %s supports "
		       " WPA with TKIP cipher\n", handle->net_dev->name);
	TRACEEXIT1(return);
}

static int setup_dev(struct net_device *dev)
{
	struct ndis_handle *handle = dev->priv;
	mac_address mac;
	unsigned int i, written, needed, res;
	union iwreq_data wrqu;

	if (strlen(if_name) > (IFNAMSIZ-1))
	{
		ERROR("interface name '%s' is too long", if_name);
		return -1;
	}
	strncpy(dev->name, if_name, IFNAMSIZ-1);
	dev->name[IFNAMSIZ-1] = '\0';

	DBGTRACE1("%s: Querying for mac", DRV_NAME);
	res = doquery(handle, 0x01010102, &mac[0], sizeof(mac),
		      &written, &needed);
	DBGTRACE1("mac:" MACSTR, MAC2STR(mac));

	if(res)
	{
		ERROR("%s", "unable to get mac address from driver");
		return -1;
	}

	memset(&wrqu, 0, sizeof(wrqu));

	set_mode(handle, NDIS_MODE_INFRA);
	set_essid(handle, handle->essid.essid, handle->essid.length);

	res = query_int(handle, OID_802_3_MAXIMUM_LIST_SIZE, &i);
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
#ifdef HAVE_ETHTOOL
	dev->ethtool_ops = &ndis_ethtool_ops;
#endif
	memcpy(&dev->dev_addr, mac, ETH_ALEN);
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
	       dev->name, DRV_NAME, MAC2STR(mac), handle->driver->name);

	check_capa(handle);
	/* check_capa changes auth_mode and encr_mode, so set them again */
	set_mode(handle, NDIS_MODE_INFRA);
	set_auth_mode(handle, AUTHMODE_OPEN);
	set_encr_mode(handle, ENCR_DISABLED);

	/* some cards (e.g., RaLink) need a scan before they can associate */
	set_int(handle, NDIS_OID_BSSID_LIST_SCAN, 0);

	return 0;
}

static struct net_device *ndis_init_netdev(struct ndis_handle **phandle,
                                           struct ndis_device *device,
                                           struct ndis_driver *driver)
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
//	SET_NETDEV_DEV(dev, &pdev->dev);

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

	dev = ndis_init_netdev(&handle, device, driver);
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
	pci_restore_state(pdev, NULL);

	DBGTRACE1("%s", "Calling ndis init routine");
	if(call_init(handle))
	{
		ERROR("%s", "Windows driver couldn't initialize the device");
		res = -EINVAL;
		goto out_start;
	}

	handle->hw_status = 0;
	handle->wrapper_work = 0;

	/* do we need to power up the card explicitly? */
	set_int(handle, NDIS_OID_PNP_SET_POWER, NDIS_PM_STATE_D0);
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

	/* SMC 2802W V2 cards need reset (any others need it too?) */
	if (ent->vendor == 0x1260)
		doreset(handle);

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
	call_halt(handle);
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

	dev = ndis_init_netdev(&handle, device, driver);
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
	if(call_init(handle)) {
		ERROR("%s", "Windows driver couldn't initialize the device");
		res = -EINVAL;
		goto out_start;
	}

	handle->hw_status = 0;
	handle->wrapper_work = 0;

	/* do we need to power up the card explicitly? */
	set_int(handle, NDIS_OID_PNP_SET_POWER, NDIS_PM_STATE_D0);
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

	/* WUSB54G requires it, maybe other USB drivers as well... */
	doreset(handle);

	if(setup_dev(handle->net_dev)) {
		ERROR("%s", "Couldn't setup interface");
		res = -EINVAL;
		goto out_setup;
	}
	hangcheck_add(handle);
	statcollector_add(handle);
	ndiswrapper_procfs_add_iface(handle);
	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(HZ);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	TRACEEXIT1(return 0);
#else
	TRACEEXIT1(return handle);
#endif

out_setup:
	call_halt(handle);
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
			DBGTRACE1("%s", "");
		}
	}

	/* Make sure all queued packets have been pushed out from
	 * xmit_bh before we call halt */
//	flush_scheduled_work();
	
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
		
	netif_carrier_off(handle->net_dev);

	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(HZ/2);
	if (handle->phys_device_obj)
		kfree(handle->phys_device_obj);

#ifndef DEBUG_CRASH_ON_INIT
	set_int(handle, NDIS_OID_DISASSOCIATE, 0);
	call_halt(handle);

	free_timers(handle);
	free_handle_ctx(handle);

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
static struct ndis_driver *load_driver(struct put_file *put_driver)
{
	void *entry;
	struct ndis_driver *driver;
	int namelen;

	TRACEENTER1("loading driver %s, size %d",
		    put_driver->name, put_driver->size);

	driver = kmalloc(sizeof(struct ndis_driver), GFP_KERNEL);
	if(!driver)
	{
		ERROR("%s", "unable to allocate memory");
		goto out_nodriver;
	}
	memset(driver, 0, sizeof(struct ndis_driver));
	driver->bustype = -1;

	INIT_LIST_HEAD(&driver->devices);
	INIT_LIST_HEAD(&driver->files);

	namelen = sizeof(put_driver->name);
	if(sizeof(driver->name) < namelen)
		namelen = sizeof(driver->name);

	strncpy(driver->name, put_driver->name, namelen-1);
	driver->name[namelen-1] = 0;

	driver->image = vmalloc(put_driver->size);
	DBGTRACE1("image is at %08X", (int)driver->image);
	if(!driver->image)
	{
		ERROR("%s", "unable to allocate memory");
		goto out_vmalloc;
	}

	if(copy_from_user(driver->image, put_driver->data, put_driver->size))
	{
		ERROR("%s", "failed to copy from user");
		goto out_baddriver;
	}

	if (load_pe_image(&entry, driver->image, put_driver->size))
	{
		ERROR("%s", "unable to prepare driver");
		goto out_baddriver;
	}
	driver->entry = entry;

	TRACEEXIT1(return driver);

out_baddriver:
	vfree(driver->image);
out_vmalloc:
	kfree(driver);
out_nodriver:
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
		ERROR("%s", "Failed to copy from user");
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

	if (!(setting = kmalloc(sizeof(*setting), GFP_KERNEL)))
		return -ENOMEM;

	memset(setting, 0, sizeof(*setting));

	if (!(setting->name = kmalloc(put_setting->name_len+1, GFP_KERNEL)))
		goto setting_fail;

	if (put_setting->val_str_len > MAX_NDIS_SETTING_VAL_LENGTH)
		goto name_fail;

	if(copy_from_user(setting->name, put_setting->name,
			  put_setting->name_len))
		goto name_fail;

	setting->name[put_setting->name_len] = 0;

	if(copy_from_user(setting->val_str, put_setting->value,
			  put_setting->val_str_len))
		goto name_fail;

	setting->val_str[put_setting->val_str_len] = 0;
	setting->value.type = NDIS_SETTING_NONE;

	if (strcmp(setting->name, "ndis_version") == 0)
	{
		if (put_setting->val_str_len > NDIS_VERSION_STRING_MAX)
			put_setting->val_str_len = NDIS_VERSION_STRING_MAX;

		memcpy(device->driver->version, setting->val_str,
		       put_setting->val_str_len);
		device->driver->version[put_setting->val_str_len] = 0;
		kfree(setting->name);
		kfree(setting);
	}
	else
		list_add(&setting->list, &device->settings);
	return 0;

name_fail:
	kfree(setting->name);
setting_fail:
	kfree(setting);
	return -EINVAL;
}

/* Delete a device and all info about it. */
static void delete_device(struct ndis_device *device)
{
	struct list_head *curr, *tmp2;

	TRACEENTER1("%s", "");
	list_for_each_safe(curr, tmp2, &device->settings)
	{
		struct ndis_setting *setting = (struct ndis_setting*) curr;
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

	if(driver->image)
		vfree(driver->image);

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

	if(driver)
		device = driver->current_device;

	switch(cmd) {
	case NDIS_PUTDRIVER:
		if(copy_from_user(&put_file, (void*)arg,
				  sizeof(struct put_file)))
			return -EINVAL;
		else
		{
			driver = load_driver(&put_file);
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

	init_ndis();
	INIT_LIST_HEAD(&wrap_allocs);
	INIT_LIST_HEAD(&handle_ctx_list);
	wrap_spin_lock_init(&wrap_allocs_lock);
	wrap_spin_lock_init(&driverlist_lock);
	ndiswrapper_procfs_init();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	err = call_usermodehelper("/sbin/loadndisdriver", argv, env, 1);
#else
	err = call_usermodehelper("/sbin/loadndisdriver", argv, env);
#endif

	if (err)
	{
		ERROR("loadndiswrapper failed (%d);"
		      "check utils version mismatch", err);
		module_cleanup();
		return -ENOEXEC;
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
