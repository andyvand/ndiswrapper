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
#include "pe_linker.h"
#include "iw_ndis.h"
#include "loader.h"

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

extern struct list_head wrap_allocs;
extern struct wrap_spinlock wrap_allocs_lock;
extern struct wrap_spinlock dispatch_event_lock;

static void ndis_set_rx_mode(struct net_device *dev);

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
	if (res == NDIS_STATUS_PENDING) {
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

	if (res == NDIS_STATUS_SUCCESS && handle->reset_status) {
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
	if (res == NDIS_STATUS_PENDING) {
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

	if (res == NDIS_STATUS_PENDING) {
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
	if (miniport->init == NULL) {
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

	if (handle->device->bustype == NDIS_PCI_BUS)
		pci_set_power_state(handle->dev.pci, 3);
	TRACEEXIT1(return);
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

	wrap_spin_lock(&handle->timers_lock);
	if (handle->hangcheck_active) {
		handle->hangcheck_timer.expires =
			jiffies + handle->hangcheck_interval;
		add_timer(&handle->hangcheck_timer);
	}
	wrap_spin_unlock(&handle->timers_lock);

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

	wrap_spin_lock(&handle->timers_lock);
	handle->hangcheck_active = 0;
	del_timer(&handle->hangcheck_timer);
	wrap_spin_unlock(&handle->timers_lock);
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

void statcollector_add(struct ndis_handle *handle)
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
	     i++, mclist = mclist->next) {
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
	} else if ((dev->mc_count > handle->multicast_list_size) ||
		   (dev->flags & IFF_ALLMULTI) ||
		   (handle->multicast_list == 0)) {
		/* Too many to filter perfectly -- accept all multicasts. */
		DBGTRACE1("%s", "Multicast list to long. Accepting all\n");
		packet_filter |= NDIS_PACKET_TYPE_ALL_MULTICAST;
	} else if (dev->mc_count > 0) {
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
static void ndis_set_rx_mode(struct net_device *dev)
{
	struct ndis_handle *handle = dev->priv;
	schedule_work(&handle->set_rx_mode_work);
}

static struct ndis_packet *alloc_packet(struct ndis_handle *handle,
				       struct ndis_buffer *buffer)
{
	struct ndis_packet *packet;

	packet = kmalloc(sizeof(struct ndis_packet), GFP_ATOMIC);
	if (!packet)
		return NULL;

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
		for (i = 0; i <= 12; i++)
			x[i] = i;
	}
#endif

	if (handle->use_scatter_gather) {
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

static void free_packet(struct ndis_handle *handle, struct ndis_packet *packet)
{
	kfree(packet->buffer_head->data);
	kfree(packet->buffer_head);

	if (packet->dataphys) {
		/* FIXME: do USB drivers call this? */
		PCI_DMA_UNMAP_SINGLE(handle->dev.pci, packet->dataphys,
				     packet->len, PCI_DMA_TODEVICE);
	}

	kfree(packet);
}

/*
 * MiniportSend and MiniportSendPackets
 * this function is called from bh disabled context, so no need to raise
 * irql to DISPATCH_LEVEL during MiniportSend(Packets)
 */
static int send_packets(struct ndis_handle *handle, unsigned int start,
			unsigned int pending)
{
	int res;
	struct miniport_char *miniport = &handle->driver->miniport_char;
	unsigned int sent, n;

	TRACEENTER3("handle = %p", handle);

	if (miniport->send_packets) {
		unsigned int i;
		if (pending > handle->max_send_packets)
			n = handle->max_send_packets;
		else
			n = pending;
		if (n > 1)
			DBGTRACE3("sending %d packets", n);

		/* copy packets from xmit_ring to linear xmit_array array */
		for (i = 0; i < n; i++) {
			int j = (start + i) % XMIT_RING_SIZE;
			handle->xmit_array[i] = handle->xmit_ring[j];
		}
		miniport->send_packets(handle->adapter_ctx,
				       handle->xmit_array, n);
		if (test_bit(ATTR_SERIALIZED, &handle->attributes)) {
			for (sent = 0; sent < n && !handle->send_status;
			     sent++) {
				switch(handle->xmit_array[sent]->status) {
				case NDIS_STATUS_SUCCESS:
					sendpacket_done(handle,
							handle->xmit_array[sent]);
					break;
				case NDIS_STATUS_PENDING:
					break;
				case NDIS_STATUS_RESOURCES:
					handle->send_status =
						NDIS_STATUS_RESOURCES;
					break;
				case NDIS_STATUS_FAILURE:
				default:
					free_packet(handle,
						    handle->xmit_array[sent]);
					break;
				}
			}
		} else
			sent = n;
	} else {
		struct ndis_packet *packet = handle->xmit_ring[start];
		res = miniport->send(handle->adapter_ctx, packet, 0);

		sent = 1;
		switch (res) {
		case NDIS_STATUS_SUCCESS:
			sendpacket_done(handle, packet);
			break;
		case NDIS_STATUS_PENDING:
			break;
		case NDIS_STATUS_RESOURCES:
			handle->send_status = res;
			sent = 0;
			break;
		case NDIS_STATUS_FAILURE:
			free_packet(handle, packet);
			break;
		}
	}
	TRACEEXIT3(return sent);
}

static void xmit_worker(void *param)
{
	struct ndis_handle *handle = (struct ndis_handle *)param;
	int n;

	TRACEENTER3("send status is %08X", handle->send_status);

	while (handle->send_status == 0) {
		wrap_spin_lock(&handle->xmit_ring_lock);
		if (handle->xmit_ring_pending == 0) {
			wrap_spin_unlock(&handle->xmit_ring_lock);
			break;
		}
		n = send_packets(handle, handle->xmit_ring_start,
				 handle->xmit_ring_pending);
		handle->xmit_ring_start =
			(handle->xmit_ring_start + n) % XMIT_RING_SIZE;
		handle->xmit_ring_pending -= n;
		wrap_spin_unlock(&handle->xmit_ring_lock);
		if (netif_queue_stopped(handle->net_dev))
			netif_wake_queue(handle->net_dev);
	}

	TRACEEXIT3(return);
}

/*
 * Free and unmap a packet created in xmit
 * This function should be called while holding send_packet_lock
 */
void sendpacket_done(struct ndis_handle *handle, struct ndis_packet *packet)
{
	TRACEENTER3("%s", "");
	wrap_spin_lock(&handle->send_packet_done_lock);
	handle->stats.tx_bytes += packet->len;
	handle->stats.tx_packets++;
	free_packet(handle, packet);
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
	struct ndis_packet *packet;
	unsigned int xmit_ring_next_slot;

	char *data = kmalloc(skb->len, GFP_ATOMIC);
	if (!data)
		return 1;

	buffer = kmalloc(sizeof(struct ndis_buffer), GFP_ATOMIC);
	if (!buffer) {
		kfree(data);
		return 1;
	}

	skb_copy_and_csum_dev(skb, data);
	buffer->data = data;
	buffer->next = 0;
	buffer->len = skb->len;
	packet = alloc_packet(handle, buffer);
	if (!packet) {
		kfree(buffer);
		kfree(data);
		return 1;
	}
	dev_kfree_skb(skb);

	wrap_spin_lock(&handle->xmit_ring_lock);
	xmit_ring_next_slot =
		(handle->xmit_ring_start +
		 handle->xmit_ring_pending) % XMIT_RING_SIZE;
	handle->xmit_ring[xmit_ring_next_slot] = packet;
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

	if (test_bit(ATTR_HALT_ON_SUSPEND, &handle->attributes)) {
		DBGTRACE2("%s", "driver requests halt_on_suspend");
		miniport_halt(handle);
		set_bit(HW_HALTED, &handle->hw_status);
	} else {
		/* some drivers don't support D2, so force them to and D3 */
		pm_state = NDIS_PM_STATE_D3;
		/* use copy; query_power changes this value */
		i = pm_state;
		res = miniport_query_int(handle, NDIS_OID_PNP_QUERY_POWER, &i);
		DBGTRACE2("%s: query power to state %d returns %08X",
			  dev->name, pm_state, res);
		if (res) {
			WARNING("No pnp capabilities for pm (%08X); halting",
				res);
			miniport_halt(handle);
			set_bit(HW_HALTED, &handle->hw_status);
		} else {
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
	else {
		res = miniport_set_int(handle, NDIS_OID_PNP_SET_POWER,
				       NDIS_PM_STATE_D0);
		DBGTRACE2("%s: setting power to state %d returns %d",
			 dev->name, NDIS_PM_STATE_D0, res);
		if (res)
			WARNING("No pnp capabilities for pm (%08X)", res);

		miniport = &handle->driver->miniport_char;
		/*
		if (miniport->pnp_event_notify) {
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
	if (miniport->pnp_event_notify) {
		INFO("%s", "calling pnp_event_notify");
		miniport->pnp_event_notify(handle, NDIS_PNP_PROFILE_CHANGED,
					 &profile_inf, sizeof(profile_inf));
	}
	*/

	/*
	if (miniport->hangcheck &&
	    miniport->hangcheck(handle->adapter_ctx)) {
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

void ndis_remove_one(struct ndis_handle *handle)
{
	struct miniport_char *miniport = &handle->driver->miniport_char;

	ndiswrapper_procfs_remove_iface(handle);
	statcollector_del(handle);
	hangcheck_del(handle);

	if (!netif_queue_stopped(handle->net_dev)) {
		netif_stop_queue(handle->net_dev);
		DBGTRACE1("%d, %p",
			  test_bit(ATTR_SURPRISE_REMOVE, &handle->attributes),
			  miniport->pnp_event_notify);
		if (test_bit(ATTR_SURPRISE_REMOVE, &handle->attributes) &&
		    miniport->pnp_event_notify) {
			miniport->pnp_event_notify(handle->adapter_ctx,
						   NDIS_PNP_SURPRISE_REMOVED,
						   NULL, 0);
		}
	}

	wrap_spin_lock(&handle->xmit_ring_lock);
	while (handle->xmit_ring_pending) {
		struct ndis_packet *packet;

		packet = handle->xmit_ring[handle->xmit_ring_start];
		free_packet(handle, packet);
		handle->xmit_ring_start =
			(handle->xmit_ring_start + 1) % XMIT_RING_SIZE;
		handle->xmit_ring_pending--;
	}
	wrap_spin_unlock(&handle->xmit_ring_lock);

	/* Make sure all queued packets have been pushed out from
	 * xmit_worker before we call halt */
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

static void reinit_encryption(struct ndis_handle *handle)
{
	unsigned int i;
	struct encr_info *encr_info = &handle->encr_info;

	TRACEENTER2("");

	if (handle->op_mode != NDIS_MODE_ADHOC)
		return;

	for (i = 0; i < MAX_ENCR_KEYS; i++) {
		if (encr_info->keys[i].length == 0)
			continue;
		if (add_wep_key(handle, encr_info->keys[i].key,
				encr_info->keys[i].length, i))
			WARNING("setting wep key %d failed", i);
	}

	/* FIXME: is it dangerous to set essid directly or schedule
	 * work again here? */
	set_bit(SET_ESSID, &handle->wrapper_work);
	schedule_work(&handle->wrapper_worker);
//	set_essid(handle, handle->essid.essid, handle->essid.length);
	TRACEEXIT2(return);
}

/* worker procedure to take care of setting/checking various states */
static void wrapper_worker_proc(void *param)
{
	struct ndis_handle *handle = (struct ndis_handle *)param;

	DBGTRACE2("%lu", handle->wrapper_work);

	if (test_bit(SHUTDOWN, &handle->wrapper_work))
		return;

	if (test_and_clear_bit(SET_OP_MODE, &handle->wrapper_work))
		set_mode(handle, handle->op_mode);

	if (test_and_clear_bit(WRAPPER_LINK_STATUS,
			       &handle->wrapper_work)) {
		struct ndis_assoc_info *ndis_assoc_info;
		unsigned char *wpa_assoc_info, *assoc_info, *p, *ies;
		union iwreq_data wrqu;
		unsigned int i, res, written, needed;
		const int assoc_size = sizeof(*ndis_assoc_info) +
			 IW_CUSTOM_MAX;

		DBGTRACE2("link status: %d", handle->link_status);
		if (handle->link_status == 0) {
			DBGTRACE2("%s", "disassociate_event");

			if (handle->op_mode == NDIS_MODE_ADHOC) {
				reinit_encryption(handle);
				return;
			}
			/* FIXME: not clear if NDIS says keys should
			 * be cleared here */
			for (i = 0; i < MAX_ENCR_KEYS; i++)
				handle->encr_info.keys[i].length = 0;

			if (netif_carrier_ok(handle->net_dev))
				netif_carrier_off(handle->net_dev);
			memset(&wrqu, 0, sizeof(wrqu));
			wrqu.ap_addr.sa_family = ARPHRD_ETHER;
			wireless_send_event(handle->net_dev, SIOCGIWAP, &wrqu,
					    NULL);
			return;
		}

		if (!netif_carrier_ok(handle->net_dev))
			netif_carrier_on(handle->net_dev);
		if (!test_bit(CAPA_WPA, &handle->capa))
			return;

		assoc_info = kmalloc(assoc_size, GFP_KERNEL);
		if (!assoc_info) {
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
		if (res || !written) {
			DBGTRACE2("query assoc_info failed (%08X)", res);
			kfree(assoc_info);
			return;
		}

		/* we need 28 extra bytes for the format strings */
		if ((ndis_assoc_info->req_ie_length +
		     ndis_assoc_info->resp_ie_length + 28) > IW_CUSTOM_MAX) {
			WARNING("information element is too long! (%lu,%lu),"
				"association information dropped",
				ndis_assoc_info->req_ie_length,
				ndis_assoc_info->resp_ie_length);
			kfree(assoc_info);
			return;
		}

		wpa_assoc_info = kmalloc(IW_CUSTOM_MAX, GFP_KERNEL);
		if (!wpa_assoc_info) {
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
		DBGTRACE2("adding %d bytes", wrqu.data.length);
		wireless_send_event(handle->net_dev, IWEVCUSTOM, &wrqu,
				    wpa_assoc_info);

		kfree(wpa_assoc_info);
		kfree(assoc_info);

		get_ap_address(handle, (char *)&wrqu.ap_addr.sa_data);
		wrqu.ap_addr.sa_family = ARPHRD_ETHER;
		wireless_send_event(handle->net_dev, SIOCGIWAP, &wrqu, NULL);
		DBGTRACE2("%s", "associate_event");
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
	for (mode = ENCR3_ENABLED; mode != ENCR_DISABLED; ) {
		DBGTRACE1("checking encryption mode %d", mode);
		if (set_encr_mode(handle, mode) ||
		    miniport_query_int(handle, NDIS_OID_ENCR_STATUS, &i))
			i = ENCR_DISABLED;

		if (mode == ENCR3_ENABLED) {
			if (i == mode || i == ENCR3_ABSENT)
				break;
			else
				mode = ENCR2_ENABLED;
		} else if (mode == ENCR2_ENABLED) {
			if (i == mode || i == ENCR2_ABSENT)
				break;
			else
				mode = ENCR1_ENABLED;
		} else
			mode = ENCR_DISABLED;
	}
	DBGTRACE1("highest encryption mode supported = %d", mode);
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

	DBGTRACE2("add key returns %08X, needed = %d, size = %d\n",
		 res, needed, sizeof(ndis_key));
	if (res != NDIS_STATUS_INVALID_DATA)
		TRACEEXIT1(return);
	res = miniport_query_info(handle, NDIS_OID_ASSOC_INFO,
				  (char *)&ndis_assoc_info,
				  sizeof(ndis_assoc_info), &written, &needed);
	DBGTRACE2("assoc info returns %d", res);
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
	if (handle->device->bustype == NDIS_PCI_BUS) {
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

static int ndis_set_mac_addr(struct net_device *dev, void *p)
{
	struct ndis_handle *handle = netdev_priv(dev);
	struct sockaddr *addr = p;
	struct ndis_config_param param;
	struct ustring key, ansi;
	unsigned int i, ret;
	unsigned char mac_string[3 * ETH_ALEN];
	mac_address mac;

	/* string <-> ansi <-> unicode conversion is driving me nuts */

	for (i = 0; i < sizeof(mac); i++)
		mac[i] = addr->sa_data[i];
	memset(mac_string, 0, sizeof(mac_string));
	ret = snprintf(mac_string, sizeof(mac_string), MACSTR,
		       MAC2STR(mac));
	DBGTRACE2("ret = %d, mac_tring = %s", ret, mac_string);
	if (ret != (sizeof(mac_string) - 1))
		TRACEEXIT1(return -EINVAL);

	ansi.buf = "mac_address";
	ansi.buflen = ansi.len = strlen(ansi.buf);
	if (RtlAnsiStringToUnicodeString(&key, &ansi, 1))
		TRACEEXIT1(return -EINVAL);

	ansi.buf = mac_string;
	ansi.buflen = ansi.len = sizeof(mac_string);
	if (RtlAnsiStringToUnicodeString(&param.data.ustring, &ansi, 1) !=
	    NDIS_STATUS_SUCCESS) {
		RtlFreeUnicodeString(&key);
		TRACEEXIT1(return -EINVAL);
	}
	param.type = NDIS_CONFIG_PARAM_STRING;
	NdisWriteConfiguration(&ret, handle, &key, &param);
	if (ret != NDIS_STATUS_SUCCESS)
		TRACEEXIT1(return -EINVAL);
	ndis_reinit(handle);
	memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);
	RtlFreeUnicodeString(&key);
	RtlFreeUnicodeString(&param.data.ustring);
	TRACEEXIT1(return 0);
}

int setup_dev(struct net_device *dev)
{
	struct ndis_handle *handle = dev->priv;
	unsigned int i, res, written, needed;
	mac_address mac;
	union iwreq_data wrqu;

	if (strlen(if_name) > (IFNAMSIZ-1)) {
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

	handle->max_send_packets = 1;
	if (handle->driver->miniport_char.send_packets) {
		res = miniport_query_int(handle, OID_GEN_MAXIMUM_SEND_PACKETS,
					 &handle->max_send_packets);
		DBGTRACE2("maximum send packets supported by driver: %d",
			  handle->max_send_packets);
		if (res == NDIS_STATUS_NOT_SUPPORTED)
			handle->max_send_packets = 1;
		else if (handle->max_send_packets > XMIT_RING_SIZE)
			handle->max_send_packets = XMIT_RING_SIZE;

		handle->xmit_array = kmalloc(sizeof(struct ndis_packet *) *
					     handle->max_send_packets,
					     GFP_KERNEL);
		if (!handle->xmit_array) {
			ERROR("couldn't allocate memory for tx_packets");
			return -EINVAL;
		}
	}
	DBGTRACE2("maximum send packets used by ndiswrapper: %d",
		  handle->max_send_packets);

	memset(&wrqu, 0, sizeof(wrqu));

	miniport_set_int(handle, NDIS_OID_POWER_MODE, NDIS_POWER_OFF);
	set_mode(handle, NDIS_MODE_INFRA);
	set_essid(handle, handle->essid.essid, handle->essid.length);

	res = miniport_query_int(handle, OID_802_3_MAXIMUM_LIST_SIZE, &i);
	if (res == NDIS_STATUS_SUCCESS) {
		DBGTRACE1("Multicast list size is %d", i);
		handle->multicast_list_size = i;
	}

	if (handle->multicast_list_size)
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
	if (res) {
		ERROR("cannot register net device %s", dev->name);
		return res;
	}

	printk(KERN_INFO "%s: %s ethernet device " MACSTR " using driver %s\n",
	       dev->name, DRV_NAME, MAC2STR(dev->dev_addr),
	       handle->driver->name);

	check_capa(handle);

	DBGTRACE1("capbilities = %ld", handle->capa);
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

struct net_device *ndis_init_netdev(struct ndis_handle **phandle,
				    struct ndis_device *device,
				    struct ndis_driver *driver,
				    void *netdev)
{
	int i, *ip;
	struct net_device *dev;
	struct ndis_handle *handle;

	dev = alloc_etherdev(sizeof(*handle));
	if (!dev) {
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

	INIT_WORK(&handle->xmit_work, xmit_worker, handle);
	wrap_spin_lock_init(&handle->xmit_ring_lock);
	handle->xmit_ring_start = 0;
	handle->xmit_ring_pending = 0;

	wrap_spin_lock_init(&handle->send_packet_done_lock);

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
	wrap_spin_lock_init(&handle->timers_lock);

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

static void module_cleanup(void)
{
	loader_exit();
	ndiswrapper_procfs_remove();
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

	ndis_init();
	loader_init();
	INIT_LIST_HEAD(&wrap_allocs);
	wrap_spin_lock_init(&wrap_allocs_lock);
	wrap_spin_lock_init(&dispatch_event_lock);
	ndiswrapper_procfs_init();
	DBGTRACE1("%s", "calling loadndisdriver");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	err = call_usermodehelper("/sbin/loadndisdriver", argv, env, 1);
#else
	err = call_usermodehelper("/sbin/loadndisdriver", argv, env);
#endif

	if (err) {
		ERROR("loadndiswrapper failed (%d); check system log "
		      "for messages from 'loadndisdriver'", err);
		module_cleanup();
		TRACEEXIT1(return -EPERM);
	}
	TRACEEXIT1(return 0);
}

static void __exit wrapper_exit(void)
{
	module_cleanup();
}

module_init(wrapper_init);
module_exit(wrapper_exit);

MODULE_LICENSE("GPL");
