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
int miniport_query_info_needed(struct ndis_handle *handle, unsigned int oid,
			       char *buf, unsigned int bufsize,
			       unsigned int *needed)
{
	unsigned int res, written;
	KIRQL irql;
	struct miniport_char *miniport = &handle->driver->miniport_char;

	TRACEENTER3("query is at %p", miniport->query);

	if (down_interruptible(&handle->ndis_comm_mutex))
		TRACEEXIT3(return NDIS_STATUS_FAILURE);

	handle->ndis_comm_done = 0;
	irql = raise_irql(DISPATCH_LEVEL);
	res = miniport->query(handle->adapter_ctx, oid, buf, bufsize,
			      &written, needed);
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

int miniport_query_info(struct ndis_handle *handle, unsigned int oid,
			char *buf, unsigned int bufsize)
{
	unsigned int res, needed;

	res = miniport_query_info_needed(handle, oid, buf, bufsize,
					 &needed);
	return res;
}

/*
 * MiniportSetInformation
 * Perform a sync setinfo and deal with the possibility of an async operation.
 * This function must be called from process context as it will sleep.
 */
int miniport_set_info(struct ndis_handle *handle, unsigned int oid, char *buf,
		      unsigned int bufsize)
{
	unsigned int res, written, needed;
	KIRQL irql;
	struct miniport_char *miniport = &handle->driver->miniport_char;

	TRACEENTER3("setinfo is at %p", miniport->setinfo);

	if (down_interruptible(&handle->ndis_comm_mutex))
		TRACEEXIT3(return NDIS_STATUS_FAILURE);

	handle->ndis_comm_done = 0;
	irql = raise_irql(DISPATCH_LEVEL);
	res = miniport->setinfo(handle->adapter_ctx, oid, buf, bufsize,
			       &written, &needed);
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
	if (needed)
		DBGTRACE2("%s failed: bufsize: %d, written: %d, needed: %d",
			  __FUNCTION__, bufsize, written, needed);
	TRACEEXIT3(return res);
}

/* Make a query that has an int as the result. */
int miniport_query_int(struct ndis_handle *handle, int oid, int *data)
{
	unsigned int res;

	res = miniport_query_info(handle, oid, (char*)data, sizeof(int));
	if (!res)
		return 0;
	*data = 0;
	return res;
}

/* Set an int */
int miniport_set_int(struct ndis_handle *handle, int oid, int data)
{
	return miniport_set_info(handle, oid, (char *)&data, sizeof(int));
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
	NDIS_STATUS status;
	UINT medium_index, res;
	UINT medium_array[] = {NDIS_MEDIUM_802_3};
	struct miniport_char *miniport = &handle->driver->miniport_char;

	TRACEENTER1("driver init routine is at %p", miniport->init);
	if (miniport->init == NULL) {
		ERROR("%s", "initialization function is not setup correctly");
		return -EINVAL;
	}
	res = miniport->init(&status, &medium_index, medium_array,
			     sizeof(medium_array) / sizeof(medium_array[0]),
			     handle, handle);
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

	ndis_exit_handle(handle);

	if (handle->device->bustype == NDIS_PCI_BUS)
		pci_set_power_state(handle->dev.pci, 3);
	TRACEEXIT1(return);
}

static void hangcheck_proc(unsigned long data)
{
	struct ndis_handle *handle = (struct ndis_handle *)data;
	KIRQL irql;

	TRACEENTER3("%s", "");
	
	if (handle->reset_status == 0) {
		int res;
		struct miniport_char *miniport;

		miniport = &handle->driver->miniport_char;
		irql = raise_irql(DISPATCH_LEVEL);
		res = miniport->hangcheck(handle->adapter_ctx);
		lower_irql(irql);
		if (res) {
			WARNING("%s is being reset", handle->net_dev->name);
			res = miniport_reset(handle);
			DBGTRACE3("reset returns %08X, %d",
				  res, handle->reset_status);
		}
	}

	wrap_spin_lock(&handle->timers_lock, PASSIVE_LEVEL);
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

	wrap_spin_lock(&handle->timers_lock, PASSIVE_LEVEL);
	add_timer(&handle->hangcheck_timer);
	handle->hangcheck_active = 1;
	wrap_spin_unlock(&handle->timers_lock);
	return;
}

void hangcheck_del(struct ndis_handle *handle)
{
	if (!handle->driver->miniport_char.hangcheck ||
	    handle->hangcheck_interval <= 0)
		return;

	wrap_spin_lock(&handle->timers_lock, PASSIVE_LEVEL);
	handle->hangcheck_active = 0;
	del_timer(&handle->hangcheck_timer);
	wrap_spin_unlock(&handle->timers_lock);
}

static void stats_proc(unsigned long data)
{
	struct ndis_handle *handle = (struct ndis_handle *)data;

	set_bit(COLLECT_STATS, &handle->wrapper_work);
	schedule_work(&handle->wrapper_worker);
	handle->stats_timer.expires = jiffies + 2 * HZ;
	add_timer(&handle->stats_timer);
}

static void stats_timer_add(struct ndis_handle *handle)
{
	init_timer(&handle->stats_timer);
	handle->stats_timer.data = (unsigned long) handle;
	handle->stats_timer.function = &stats_proc;
	handle->stats_timer.expires = jiffies + 2 * HZ;
	add_timer(&handle->stats_timer);
}

static void stats_timer_del(struct ndis_handle *handle)
{
	wrap_spin_lock(&handle->timers_lock, PASSIVE_LEVEL);
	del_timer_sync(&handle->stats_timer);
	wrap_spin_unlock(&handle->timers_lock);
}

static int ndis_open(struct net_device *dev)
{
	TRACEENTER1("%s", "");
	netif_device_attach(dev);
	netif_start_queue(dev);
	return 0;
}

static int ndis_close(struct net_device *dev)
{
	TRACEENTER1("%s", "");

	if (netif_running(dev)) {
		netif_stop_queue(dev);
		netif_device_detach(dev);
	}

	return 0;
}

/*
 * query functions may not be called from this function as they might
 * sleep which is not allowed from the context this function is
 * running in.
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
	struct dev_mc_list *mclist;
	int i;
	char *list = handle->multicast_list;
	int size = 0, res;

	for (i = 0, mclist = dev->mc_list; mclist && i < dev->mc_count;
	     i++, mclist = mclist->next) {
		memcpy(list, mclist->dmi_addr, ETH_ALEN);
		list += ETH_ALEN;
		size += ETH_ALEN;
	}
	DBGTRACE1("%d entries. size=%d", dev->mc_count, size);

	res = miniport_set_info(handle, OID_802_3_MULTICAST_LIST, list,
				size);
	if (res)
		ERROR("Unable to set multicast list (%08X)", res);
}

/*
 * This function is called fom BH context...no sleep!
 */
static void ndis_set_rx_mode(struct net_device *dev)
{
	struct ndis_handle *handle = dev->priv;
	set_bit(SET_PACKET_FILTER, &handle->wrapper_work);
	schedule_work(&handle->wrapper_worker);
}

static struct ndis_packet *alloc_packet(struct ndis_handle *handle,
				       struct ndis_buffer *buffer)
{
	struct ndis_packet *packet;

	packet = kmalloc(sizeof(struct ndis_packet), GFP_ATOMIC);
	if (!packet)
		return NULL;

	memset(packet, 0, sizeof(*packet));

	if (handle->use_scatter_gather) {
		/* FIXME: do USB drivers call this? */
		packet->dataphys =
			PCI_DMA_MAP_SINGLE(handle->dev.pci,
					   buffer->data, buffer->len,
					   PCI_DMA_TODEVICE);
		packet->sg_list.len = 1;
		packet->sg_element.address.quad = packet->dataphys;
		packet->sg_element.len = buffer->len;
		packet->sg_list.elements = &packet->sg_element;
		packet->extension.info[NDIS_SCLIST_INFO] = &packet->sg_list;
	}

	packet->private.oob_offset = offsetof(struct ndis_packet, oob_tx);

	packet->private.nr_pages = NDIS_BUFFER_TO_SPAN_PAGES(buffer);
	packet->private.len = buffer->len;
	packet->private.count = 1;
	packet->private.valid_counts = 1;

	packet->private.buffer_head = buffer;
	packet->private.buffer_tail = buffer;

	return packet;
}

static void free_packet(struct ndis_handle *handle, struct ndis_packet *packet)
{
	if (!packet) {
		ERROR("illegal packet from %p", handle);
		return;
	}

	kfree(packet->private.buffer_head->data);
	kfree(packet->private.buffer_head);

	if (packet->dataphys) {
		/* FIXME: do USB drivers call this? */
		PCI_DMA_UNMAP_SINGLE(handle->dev.pci, packet->dataphys,
				     packet->private.len, PCI_DMA_TODEVICE);
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
	struct ndis_packet *packet;

	TRACEENTER3("start: %d, pending: %d", start, pending);

	if (miniport->send_packets) {
		unsigned int i;
		if (pending > handle->max_send_packets)
			n = handle->max_send_packets;
		else
			n = pending;

		DBG_BLOCK() {
			if (n > 1)
				DBGTRACE3("sending %d packets", n);
		}

		/* copy packets from xmit_ring to linear xmit_array array */
		for (i = 0; i < n; i++) {
			int j = (start + i) % XMIT_RING_SIZE;
			handle->xmit_array[i] = handle->xmit_ring[j];
		}
		miniport->send_packets(handle->adapter_ctx,
				       handle->xmit_array, n);
		if (test_bit(ATTR_SERIALIZED, &handle->attributes)) {
			for (sent = 0; sent < n && handle->send_ok;
			     sent++) {
				packet = handle->xmit_array[sent];
				switch(packet->status) {
				case NDIS_STATUS_SUCCESS:
					sendpacket_done(handle, packet);
					break;
				case NDIS_STATUS_PENDING:
					break;
				case NDIS_STATUS_RESOURCES:
					handle->send_ok = 0;
					break;
				case NDIS_STATUS_FAILURE:
				default:
					free_packet(handle, packet);
					break;
				}
			}
		} else {
			sent = n;
		}
	} else {
		packet = handle->xmit_ring[start];
		res = miniport->send(handle->adapter_ctx, packet, 0);

		sent = 1;
		switch (res) {
		case NDIS_STATUS_SUCCESS:
			sendpacket_done(handle, packet);
			break;
		case NDIS_STATUS_PENDING:
			break;
		case NDIS_STATUS_RESOURCES:
			handle->send_ok = 0;
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

	TRACEENTER3("send_ok %d", handle->send_ok);

	/* some drivers e.g., new RT2500 driver, crash if any packets
	 * are sent when the card is not associated */
	while (handle->send_ok) {
		wrap_spin_lock(&handle->xmit_ring_lock, DISPATCH_LEVEL);
		if (handle->xmit_ring_pending == 0) {
			wrap_spin_unlock(&handle->xmit_ring_lock);
			break;
		}
		n = send_packets(handle, handle->xmit_ring_start,
				 handle->xmit_ring_pending);
		handle->xmit_ring_start =
			(handle->xmit_ring_start + n) % XMIT_RING_SIZE;
		handle->xmit_ring_pending -= n;
		if (n > 0 && netif_queue_stopped(handle->net_dev))
			netif_wake_queue(handle->net_dev);
		wrap_spin_unlock(&handle->xmit_ring_lock);
	}

	TRACEEXIT3(return);
}

/*
 * Free and unmap packet created in xmit
 */
void sendpacket_done(struct ndis_handle *handle, struct ndis_packet *packet)
{
	TRACEENTER3("%s", "");
	wrap_spin_lock(&handle->send_packet_done_lock, PASSIVE_LEVEL);
	handle->stats.tx_bytes += packet->private.len;
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

	wrap_spin_lock(&handle->xmit_ring_lock, PASSIVE_LEVEL);
	xmit_ring_next_slot =
		(handle->xmit_ring_start +
		 handle->xmit_ring_pending) % XMIT_RING_SIZE;
	handle->xmit_ring[xmit_ring_next_slot] = packet;
	handle->xmit_ring_pending++;
	if (handle->xmit_ring_pending == XMIT_RING_SIZE)
		netif_stop_queue(handle->net_dev);
	wrap_spin_unlock(&handle->xmit_ring_lock);

	schedule_work(&handle->xmit_work);

	return 0;
}

int ndis_suspend_pci(struct pci_dev *pdev, u32 state)
{
	struct net_device *dev;
	struct ndis_handle *handle;
	int res, pm_state;

	if (!pdev)
		return -1;
	handle = pci_get_drvdata(pdev);
	if (!handle)
		return -1;
	dev = handle->net_dev;

	if (test_bit(HW_SUSPENDED, &handle->hw_status) ||
	    test_bit(HW_HALTED, &handle->hw_status))
		return 0;

	DBGTRACE2("irql: %d", KeGetCurrentIrql());
	DBGTRACE2("%s: detaching device", dev->name);
	if (netif_running(dev)) {
		netif_stop_queue(dev);
		netif_device_detach(dev);
	}
	hangcheck_del(handle);
	stats_timer_del(handle);

	if (test_bit(ATTR_HALT_ON_SUSPEND, &handle->attributes)) {
		DBGTRACE2("%s", "driver requests halt_on_suspend");
		miniport_halt(handle);
		set_bit(HW_HALTED, &handle->hw_status);
	} else {
		int i;
		/* some drivers don't support D2, so force D3 */
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
	pci_disable_device(pdev);
	pci_set_power_state(pdev, 3);

	DBGTRACE2("%s: device suspended", dev->name);
	return 0;
}

int ndis_resume_pci(struct pci_dev *pdev)
{
	struct net_device *dev;
	struct ndis_handle *handle;

	if (!pdev)
		return -1;
	handle = pci_get_drvdata(pdev);
	if (!handle)
		return -1;
	dev = handle->net_dev;

	if (!(test_bit(HW_SUSPENDED, &handle->hw_status) ||
	      test_bit(HW_HALTED, &handle->hw_status)))
		return 0;

	pci_enable_device(pdev);
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,9)
	pci_restore_state(pdev);
#else
	pci_restore_state(pdev, handle->pci_state);
#endif
	DBGTRACE2("irql: %d", KeGetCurrentIrql());
	set_bit(SUSPEND_RESUME, &handle->wrapper_work);
	schedule_work(&handle->wrapper_worker);
	return 0;
}

void ndis_remove_one(struct ndis_handle *handle)
{
	struct miniport_char *miniport = &handle->driver->miniport_char;

	TRACEENTER1("%s", handle->net_dev->name);

	stats_timer_del(handle);
	hangcheck_del(handle);
	ndiswrapper_procfs_remove_iface(handle);

	ndis_close(handle->net_dev);
	netif_carrier_off(handle->net_dev);

	set_bit(SHUTDOWN, &handle->wrapper_work);

	/* flush_scheduled_work here causes crash with 2.4 kernels */
	/* instead, throw away pending packets */
	wrap_spin_lock(&handle->xmit_ring_lock, DISPATCH_LEVEL);
	while (handle->xmit_ring_pending) {
		struct ndis_packet *packet;

		packet = handle->xmit_ring[handle->xmit_ring_start];
		free_packet(handle, packet);
		handle->xmit_ring_start =
			(handle->xmit_ring_start + 1) % XMIT_RING_SIZE;
		handle->xmit_ring_pending--;
	}
	wrap_spin_unlock(&handle->xmit_ring_lock);

	miniport_set_int(handle, NDIS_OID_DISASSOCIATE, 0);

	if (handle->net_dev)
		unregister_netdev(handle->net_dev);

	printk(KERN_INFO "%s: device %s removed\n", DRV_NAME,
	       handle->net_dev->name);

	DBGTRACE1("%d, %p",
		  test_bit(ATTR_SURPRISE_REMOVE, &handle->attributes),
		  miniport->pnp_event_notify);
	if (test_bit(ATTR_SURPRISE_REMOVE, &handle->attributes) &&
	    miniport->pnp_event_notify) {
		miniport->pnp_event_notify(handle->adapter_ctx,
					   NDIS_PNP_SURPRISE_REMOVED,
					   NULL, 0);
	}

	DBGTRACE1("halting device %s", handle->driver->name);
	miniport_halt(handle);
	DBGTRACE1("halt successful");

	if (handle->multicast_list)
		kfree(handle->multicast_list);
	if (handle->net_dev)
		free_netdev(handle->net_dev);

	if (handle->phys_device_obj)
		kfree(handle->phys_device_obj);
}

static void link_status_handler(struct ndis_handle *handle)
{
	struct ndis_assoc_info *ndis_assoc_info;
	unsigned char *wpa_assoc_info, *assoc_info, *p, *ies;
	union iwreq_data wrqu;
	unsigned int i, res;
	const int assoc_size = sizeof(*ndis_assoc_info) + IW_CUSTOM_MAX;
	struct encr_info *encr_info = &handle->encr_info;

	TRACEENTER2("");

	DBGTRACE2("link status: %d", handle->link_status);
	if (handle->link_status == 0) {
		if (handle->encr_mode == ENCR1_ENABLED ||
		    handle->op_mode == NDIS_MODE_ADHOC) {
			for (i = 0; i < MAX_ENCR_KEYS; i++) {
				if (encr_info->keys[i].length == 0)
					continue;
				if (add_wep_key(handle, encr_info->keys[i].key,
						encr_info->keys[i].length, i))
					WARNING("setting wep key %d failed",
						i);
			}

			set_bit(SET_ESSID, &handle->wrapper_work);
			schedule_work(&handle->wrapper_worker);
			TRACEEXIT2(return);

		}
		/* FIXME: not clear if NDIS says keys should
		 * be cleared here */
		for (i = 0; i < MAX_ENCR_KEYS; i++)
			handle->encr_info.keys[i].length = 0;

		memset(&wrqu, 0, sizeof(wrqu));
		wrqu.ap_addr.sa_family = ARPHRD_ETHER;
		wireless_send_event(handle->net_dev, SIOCGIWAP, &wrqu, NULL);
		TRACEEXIT2(return);
	}

	if (!test_bit(CAPA_WPA, &handle->capa))
		TRACEEXIT2(return);

	assoc_info = kmalloc(assoc_size, GFP_KERNEL);
	if (!assoc_info) {
		ERROR("%s", "couldn't allocate memory");
		TRACEEXIT2(return);
	}
	memset(assoc_info, 0, assoc_size);

	ndis_assoc_info = (struct ndis_assoc_info *)assoc_info;
	ndis_assoc_info->length = sizeof(*ndis_assoc_info);
	ndis_assoc_info->offset_req_ies = sizeof(*ndis_assoc_info);
	ndis_assoc_info->req_ie_length = IW_CUSTOM_MAX / 2;
	ndis_assoc_info->offset_resp_ies = sizeof(*ndis_assoc_info) +
		ndis_assoc_info->req_ie_length;
	ndis_assoc_info->resp_ie_length = IW_CUSTOM_MAX / 2;

	res = miniport_query_info(handle, NDIS_OID_ASSOC_INFO, assoc_info,
				  assoc_size);
	if (res) {
		DBGTRACE2("query assoc_info failed (%08X)", res);
		kfree(assoc_info);
		TRACEEXIT2(return);
	}

	/* we need 28 extra bytes for the format strings */
	if ((ndis_assoc_info->req_ie_length +
	     ndis_assoc_info->resp_ie_length + 28) > IW_CUSTOM_MAX) {
		WARNING("information element is too long! (%u,%u),"
			"association information dropped",
			ndis_assoc_info->req_ie_length,
			ndis_assoc_info->resp_ie_length);
		kfree(assoc_info);
		TRACEEXIT2(return);
	}

	wpa_assoc_info = kmalloc(IW_CUSTOM_MAX, GFP_KERNEL);
	if (!wpa_assoc_info) {
		ERROR("%s", "couldn't allocate memory");
		kfree(assoc_info);
		TRACEEXIT2(return);
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
	TRACEEXIT2(return);
}

static void set_packet_filter(struct ndis_handle *handle)
{
	struct net_device *dev = (struct net_device *)handle->net_dev;
	unsigned long packet_filter;
	unsigned int res;

	packet_filter = (NDIS_PACKET_TYPE_DIRECTED |
			 NDIS_PACKET_TYPE_BROADCAST |
			 NDIS_PACKET_TYPE_ALL_MULTICAST);

	if (dev->flags & IFF_PROMISC) {
		DBGTRACE1("%s", "Going into promiscuous mode");
		printk(KERN_WARNING "promiscuous mode is not "
		       "supported by NDIS; only packets sent "
		       "from/to this host will be seen\n");
		packet_filter |= NDIS_PACKET_TYPE_ALL_LOCAL;
	} else if ((dev->mc_count > handle->multicast_list_size) ||
		   (dev->flags & IFF_ALLMULTI) ||
		   (handle->multicast_list == 0)) {
		/* Too many to filter perfectly -- accept all multicasts. */

		DBGTRACE1("Multicast list to long. Accepting all");
		packet_filter |= NDIS_PACKET_TYPE_ALL_MULTICAST;
	} else if (dev->mc_count > 0) {
		packet_filter |= NDIS_PACKET_TYPE_MULTICAST;
		set_multicast_list(dev, handle);
	}

	res = miniport_set_info(handle, NDIS_OID_PACKET_FILTER,
				(char *)&packet_filter, sizeof(packet_filter));
	if (res && res != NDIS_STATUS_NOT_SUPPORTED)
		ERROR("Unable to set packet filter (%08X)", res);
	TRACEEXIT2(return);
}

static void update_wireless_stats(struct ndis_handle *handle)
{
	struct iw_statistics *iw_stats = &handle->wireless_stats;
	struct ndis_wireless_stats ndis_stats;
	long rssi;
	unsigned int res;

	if (handle->reset_status)
		return;
	res = miniport_query_info(handle, NDIS_OID_RSSI, (char *)&rssi,
				  sizeof(rssi));
	iw_stats->qual.level = rssi;

	memset(&ndis_stats, 0, sizeof(ndis_stats));
	res = miniport_query_info(handle, NDIS_OID_STATISTICS,
				  (char *)&ndis_stats, sizeof(ndis_stats));
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
	TRACEEXIT2(return);
}

static struct iw_statistics *get_wireless_stats(struct net_device *dev)
{
	struct ndis_handle *handle = dev->priv;
	return &handle->wireless_stats;
}

/* worker procedure to take care of setting/checking various states */
static void wrapper_worker_proc(void *param)
{
	struct ndis_handle *handle = (struct ndis_handle *)param;

	DBGTRACE2("%lu", handle->wrapper_work);

	if (test_bit(SHUTDOWN, &handle->wrapper_work))
		TRACEEXIT3(return);

	if (test_and_clear_bit(SET_OP_MODE, &handle->wrapper_work))
		set_mode(handle, handle->op_mode);

	if (test_and_clear_bit(WRAPPER_LINK_STATUS, &handle->wrapper_work))
		link_status_handler(handle);

	if (test_and_clear_bit(SET_ESSID, &handle->wrapper_work))
		set_essid(handle, handle->essid.essid, handle->essid.length);

	if (test_and_clear_bit(SET_PACKET_FILTER, &handle->wrapper_work))
		set_packet_filter(handle);

	if (test_and_clear_bit(COLLECT_STATS, &handle->wrapper_work))
		update_wireless_stats(handle);

	if (test_and_clear_bit(SUSPEND_RESUME, &handle->wrapper_work)) {
		unsigned int res;
		struct net_device *net_dev = handle->net_dev;

		if (test_bit(HW_HALTED, &handle->hw_status)) {
			res = miniport_init(handle);
			if (res)
				ERROR("initialization failed: %08X", res);
			clear_bit(HW_HALTED, &handle->hw_status);
		} else {
			res = miniport_set_int(handle, NDIS_OID_PNP_SET_POWER,
					       NDIS_PM_STATE_D0);
			clear_bit(HW_SUSPENDED, &handle->hw_status);
			DBGTRACE2("%s: setting power to state %d returns %d",
				  net_dev->name, NDIS_PM_STATE_D0, res);
			if (res)
				WARNING("No pnp capabilities for pm (%08X)",
					res);
			/* ignore this error and continue */
			res = 0;
			/*
			  if (miniport->pnp_event_notify) {
			  INFO("%s", "calling pnp_event_notify");
			  miniport->pnp_event_notify(handle,
			  NDIS_PNP_PROFILE_CHANGED,
			  &profile_inf, sizeof(profile_inf));
			  }
			*/
		}

		if (!res) {
			hangcheck_add(handle);
			stats_timer_add(handle);
			miniport_set_int(handle, NDIS_OID_BSSID_LIST_SCAN, 0);
			set_bit(SET_ESSID, &handle->wrapper_work);
			schedule_work(&handle->wrapper_worker);

			if (netif_running(net_dev)) {
				netif_device_attach(net_dev);
				netif_start_queue(net_dev);
			}

			DBGTRACE2("%s: device resumed", net_dev->name);
		}
	}
	TRACEEXIT3(return);
}

/* check capabilites - mainly for WPA */
static void check_capa(struct ndis_handle *handle)
{
	int i, mode;
	unsigned int res;
	struct ndis_assoc_info ndis_assoc_info;
	struct ndis_add_key ndis_key;

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
				ndis_key.struct_size);

	DBGTRACE2("add key returns %08X, size = %ld\n",
		 res, (unsigned long)sizeof(ndis_key));
	if (res != NDIS_STATUS_INVALID_DATA)
		TRACEEXIT1(return);
	res = miniport_query_info(handle, NDIS_OID_ASSOC_INFO,
				  (char *)&ndis_assoc_info,
				  sizeof(ndis_assoc_info));
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

	if (!i)
		clear_bit(ATTR_HALT_ON_SUSPEND, &handle->attributes);
	return 0;
}

static int ndis_set_mac_addr(struct net_device *dev, void *p)
{
	struct ndis_handle *handle = dev->priv;
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
	unsigned int i, res;
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
				  &mac[0], sizeof(mac));
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
	set_essid(handle, "", 0);

	res = miniport_query_int(handle, OID_802_3_MAXIMUM_LIST_SIZE, &i);
	if (res == NDIS_STATUS_SUCCESS) {
		DBGTRACE1("Multicast list size is %d", i);
		handle->multicast_list_size = i;
	}

	if (handle->multicast_list_size)
		handle->multicast_list =
			kmalloc(handle->multicast_list_size * ETH_ALEN,
				GFP_KERNEL);

	if (set_privacy_filter(handle, NDIS_PRIV_ACCEPT_ALL))
		WARNING("%s", "Unable to set privacy filter");

	ndis_set_rx_mode(dev);

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
		dev->irq = handle->ndis_irq->irq.irq;
	dev->mem_start = handle->mem_start;
	dev->mem_end = handle->mem_end;

	res = register_netdev(dev);
	if (res) {
		ERROR("cannot register net device %s", dev->name);
		return res;
	}

	netif_stop_queue(dev);
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

	hangcheck_add(handle);
	stats_timer_add(handle);
	ndiswrapper_procfs_add_iface(handle);

	return 0;
}

struct net_device *ndis_init_netdev(struct ndis_handle **phandle,
				    struct ndis_device *device,
				    struct ndis_driver *driver)
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

	handle = dev->priv;

	/* Poison the fileds as they may contain function pointers
	 * which my be called by the driver */
	for (i = 0, ip = (int *)&handle->signature;
	     (void *)&ip[i] < (void *)&handle->dev.pci; i++)
		ip[i] = 0x1000+i;

	handle->driver = driver;
	handle->device = device;
	handle->net_dev = dev;
	handle->ndis_irq = NULL;

	init_MUTEX(&handle->ndis_comm_mutex);
	init_waitqueue_head(&handle->ndis_comm_wq);
	handle->ndis_comm_done = 0;

	/* don't send packets until the card is associated */
	handle->send_ok = 0;

	INIT_WORK(&handle->xmit_work, xmit_worker, handle);
	wrap_spin_lock_init(&handle->xmit_ring_lock);
	handle->xmit_ring_start = 0;
	handle->xmit_ring_pending = 0;

	wrap_spin_lock_init(&handle->send_packet_done_lock);

	handle->encr_mode = ENCR_DISABLED;
	handle->auth_mode = AUTHMODE_OPEN;
	handle->capa = 0;
	handle->attributes = 0;

	handle->reset_status = 0;

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
	ndis_exit();
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

	if (loader_init())
		TRACEEXIT1(return -EPERM);
	if (ndis_init()) {
		module_cleanup();
		TRACEEXIT1(return -EPERM);
	}		
	usb_init();
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
	TRACEENTER1("");
	module_cleanup();
}

module_init(wrapper_init);
module_exit(wrapper_exit);

MODULE_LICENSE("GPL");
