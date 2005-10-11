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
#include <asm/scatterlist.h>
#include <asm/uaccess.h>

#include "wrapper.h"
#include "iw_ndis.h"
#include "loader.h"

static char *if_name = "wlan%d";
int proc_uid, proc_gid;
static int hangcheck_interval;

#if defined(DEBUG) && (DEBUG > 0)
int debug = DEBUG;
#else
int debug = 0;
#endif

/* used to implement Windows spinlocks */
spinlock_t spinlock_kspin_lock;
/* use own workqueue instead of shared one, to avoid depriving
 * others */
struct workqueue_struct *ndiswrapper_wq;

WRAP_MODULE_PARM_STRING(if_name, 0400);
MODULE_PARM_DESC(if_name, "Network interface name or template "
		 "(default: wlan%d)");
WRAP_MODULE_PARM_INT(proc_uid, 0600);
MODULE_PARM_DESC(proc_uid, "The uid of the files created in /proc "
		 "(default: 0).");
WRAP_MODULE_PARM_INT(proc_gid, 0600);
MODULE_PARM_DESC(proc_gid, "The gid of the files created in /proc "
		 "(default: 0).");
WRAP_MODULE_PARM_INT(hangcheck_interval, 0600);
/* 0 - default value provided by NDIS driver,
 * positive value - force hangcheck interval to that many seconds
 * negative value - disable hangcheck
 */
WRAP_MODULE_PARM_INT(debug, 0600);
MODULE_PARM_DESC(debug, "debug level");

MODULE_PARM_DESC(hangcheck_interval, "The interval, in seconds, for checking"
		 " if driver is hung. (default: -1)");

MODULE_AUTHOR("ndiswrapper team <ndiswrapper-general@lists.sourceforge.net>");
#ifdef MODULE_VERSION
MODULE_VERSION(DRIVER_VERSION);
#endif

extern KSPIN_LOCK timer_lock;
static int set_packet_filter(struct wrapper_dev *wd, ULONG packet_filter);

static int inline ndis_wait_pending_completion(struct wrapper_dev *wd)
{
	/* wait for NdisMXXComplete to be called*/
	/* As per spec, we should wait until miniport calls back
	 * completion routine, but some drivers (e.g., ZyDas) don't
	 * call back, so timeout is used; TODO: find out why drivers
	 * don't call completion function */
#if 1
	if (wait_event_interruptible_timeout(wd->ndis_comm_wq,
					     (wd->ndis_comm_done == 1),
					     2 * HZ) <= 0)
#else
	if (wait_event_interruptible(wd->ndis_comm_wq,
				     (wd->ndis_comm_done == 1)))
#endif
		return -1;
	else
		return 0;
}

/*
 * MiniportReset
 */
NDIS_STATUS miniport_reset(struct wrapper_dev *wd)
{
	KIRQL irql;
	NDIS_STATUS res = 0;
	struct miniport_char *miniport;
	UINT cur_lookahead;
	UINT max_lookahead;
	BOOLEAN reset_address;

	TRACEENTER2("wd: %p", wd);

	if (!test_bit(HW_AVAILABLE, &wd->hw_status))
		TRACEEXIT1(return NDIS_STATUS_FAILURE);

	if (down_interruptible(&wd->ndis_comm_mutex))
		TRACEEXIT3(return NDIS_STATUS_FAILURE);
	miniport = &wd->driver->miniport;
	wd->ndis_comm_status = NDIS_STATUS_PENDING;
	wd->ndis_comm_done = 0;
	cur_lookahead = wd->nmb->cur_lookahead;
	max_lookahead = wd->nmb->max_lookahead;
	irql = raise_irql(DISPATCH_LEVEL);
	res = LIN2WIN2(miniport->reset, &reset_address,
		       wd->nmb->adapter_ctx);
	lower_irql(irql);

	DBGTRACE2("res = %08X, reset_status = %08X", res, reset_address);
	if (res == NDIS_STATUS_PENDING) {
		/* wait for NdisMResetComplete */
		if (ndis_wait_pending_completion(wd))
			res = NDIS_STATUS_FAILURE;
		else
			res = wd->ndis_comm_status;
		DBGTRACE2("res = %08X, reset_status = %08X",
			  res, reset_address);
	}
	DBGTRACE2("reset: res = %08X, reset status = %08X",
		  res, reset_address);

	if (res == NDIS_STATUS_SUCCESS && reset_address) {
		wd->nmb->cur_lookahead = cur_lookahead;
		wd->nmb->max_lookahead = max_lookahead;
		set_packet_filter(wd, wd->packet_filter);
//		set_multicast_list(wd->net_dev);
	}
	up(&wd->ndis_comm_mutex);

	TRACEEXIT3(return res);
}


/*
 * MiniportQueryInformation
 * Perform a sync query and deal with the possibility of an async operation.
 * This function must be called from process context as it will sleep.
 */
NDIS_STATUS miniport_query_info_needed(struct wrapper_dev *wd,
				       ndis_oid oid, void *buf,
				       ULONG bufsize, ULONG *needed)
{
	NDIS_STATUS res;
	ULONG written;
	struct miniport_char *miniport = &wd->driver->miniport;
	KIRQL irql;

	DBGTRACE2("oid: %08X", oid);

	if (!test_bit(HW_AVAILABLE, &wd->hw_status))
		TRACEEXIT1(return NDIS_STATUS_FAILURE);

	if (down_interruptible(&wd->ndis_comm_mutex))
		TRACEEXIT3(return NDIS_STATUS_FAILURE);
	wd->ndis_comm_done = 0;
	DBGTRACE2("query %p, oid: %08X", miniport->query, oid);
	irql = raise_irql(DISPATCH_LEVEL);
	res = LIN2WIN6(miniport->query, wd->nmb->adapter_ctx, oid, buf,
		       bufsize, &written, needed);
	lower_irql(irql);

	DBGTRACE2("res: %08X, oid: %08X", res, oid);
	if (res == NDIS_STATUS_PENDING) {
		/* wait for NdisMQueryInformationComplete */
		if (ndis_wait_pending_completion(wd))
			res = NDIS_STATUS_FAILURE;
		else
			res = wd->ndis_comm_status;
		DBGTRACE2("res: %08X", res);
	}
	up(&wd->ndis_comm_mutex);
	if (res && needed)
		DBGTRACE2("res: %08X, bufsize: %d, written: %d, needed: %d",
			  res, bufsize, written, *needed);
	TRACEEXIT3(return res);
}

NDIS_STATUS miniport_query_info(struct wrapper_dev *wd, ndis_oid oid,
				void *buf, ULONG bufsize)
{
	NDIS_STATUS res;
	ULONG needed;

	res = miniport_query_info_needed(wd, oid, buf, bufsize, &needed);
	return res;
}

/*
 * MiniportSetInformation
 * Perform a sync setinfo and deal with the possibility of an async operation.
 * This function must be called from process context as it will sleep.
 */
NDIS_STATUS miniport_set_info(struct wrapper_dev *wd, ndis_oid oid,
			      void *buf, ULONG bufsize)
{
	NDIS_STATUS res;
	ULONG written, needed;
	struct miniport_char *miniport = &wd->driver->miniport;
	KIRQL irql;

	DBGTRACE2("oid: %08X", oid);

	if (!test_bit(HW_AVAILABLE, &wd->hw_status))
		TRACEEXIT1(return NDIS_STATUS_FAILURE);

	if (down_interruptible(&wd->ndis_comm_mutex))
		TRACEEXIT3(return NDIS_STATUS_FAILURE);
	wd->ndis_comm_done = 0;
	irql = raise_irql(DISPATCH_LEVEL);
	res = LIN2WIN6(miniport->setinfo, wd->nmb->adapter_ctx, oid, buf,
		       bufsize, &written, &needed);
	lower_irql(irql);
	DBGTRACE2("res: %08X, oid: %08X", res, oid);

	if (res == NDIS_STATUS_PENDING) {
		/* wait for NdisMSetInformationComplete */
		if (ndis_wait_pending_completion(wd))
			res = NDIS_STATUS_FAILURE;
		else
			res = wd->ndis_comm_status;
		DBGTRACE2("res: %08X", res);
	}
	up(&wd->ndis_comm_mutex);
	if (res && needed)
		DBGTRACE2("res: %08X, bufsize: %d, written: %d, needed: %d",
			  res, bufsize, written, needed);
	TRACEEXIT3(return res);
}

/* Make a query that has an int as the result. */
NDIS_STATUS miniport_query_int(struct wrapper_dev *wd, ndis_oid oid,
			       ULONG *data)
{
	return miniport_query_info(wd, oid, data, sizeof(ULONG));
}

/* Set an int */
NDIS_STATUS miniport_set_int(struct wrapper_dev *wd, ndis_oid oid,
			     ULONG data)
{
	return miniport_set_info(wd, oid, &data, sizeof(data));
}


/*
 * MiniportInitialize
 */
NDIS_STATUS miniport_init(struct wrapper_dev *wd)
{
	NDIS_STATUS status, res;
	UINT medium_index;
	UINT medium_array[] = {NdisMedium802_3};
	struct miniport_char *miniport = &wd->driver->miniport;

	TRACEENTER1("driver init routine is at %p", miniport->init);
	if (miniport->init == NULL) {
		ERROR("initialization function is not setup correctly");
		return -EINVAL;
	}
	if (test_bit(HW_INITIALIZED, &wd->hw_status)) {
		ERROR("device %p already initialized!", wd);
		return -EINVAL;
	}
	res = ntoskernel_init_device(wd);
	if (res)
		return res;
	res = misc_funcs_init_device(wd);
	if (res)
		goto err_misc_funcs;
	if (wd->dev.dev_type == NDIS_USB_BUS) {
#ifdef CONFIG_USB
		res = usb_init_device(wd);
#else
		res = -EINVAL;
#endif
		if (res)
			goto err_usb;
	}
	res = LIN2WIN6(miniport->init, &status, &medium_index, medium_array,
		       sizeof(medium_array) / sizeof(medium_array[0]),
		       wd->nmb, wd->nmb);
	DBGTRACE1("init returns: %08X", res);
	if (res)
		goto err_miniport_init;

	set_bit(HW_INITIALIZED, &wd->hw_status);
	/* Wait a little to let card power up otherwise ifup might fail after
	   boot; USB devices seem to need long delays */
	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(HZ);

	/* do we need to reset the device? */
//	res = miniport_reset(wd);
#if 0
	res = miniport_set_pm_state(wd, NdisDeviceStateD0);
	if (res)
		DBGTRACE1("setting power state to device %s returns %08X",
			  wd->net_dev->name, res);
#endif
	TRACEEXIT1(return 0);

err_miniport_init:
#ifdef CONFIG_USB
	if (wd->dev.dev_type == NDIS_USB_BUS)
		usb_exit_device(wd);
#endif
err_usb:
	misc_funcs_exit_device(wd);
 err_misc_funcs:
	ntoskernel_exit_device(wd);
	return res;
}

/*
 * MiniportHalt
 */
void miniport_halt(struct wrapper_dev *wd)
{
	struct miniport_char *miniport = &wd->driver->miniport;
	struct kthread *kthread;

	TRACEENTER1("%p", wd);
	if (!test_bit(HW_INITIALIZED, &wd->hw_status)) {
		WARNING("device %p is not initialized - not halting", wd);
		TRACEEXIT1(return);
	}
	kthread = wrap_create_thread(get_current());
	if (kthread == NULL)
		WARNING("couldn't create system thread for task: %p",
			get_current());
	DBGTRACE1("driver halt is at %p", miniport->miniport_halt);

	DBGTRACE2("task: %p, pid: %d", get_current(), get_current()->pid);
	LIN2WIN1(miniport->miniport_halt, wd->nmb->adapter_ctx);
	clear_bit(HW_INITIALIZED, &wd->hw_status);
	ndis_exit_device(wd);

	if (kthread)
		wrap_remove_thread(kthread);
	if (wd->wrapper_packet_pool)
		NdisFreePacketPool(wd->wrapper_packet_pool);
	if (wd->wrapper_buffer_pool)
		NdisFreeBufferPool(wd->wrapper_buffer_pool);
#ifdef CONFIG_USB
	if (wd->dev.dev_type == NDIS_USB_BUS)
		usb_exit_device(wd);
#endif
	misc_funcs_exit_device(wd);
	ntoskernel_exit_device(wd);

	TRACEEXIT1(return);
}

NDIS_STATUS miniport_set_pm_state(struct wrapper_dev *wd,
				  enum ndis_pm_state pm_state)
{
	NDIS_STATUS res;
	struct miniport_char *miniport;

	res = NDIS_STATUS_SUCCESS;
	if (pm_state != NdisDeviceStateD0) {
		enum ndis_pm_state ps;
		ps = pm_state;
		res = miniport_query_int(wd, OID_PNP_QUERY_POWER, &ps);
		DBGTRACE2("query_power returns %08X", res);
	}
	if (res != NDIS_STATUS_SUCCESS)
		WARNING("device may not support power management");
	res = miniport_set_int(wd, OID_PNP_SET_POWER, pm_state);
	DBGTRACE2("set_power returns %08X", res);
	miniport = &wd->driver->miniport;

	/* According NDIS, pnp_event_notify should be called whenever power
	 * is set to D0
	 * Only NDIS 5.1 drivers are required to supply this function; some
	 * drivers don't seem to support it (at least Orinoco)
	 */
	if (res == NDIS_STATUS_SUCCESS && pm_state == NdisDeviceStateD0 &&
	    miniport->pnp_event_notify) {
		ULONG pnp_info;
		pnp_info = NdisPowerProfileAcOnLine;
		DBGTRACE2("calling pnp_event_notify");
		LIN2WIN4(miniport->pnp_event_notify, wd->nmb->adapter_ctx,
			 NdisDevicePnPEventPowerProfileChanged,
			 &pnp_info, (ULONG)sizeof(pnp_info));
	}
	return res;
}

NDIS_STATUS miniport_surprise_remove(struct wrapper_dev *wd)
{
	struct miniport_char *miniport;

	miniport = &wd->driver->miniport;
	DBGTRACE1("%d, %p",
		  test_bit(ATTR_SURPRISE_REMOVE, &wd->attributes),
		  miniport->pnp_event_notify);

	if (miniport->pnp_event_notify) {
		DBGTRACE1("calling surprise_removed");
		LIN2WIN4(miniport->pnp_event_notify,
			 wd->nmb->adapter_ctx,
			 NdisDevicePnPEventSurpriseRemoved, NULL, 0);
		return NDIS_STATUS_SUCCESS;
	} else {
		WARNING("%s: Windows driver for device %s doesn't "
			"support MiniportPnpEventNotify for safely "
			"removing the device", DRIVER_NAME,
			wd->net_dev->name);
		return NDIS_STATUS_FAILURE;
	}
}

static void hangcheck_proc(unsigned long data)
{
	struct wrapper_dev *wd = (struct wrapper_dev *)data;

	TRACEENTER3("");
	if (wd->hangcheck_interval <= 0)
		return;

	set_bit(HANGCHECK, &wd->wrapper_work);
	schedule_work(&wd->wrapper_worker);

	wd->hangcheck_timer.expires += wd->hangcheck_interval;
	add_timer(&wd->hangcheck_timer);

	TRACEEXIT3(return);
}

void hangcheck_add(struct wrapper_dev *wd)
{
	if (!wd->driver->miniport.hangcheck || wd->hangcheck_interval <= 0)
		return;
	init_timer(&wd->hangcheck_timer);
	wd->hangcheck_timer.data = (unsigned long)wd;
	wd->hangcheck_timer.function = &hangcheck_proc;
	wd->hangcheck_timer.expires = jiffies + wd->hangcheck_interval;
	add_timer(&wd->hangcheck_timer);
	return;
}

void hangcheck_del(struct wrapper_dev *wd)
{
	del_timer_sync(&wd->hangcheck_timer);
}

static void stats_proc(unsigned long data)
{
	struct wrapper_dev *wd = (struct wrapper_dev *)data;

	set_bit(COLLECT_STATS, &wd->wrapper_work);
	schedule_work(&wd->wrapper_worker);
	wd->stats_timer.expires += 10 * HZ;
	add_timer(&wd->stats_timer);
}

static void stats_timer_add(struct wrapper_dev *wd)
{
	init_timer(&wd->stats_timer);
	wd->stats_timer.data = (unsigned long)wd;
	wd->stats_timer.function = &stats_proc;
	wd->stats_timer.expires = jiffies + 10 * HZ;
	add_timer(&wd->stats_timer);
}

static void stats_timer_del(struct wrapper_dev *wd)
{
	del_timer_sync(&wd->stats_timer);
}

static int set_packet_filter(struct wrapper_dev *wd, ULONG packet_filter)
{
	NDIS_STATUS res;
	ULONG filter = packet_filter;

	TRACEENTER3("%x", packet_filter);
	res = miniport_set_info(wd, OID_GEN_CURRENT_PACKET_FILTER,
				&filter, sizeof(filter));
	if (res) {
		DBGTRACE1("couldn't set packet filter: %08X", res);
		TRACEEXIT3(return res);
	}
	wd->packet_filter = packet_filter;
	TRACEEXIT3(return 0);
}

static int get_packet_filter(struct wrapper_dev *wd, ULONG *packet_filter)
{
	NDIS_STATUS res;

	TRACEENTER3("");
	res = miniport_query_info(wd, OID_GEN_CURRENT_PACKET_FILTER,
				  packet_filter, sizeof(*packet_filter));
	if (res) {
		DBGTRACE1("couldn't get packet filter: %08X", res);
		TRACEEXIT3(return res);
	}
	TRACEEXIT3(return 0);
}

static int ndis_open(struct net_device *dev)
{
	ULONG packet_filter;
	struct wrapper_dev *wd = netdev_priv(dev);

	TRACEENTER1("");
	packet_filter = NDIS_PACKET_TYPE_DIRECTED | NDIS_PACKET_TYPE_BROADCAST;
	/* first try with minimum required */
	if (set_packet_filter(wd, packet_filter))
		DBGTRACE1("couldn't set packet filter %x", packet_filter);
	else
		DBGTRACE1("set packet filter");
	/* add any dev specific filters */
	if (dev->flags & IFF_PROMISC)
		packet_filter |= NDIS_PACKET_TYPE_ALL_LOCAL;
	if (set_packet_filter(wd, packet_filter))
		DBGTRACE1("couldn't add packet filter %x", packet_filter);
	/* NDIS_PACKET_TYPE_PROMISCUOUS will not work with 802.11 */
	netif_device_attach(dev);
	netif_start_queue(dev);
	return 0;
}

static int ndis_close(struct net_device *dev)
{
	TRACEENTER1("");

	if (netif_running(dev)) {
		netif_tx_disable(dev);
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
	struct wrapper_dev *wd = netdev_priv(dev);
	return &wd->stats;
}

static int ndis_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	int rc = -ENODEV;
	return rc;
}

/*
 * This function is called fom BH context...no sleep!
 */
static void ndis_set_multicast_list(struct net_device *dev)
{
	struct wrapper_dev *wd = netdev_priv(dev);
	set_bit(SET_MULTICAST_LIST, &wd->wrapper_work);
	schedule_work(&wd->wrapper_worker);
}

static void set_multicast_list(struct wrapper_dev *wd)
{
	struct net_device *net_dev;
	ULONG packet_filter;
	NDIS_STATUS res = 0;

	net_dev = wd->net_dev;
	if (!(net_dev->mc_count > 0 ||
	      net_dev->flags & IFF_ALLMULTI))
		TRACEEXIT3(return);

	res = get_packet_filter(wd, &packet_filter);
	if (res) {
//		WARNING("couldn't get packet filter: %08X", res);
		TRACEEXIT3(return);
	}

	packet_filter |= NDIS_PACKET_TYPE_MULTICAST;
	packet_filter |= NDIS_PACKET_TYPE_ALL_MULTICAST;
	DBGTRACE2("packet filter: %08x", packet_filter);
	res = set_packet_filter(wd, packet_filter);
	if (res)
		DBGTRACE1("couldn't set packet filter (%08X)", res);

	TRACEEXIT2(return);
}

static struct ndis_packet *
allocate_send_packet(struct wrapper_dev *wd, ndis_buffer *buffer)
{
	struct ndis_packet *packet;
	struct wrap_ndis_packet *wrap_ndis_packet;
	NDIS_STATUS status;

	NdisAllocatePacket(&status, &packet, wd->wrapper_packet_pool);
	if (status != NDIS_STATUS_SUCCESS)
		return NULL;

	packet->private.buffer_head = buffer;
	packet->private.buffer_tail = buffer;
	wrap_ndis_packet = packet->wrap_ndis_packet;
	if (wd->use_sg_dma) {
		wrap_ndis_packet->ndis_sg_element.address =
			PCI_DMA_MAP_SINGLE(wd->dev.pci,
					   MmGetMdlVirtualAddress(buffer),
					   MmGetMdlByteCount(buffer),
					   PCI_DMA_TODEVICE);

		wrap_ndis_packet->ndis_sg_element.length =
			MmGetMdlByteCount(buffer);
		wrap_ndis_packet->ndis_sg_list.nent = 1;
		wrap_ndis_packet->ndis_sg_list.elements =
			&wrap_ndis_packet->ndis_sg_element;
		wrap_ndis_packet->extension.info[ScatterGatherListPacketInfo] =
			&wrap_ndis_packet->ndis_sg_list;
	}
	return packet;
}

static void free_send_packet(struct wrapper_dev *wd,
			     struct ndis_packet *packet)
{
	ndis_buffer *buffer;
	struct wrap_ndis_packet *wrap_ndis_packet;

	TRACEENTER3("packet: %p", packet);
	if (!packet) {
		ERROR("illegal packet from %p", wd);
		return;
	}

	buffer = packet->private.buffer_head;
	wrap_ndis_packet = packet->wrap_ndis_packet;
	if (wd->use_sg_dma)
		PCI_DMA_UNMAP_SINGLE(wd->dev.pci,
				     wrap_ndis_packet->ndis_sg_element.address,
				     wrap_ndis_packet->ndis_sg_element.length,
				     PCI_DMA_TODEVICE);

	DBGTRACE3("freeing buffer %p", buffer);
	NdisFreeBuffer(buffer);
	dev_kfree_skb(wrap_ndis_packet->skb);

	DBGTRACE3("freeing packet %p", packet);
	NdisFreePacket(packet);
	TRACEEXIT3(return);
}

/*
 * MiniportSend and MiniportSendPackets
 * this function is called with lock held in DISPATCH_LEVEL, so no need
 * to raise irql to DISPATCH_LEVEL during MiniportSend(Packets)
*/
static int send_packets(struct wrapper_dev *wd, unsigned int start,
			unsigned int pending)
{
	NDIS_STATUS res;
	struct miniport_char *miniport = &wd->driver->miniport;
	unsigned int sent, n;
	struct ndis_packet *packet;
	struct wrap_ndis_packet *wrap_ndis_packet;

	TRACEENTER3("start: %d, pending: %d", start, pending);

	if (pending > wd->max_send_packets)
		n = wd->max_send_packets;
	else
		n = pending;

	if (miniport->send_packets) {
		int i;
		/* copy packets from xmit ring to linear xmit array */
		for (i = 0; i < n; i++) {
			int j = (start + i) % XMIT_RING_SIZE;
			wd->xmit_array[i] = wd->xmit_ring[j];
		}
		LIN2WIN3(miniport->send_packets, wd->nmb->adapter_ctx,
			 wd->xmit_array, n);
		DBGTRACE3("sent");
		if (test_bit(ATTR_SERIALIZED, &wd->attributes)) {
			for (sent = 0; sent < n && wd->send_ok; sent++) {
				packet = wd->xmit_array[sent];
				wrap_ndis_packet = packet->wrap_ndis_packet;
				switch(wrap_ndis_packet->oob_data.status) {
				case NDIS_STATUS_SUCCESS:
					sendpacket_done(wd, packet);
					break;
				case NDIS_STATUS_PENDING:
					break;
				case NDIS_STATUS_RESOURCES:
					wd->send_ok = 0;
					break;
				case NDIS_STATUS_FAILURE:
				default:
					free_send_packet(wd, packet);
					break;
				}
			}
		} else {
			sent = n;
		}
	} else {
		packet = wd->xmit_ring[start];
		res = LIN2WIN3(miniport->send, wd->nmb->adapter_ctx,
			       packet, 0);

		sent = 1;
		switch (res) {
		case NDIS_STATUS_SUCCESS:
			sendpacket_done(wd, packet);
			break;
		case NDIS_STATUS_PENDING:
			break;
		case NDIS_STATUS_RESOURCES:
			wd->send_ok = 0;
			sent = 0;
			break;
		case NDIS_STATUS_FAILURE:
			free_send_packet(wd, packet);
			break;
		}
	}
	TRACEEXIT3(return sent);
}

static void xmit_worker(void *param)
{
	struct wrapper_dev *wd = (struct wrapper_dev *)param;
	int n;
	KIRQL irql;

	TRACEENTER3("send_ok %d", wd->send_ok);

	/* some drivers e.g., new RT2500 driver, crash if any packets
	 * are sent when the card is not associated */
	irql = kspin_lock_irql(&wd->xmit_lock, DISPATCH_LEVEL);
	while (wd->send_ok) {
		if (wd->xmit_ring_pending == 0)
			break;
		n = send_packets(wd, wd->xmit_ring_start,
				 wd->xmit_ring_pending);
		wd->xmit_ring_start =
			(wd->xmit_ring_start + n) % XMIT_RING_SIZE;
		wd->xmit_ring_pending -= n;
		if (n > 0 && netif_queue_stopped(wd->net_dev))
			netif_wake_queue(wd->net_dev);
	}
	kspin_unlock_irql(&wd->xmit_lock, irql);

	TRACEEXIT3(return);
}

/*
 * Free and unmap packet created in xmit
 */
void sendpacket_done(struct wrapper_dev *wd, struct ndis_packet *packet)
{
	KIRQL irql;

	TRACEENTER3("");
	irql = kspin_lock_irql(&wd->send_packet_done_lock, DISPATCH_LEVEL);
	wd->stats.tx_bytes += packet->private.len;
	wd->stats.tx_packets++;
	free_send_packet(wd, packet);
	kspin_unlock_irql(&wd->send_packet_done_lock, irql);
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
	struct wrapper_dev *wd = netdev_priv(dev);
	ndis_buffer *buffer;
	struct ndis_packet *packet;
	unsigned int xmit_ring_next_slot;
	KIRQL irql;
	NDIS_STATUS res;

	NdisAllocateBuffer(&res, &buffer, wd->wrapper_buffer_pool,
			   skb->data, skb->len);
	if (res != NDIS_STATUS_SUCCESS)
		return 1;
	packet = allocate_send_packet(wd, buffer);
	if (!packet) {
		NdisFreeBuffer(buffer);
		return 1;
	}
	packet->wrap_ndis_packet->skb = skb;
	irql = kspin_lock_irql(&wd->xmit_lock, DISPATCH_LEVEL);
	xmit_ring_next_slot =
		(wd->xmit_ring_start +
		 wd->xmit_ring_pending) % XMIT_RING_SIZE;
	wd->xmit_ring[xmit_ring_next_slot] = packet;
	wd->xmit_ring_pending++;
	if (wd->xmit_ring_pending == XMIT_RING_SIZE)
		netif_stop_queue(wd->net_dev);
	kspin_unlock_irql(&wd->xmit_lock, irql);

	schedule_work(&wd->xmit_work);

	return 0;
}

static NTSTATUS ndiswrapper_start_device(struct wrapper_dev *wd)
{
	NTSTATUS status;
	struct kthread *kthread;

	kthread = wrap_create_thread(get_current());
	if (!kthread) {
		ERROR("couldn't allocate thread object");
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	status = miniport_init(wd);
	if (status != NDIS_STATUS_SUCCESS) {
		WARNING("couldn't initialize device: %08X", status);
		return status;
	}
	wrap_remove_thread(kthread);
	hangcheck_add(wd);
	stats_timer_add(wd);
	TRACEEXIT1(return NDIS_STATUS_SUCCESS);
}

static void ndiswrapper_stop_device(struct wrapper_dev *wd)
{
	hangcheck_del(wd);
	stats_timer_del(wd);
	miniport_halt(wd);
}

int ndis_reinit(struct wrapper_dev *wd)
{
	ndiswrapper_stop_device(wd);
	ndiswrapper_start_device(wd);
	return 0;
}

int ndiswrapper_suspend_device(struct wrapper_dev *wd,
			       enum ndis_pm_state pm_state)
{
	NDIS_STATUS status;

	if (!wd)
		return -1;

	if (test_bit(HW_SUSPENDED, &wd->hw_status) ||
	    test_bit(HW_HALTED, &wd->hw_status))
		return -1;

	DBGTRACE2("irql: %d", current_irql());
	DBGTRACE2("detaching device: %s", wd->net_dev->name);
	netif_poll_disable(wd->net_dev);
	if (netif_running(wd->net_dev)) {
		netif_tx_disable(wd->net_dev);
		netif_device_detach(wd->net_dev);
	}
	hangcheck_del(wd);
	stats_timer_del(wd);

	status = miniport_set_pm_state(wd, pm_state);
	DBGTRACE2("suspending returns %08X", status);
	if (status == NDIS_STATUS_SUCCESS)
		set_bit(HW_SUSPENDED, &wd->hw_status);
	else {
		DBGTRACE2("no pm: halting the device");
		ndiswrapper_stop_device(wd);
		set_bit(HW_HALTED, &wd->hw_status);
	}
	clear_bit(HW_AVAILABLE, &wd->hw_status);
	return 0;
}

int ndiswrapper_resume_device(struct wrapper_dev *wd)
{
	if (!wd)
		TRACEEXIT1(return -1);
	if (test_bit(HW_AVAILABLE, &wd->hw_status))
		TRACEEXIT1(return -1);
	if (!(test_bit(HW_SUSPENDED, &wd->hw_status) ||
	      test_bit(HW_HALTED, &wd->hw_status)))
		TRACEEXIT1(return -1);

	set_bit(SUSPEND_RESUME, &wd->wrapper_work);
	schedule_work(&wd->wrapper_worker);
	TRACEEXIT1(return 0);
}

int ndiswrapper_suspend_pci(struct pci_dev *pdev, pm_message_t state)
{
	struct wrapper_dev *wd;
	int ret;

	if (!pdev)
		return -1;
	wd = pci_get_drvdata(pdev);
	/* some drivers support only D3, so force it */
	ret = ndiswrapper_suspend_device(wd, NdisDeviceStateD3);
	if (ret)
		return ret;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,9)
	pci_save_state(pdev);
#else
	pci_save_state(pdev, wd->pci_state);
#endif
	/* PM seems to be in constant flux and documentation is not
	 * up-to-date on what is the correct way to suspend/resume, so
	 * this needs to be tweaked for different kernel versions */
//	pci_disable_device(pdev);
//	ret = pci_set_power_state(pdev, pci_choose_state(pdev, state));

	DBGTRACE2("%s: device suspended", wd->net_dev->name);
	return 0;
}

int ndiswrapper_resume_pci(struct pci_dev *pdev)
{
	struct wrapper_dev *wd;
	int ret;

	if (!pdev)
		return -1;
	wd = pci_get_drvdata(pdev);
	if (!wd)
		return -1;
//	ret = pci_set_power_state(pdev, PCI_D0);
//	ret = pci_enable_device(pdev);
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,9)
	pci_restore_state(pdev);
#else
	pci_restore_state(pdev, wd->pci_state);
#endif
	ret = ndiswrapper_resume_device(wd);
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
int ndiswrapper_suspend_usb(struct usb_interface *intf, pm_message_t state)
{
	struct wrapper_dev *wd;
	int ret;

	wd = usb_get_intfdata(intf);
	/* some drivers support only D3, so force it */
	ret = ndiswrapper_suspend_device(wd, NdisDeviceStateD3);
	DBGTRACE2("ret = %d", ret);
	/* TODO: suspend seems to work fine and resume also works if
	 * resumed from command line, but resuming from S3 crashes
	 * kernel. Should we kill any pending urbs? what about
	 * irps? */
	if (!ret)
		intf->dev.power.power_state = state;
	return ret;
}

int ndiswrapper_resume_usb(struct usb_interface *intf)
{
	struct wrapper_dev *wd;
	int ret;

	wd = usb_get_intfdata(intf);
	ret = ndiswrapper_resume_device(wd);
	if (!ret)
		intf->dev.power.power_state = PMSG_ON;
	return ret;
}
#endif

void ndiswrapper_remove_device(struct wrapper_dev *wd)
{
	KIRQL irql;

	DBGTRACE1("%s", wd->net_dev->name);

	set_bit(SHUTDOWN, &wd->wrapper_work);

	ndis_close(wd->net_dev);
	netif_carrier_off(wd->net_dev);
	ndiswrapper_procfs_remove_iface(wd);

	/* flush_scheduled_work here causes crash with 2.4 kernels */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	flush_scheduled_work();
#endif
	/* instead, throw away pending packets */
	irql = kspin_lock_irql(&wd->xmit_lock, DISPATCH_LEVEL);
	while (wd->xmit_ring_pending) {
		struct ndis_packet *packet;

		packet = wd->xmit_ring[wd->xmit_ring_start];
		free_send_packet(wd, packet);
		wd->xmit_ring_start =
			(wd->xmit_ring_start + 1) % XMIT_RING_SIZE;
		wd->xmit_ring_pending--;
	}
	kspin_unlock_irql(&wd->xmit_lock, irql);

//	miniport_set_int(wd, OID_802_11_DISASSOCIATE, 0);

	DBGTRACE1("stopping device; irql: %d", current_irql());
	ndiswrapper_stop_device(wd);
	DBGTRACE1("stopped; irql: %d", current_irql());

	IoDeleteDevice(wd->nmb->fdo);
	IoDeleteDevice(wd->nmb->pdo);
//	free_pdo(wd->nmb->pdo);
	if (wd->xmit_array)
		kfree(wd->xmit_array);
	printk(KERN_INFO "%s: device %s removed\n", DRIVER_NAME,
	       wd->net_dev->name);
	unregister_netdev(wd->net_dev);
	free_netdev(wd->net_dev);
	TRACEEXIT1(return);
}

static void link_status_handler(struct wrapper_dev *wd)
{
	struct ndis_assoc_info *ndis_assoc_info;
#if WIRELESS_EXT < 18
	unsigned char *wpa_assoc_info, *ies;
	unsigned char *p;
	int i;
#endif
	unsigned char *assoc_info;
	union iwreq_data wrqu;
	NDIS_STATUS res;
	const int assoc_size = sizeof(*ndis_assoc_info) + IW_CUSTOM_MAX;

	TRACEENTER2("link status: %d", wd->link_status);
	if (wd->link_status == 0) {
#if 0
		unsigned int i;
		struct encr_info *encr_info = &wd->encr_info;

		if (wd->encr_mode == Ndis802_11Encryption1Enabled ||
		    wd->infrastructure_mode == Ndis802_11IBSS) {
			for (i = 0; i < MAX_ENCR_KEYS; i++) {
				if (encr_info->keys[i].length == 0)
					continue;
				add_wep_key(wd, encr_info->keys[i].key,
					    encr_info->keys[i].length, i);
			}

			set_bit(SET_ESSID, &wd->wrapper_work);
			schedule_work(&wd->wrapper_worker);
			TRACEEXIT2(return);
		}
		/* TODO: not clear if NDIS says keys should
		 * be cleared here */
		for (i = 0; i < MAX_ENCR_KEYS; i++)
			wd->encr_info.keys[i].length = 0;
#endif

		memset(&wrqu, 0, sizeof(wrqu));
		wrqu.ap_addr.sa_family = ARPHRD_ETHER;
		wireless_send_event(wd->net_dev, SIOCGIWAP, &wrqu, NULL);
		TRACEEXIT2(return);
	}

	if (!(test_bit(Ndis802_11Encryption2Enabled, &wd->capa.encr) ||
	      test_bit(Ndis802_11Encryption3Enabled, &wd->capa.encr)))
		TRACEEXIT2(return);

	assoc_info = kmalloc(assoc_size, GFP_KERNEL);
	if (!assoc_info) {
		ERROR("couldn't allocate memory");
		TRACEEXIT2(return);
	}
	memset(assoc_info, 0, assoc_size);

	ndis_assoc_info = (struct ndis_assoc_info *)assoc_info;
#if 0
	ndis_assoc_info->length = sizeof(*ndis_assoc_info);
	ndis_assoc_info->offset_req_ies = sizeof(*ndis_assoc_info);
	ndis_assoc_info->req_ie_length = IW_CUSTOM_MAX / 2;
	ndis_assoc_info->offset_resp_ies = sizeof(*ndis_assoc_info) +
		ndis_assoc_info->req_ie_length;
	ndis_assoc_info->resp_ie_length = IW_CUSTOM_MAX / 2;
#endif
	res = miniport_query_info(wd, OID_802_11_ASSOCIATION_INFORMATION,
				  assoc_info, assoc_size);
	if (res) {
		DBGTRACE2("query assoc_info failed (%08X)", res);
		kfree(assoc_info);
		TRACEEXIT2(return);
	}

	/*
	 * TODO: backwards compatibility would require that IWEVCUSTOM
	 * is sent even if WIRELESS_EXT > 17. This version does not do
	 * this in order to allow wpa_supplicant to be tested with
	 * WE-18.
	 */
#if WIRELESS_EXT > 17
	memset(&wrqu, 0, sizeof(wrqu));
	wrqu.data.length = ndis_assoc_info->req_ie_length;
	wireless_send_event(wd->net_dev, IWEVASSOCREQIE, &wrqu,
			    ((char *) ndis_assoc_info) +
			    ndis_assoc_info->offset_req_ies);
	wrqu.data.length = ndis_assoc_info->resp_ie_length;
	wireless_send_event(wd->net_dev, IWEVASSOCRESPIE, &wrqu,
			    ((char *) ndis_assoc_info) +
			    ndis_assoc_info->offset_resp_ies);
#else
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
		ERROR("couldn't allocate memory");
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
	wireless_send_event(wd->net_dev, IWEVCUSTOM, &wrqu, wpa_assoc_info);

	kfree(wpa_assoc_info);
#endif
	kfree(assoc_info);

	get_ap_address(wd, (char *)&wrqu.ap_addr.sa_data);
	wrqu.ap_addr.sa_family = ARPHRD_ETHER;
	wireless_send_event(wd->net_dev, SIOCGIWAP, &wrqu, NULL);
	DBGTRACE2("associate to " MACSTR, MAC2STR(wrqu.ap_addr.sa_data));
	TRACEEXIT2(return);
}

static void update_wireless_stats(struct wrapper_dev *wd)
{
	struct iw_statistics *iw_stats = &wd->wireless_stats;
	struct ndis_wireless_stats ndis_stats;
	NDIS_STATUS res;
	ndis_rssi rssi;

	TRACEENTER2("");
	if (wd->stats_enabled == FALSE || wd->link_status == 0)
		TRACEEXIT2(return);
	res = miniport_query_info(wd, OID_802_11_RSSI, &rssi, sizeof(rssi));
	if (res == NDIS_STATUS_SUCCESS)
		iw_stats->qual.level = rssi;

	memset(&ndis_stats, 0, sizeof(ndis_stats));
	res = miniport_query_info(wd, OID_802_11_STATISTICS,
				  &ndis_stats, sizeof(ndis_stats));
	if (res != NDIS_STATUS_SUCCESS)
		TRACEEXIT2(return);
	iw_stats->discard.retries = (u32)ndis_stats.retry +
		(u32)ndis_stats.multi_retry;
	iw_stats->discard.misc = (u32)ndis_stats.fcs_err +
		(u32)ndis_stats.rtss_fail +
		(u32)ndis_stats.ack_fail +
		(u32)ndis_stats.frame_dup;

	if ((u32)ndis_stats.tx_frag)
		iw_stats->qual.qual = 100 - 100 *
			((u32)ndis_stats.retry +
			 2 * (u32)ndis_stats.multi_retry +
			 3 * (u32)ndis_stats.failed) /
			(6 * (u32)ndis_stats.tx_frag);
	else
		iw_stats->qual.qual = 100;
	TRACEEXIT2(return);
}

struct iw_statistics *get_wireless_stats(struct net_device *dev)
{
	struct wrapper_dev *wd = netdev_priv(dev);
	return &wd->wireless_stats;
}

#ifdef HAVE_ETHTOOL
static u32 ndis_get_link(struct net_device *dev)
{
	struct wrapper_dev *wd = netdev_priv(dev);
	return wd->link_status;
}

static struct ethtool_ops ndis_ethtool_ops = {
	.get_link		= ndis_get_link,
};
#endif

/* worker procedure to take care of setting/checking various states */
static void wrapper_worker_proc(void *param)
{
	struct wrapper_dev *wd = (struct wrapper_dev *)param;

	DBGTRACE2("%lu", wd->wrapper_work);

	if (test_bit(SHUTDOWN, &wd->wrapper_work))
		TRACEEXIT3(return);

	if (test_and_clear_bit(SET_INFRA_MODE, &wd->wrapper_work))
		set_infra_mode(wd, wd->infrastructure_mode);

	if (test_and_clear_bit(SET_ESSID, &wd->wrapper_work))
		set_essid(wd, wd->essid.essid, wd->essid.length);

	if (test_and_clear_bit(SET_MULTICAST_LIST, &wd->wrapper_work))
		set_multicast_list(wd);

	if (test_and_clear_bit(COLLECT_STATS, &wd->wrapper_work))
		update_wireless_stats(wd);

	if (test_and_clear_bit(LINK_STATUS_CHANGED, &wd->wrapper_work))
		link_status_handler(wd);

	if (test_and_clear_bit(HANGCHECK, &wd->wrapper_work)) {
		NDIS_STATUS res;
		struct miniport_char *miniport;
		KIRQL irql;

		miniport = &wd->driver->miniport;
		irql = raise_irql(DISPATCH_LEVEL);
		res = LIN2WIN1(miniport->hangcheck, wd->nmb->adapter_ctx);
		lower_irql(irql);
		if (res) {
			WARNING("%s is being reset", wd->net_dev->name);
			res = miniport_reset(wd);
			DBGTRACE3("reset returns %08X", res);
		}
	}
	if (test_and_clear_bit(SUSPEND_RESUME, &wd->wrapper_work)) {
		NDIS_STATUS res;
		struct net_device *net_dev = wd->net_dev;

		DBGTRACE2("resuming device %s", net_dev->name);
		DBGTRACE2("continuing resume of device %s", net_dev->name);
		if (test_and_clear_bit(HW_SUSPENDED, &wd->hw_status)) {
			set_bit(HW_AVAILABLE, &wd->hw_status);
			res = miniport_set_pm_state(wd, NdisDeviceStateD0);
			DBGTRACE1("%s: setting power state returns %08X",
				  net_dev->name, res);
			if (res)
				WARNING("device %s may not have resumed "
					"properly (%08X)", net_dev->name, res);
		} else if (test_and_clear_bit(HW_HALTED, &wd->hw_status)) {
			res = ndiswrapper_start_device(wd);
			DBGTRACE2("res: %08X", res);
			if (res) {
				ERROR("device %s re-initialization failed "
				      "(%08X)", net_dev->name, res);
				/* TODO: should be halted? */
				set_bit(SHUTDOWN, &wd->hw_status);
				return;
			} else
				set_bit(HW_AVAILABLE, &wd->hw_status);
		}
		hangcheck_add(wd);
		stats_timer_add(wd);
		set_scan(wd);
		set_bit(SET_ESSID, &wd->wrapper_work);

		if (netif_running(net_dev)) {
			netif_device_attach(net_dev);
			netif_wake_queue(net_dev);
		}
		netif_poll_enable(net_dev);
		DBGTRACE2("%s: device resumed", net_dev->name);
	}

	TRACEEXIT3(return);
}

/* check capabilites - mainly for WPA */
void check_capa(struct wrapper_dev *wd)
{
	int i, mode;
	NDIS_STATUS res;
	struct ndis_assoc_info ndis_assoc_info;
	struct ndis_add_key ndis_key;
	struct ndis_capability *c;
	char *buf;
	const int buf_len = 512;

	TRACEENTER1("");

	/* check if WEP is supported */
	if (set_encr_mode(wd, Ndis802_11Encryption1Enabled) == 0 &&
	    get_encr_mode(wd) == Ndis802_11Encryption1KeyAbsent)
		set_bit(Ndis802_11Encryption1Enabled, &wd->capa.encr);

	/* check if WPA is supported */
	DBGTRACE1("");
	if (set_auth_mode(wd, Ndis802_11AuthModeWPA) == 0 &&
	    get_auth_mode(wd) == Ndis802_11AuthModeWPA)
		set_bit(Ndis802_11AuthModeWPA, &wd->capa.auth);
	else
		TRACEEXIT1(return);

	if (set_auth_mode(wd, Ndis802_11AuthModeWPAPSK) == 0 &&
	    get_auth_mode(wd) == Ndis802_11AuthModeWPAPSK)
		set_bit(Ndis802_11AuthModeWPAPSK, &wd->capa.auth);

	/* check for highest encryption */
	mode = 0;
	if (set_encr_mode(wd, Ndis802_11Encryption3Enabled) == 0 &&
	    (i = get_encr_mode(wd)) > 0 &&
	    (i == Ndis802_11Encryption3KeyAbsent ||
	     i == Ndis802_11Encryption3Enabled))
		mode = Ndis802_11Encryption3Enabled;
	else if (set_encr_mode(wd, Ndis802_11Encryption2Enabled) == 0 &&
		 (i = get_encr_mode(wd)) > 0 &&
		 (i == Ndis802_11Encryption2KeyAbsent ||
		  i == Ndis802_11Encryption2Enabled))
		mode = Ndis802_11Encryption2Enabled;
	else if (set_encr_mode(wd, Ndis802_11Encryption1Enabled) == 0 &&
		 (i = get_encr_mode(wd)) > 0 &&
		 (i == Ndis802_11Encryption1KeyAbsent ||
		  i == Ndis802_11Encryption1Enabled))
		mode = Ndis802_11Encryption1Enabled;

	DBGTRACE1("mode: %d", mode);
	if (mode == 0)
		TRACEEXIT1(return);
	set_bit(Ndis802_11Encryption1Enabled, &wd->capa.encr);
	if (mode == Ndis802_11Encryption1Enabled)
		TRACEEXIT1(return);

	ndis_key.length = 32;
	ndis_key.index = 0xC0000001;
	ndis_key.struct_size = sizeof(ndis_key);
	res = miniport_set_info(wd, OID_802_11_ADD_KEY, &ndis_key,
				ndis_key.struct_size);
	DBGTRACE2("add key returns %08X, size = %lu",
		  res, (unsigned long)sizeof(ndis_key));
	if (res && res != NDIS_STATUS_INVALID_DATA)
		TRACEEXIT1(return);
	res = miniport_query_info(wd, OID_802_11_ASSOCIATION_INFORMATION,
				  &ndis_assoc_info, sizeof(ndis_assoc_info));
	DBGTRACE1("assoc info returns %08X", res);
	if (res == NDIS_STATUS_NOT_SUPPORTED)
		TRACEEXIT1(return);

	set_bit(Ndis802_11Encryption2Enabled, &wd->capa.encr);
	if (mode == Ndis802_11Encryption3Enabled)
		set_bit(Ndis802_11Encryption3Enabled, &wd->capa.encr);
	/* not all drivers support OID_802_11_CAPABILITY, so we don't
	 * know for sure if driver support WPA or WPAPSK; assume
	 * WPA */
	set_bit(Ndis802_11AuthModeWPA, &wd->capa.auth);

	/* check for wpa2 */
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		ERROR("couldn't allocate memory");
		TRACEEXIT1(return);
	}
	memset(buf, 0, buf_len);
	c = (struct ndis_capability *)buf;
	res = miniport_query_info(wd, OID_802_11_CAPABILITY, buf, buf_len);
	if (!(res == NDIS_STATUS_SUCCESS && c->version == 2)) {
		DBGTRACE1("res: %X", res);
		kfree(buf);
		TRACEEXIT1(return);
	}
	wd->num_pmkids = c->num_PMKIDs;

	for (i = 0; i < c->num_auth_encr_pair; i++) {
		struct ndis_auth_encr_pair *ae;

		ae = &c->auth_encr_pair[i];
		if ((char *)(ae + 1) > buf + buf_len)
			break;
		switch (ae->auth_mode) {
		case Ndis802_11AuthModeOpen:
		case Ndis802_11AuthModeShared:
		case Ndis802_11AuthModeWPA:
		case Ndis802_11AuthModeWPAPSK:
		case Ndis802_11AuthModeWPANone:
		case Ndis802_11AuthModeWPA2:
		case Ndis802_11AuthModeWPA2PSK:
			set_bit(ae->auth_mode, &wd->capa.auth);
			break;
		default:
			WARNING("unknown auth_mode: %d", ae->auth_mode);
			break;
		}
		switch (ae->encr_mode) {
		case Ndis802_11EncryptionDisabled:
		case Ndis802_11Encryption1Enabled:
		case Ndis802_11Encryption2Enabled:
		case Ndis802_11Encryption3Enabled:
			set_bit(ae->encr_mode, &wd->capa.encr);
			break;
		default:
			WARNING("unknown encr_mode: %d", ae->encr_mode);
			break;
		}
	}
	kfree(buf);
	TRACEEXIT1(return);
}

static int ndis_set_mac_addr(struct net_device *dev, void *p)
{
	struct wrapper_dev *wd = netdev_priv(dev);
	struct sockaddr *addr = p;
	struct ndis_config_param param;
	struct unicode_string key;
	struct ansi_string ansi;
	unsigned int i;
	NDIS_STATUS res;
	unsigned char mac_string[3 * ETH_ALEN];
	mac_address mac;

	/* string <-> ansi <-> unicode conversion is driving me nuts */

	for (i = 0; i < sizeof(mac); i++)
		mac[i] = addr->sa_data[i];
	memset(mac_string, 0, sizeof(mac_string));
	res = snprintf(mac_string, sizeof(mac_string), MACSTR,
		       MAC2STR(mac));
	DBGTRACE2("res = %d, mac_tring = %s", res, mac_string);
	if (res != (sizeof(mac_string) - 1))
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
	NdisWriteConfiguration(&res, wd->nmb, &key, &param);
	if (res != NDIS_STATUS_SUCCESS) {
		RtlFreeUnicodeString(&key);
		RtlFreeUnicodeString(&param.data.ustring);
		TRACEEXIT1(return -EINVAL);
	}
	ndis_reinit(wd);
	memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);
	RtlFreeUnicodeString(&key);
	RtlFreeUnicodeString(&param.data.ustring);
	TRACEEXIT1(return 0);
}

static void show_supported_oids(struct wrapper_dev *wd)
{
	NDIS_STATUS res;
	int i, n, needed;
	ndis_oid *oids;

	res = miniport_query_info_needed(wd, OID_GEN_SUPPORTED_LIST, NULL, 0,
					 &needed);
	if (res != NDIS_STATUS_BUFFER_TOO_SHORT &&
	    res != NDIS_STATUS_INVALID_LENGTH)
		TRACEEXIT1(return);
	oids = kmalloc(needed, GFP_KERNEL);
	if (!oids) {
		DBGTRACE1("couldn't allocate memory");
		TRACEEXIT1(return);
	}
	res = miniport_query_info(wd, OID_GEN_SUPPORTED_LIST, oids, needed);
	if (res) {
		DBGTRACE1("failed: %08X", res);
		kfree(oids);
		TRACEEXIT1(return);
	}
	for (i = 0, n = needed / sizeof(*oids); i < n; i++)
		DBGTRACE1("oid: %08X", oids[i]);
	kfree(oids);
	TRACEEXIT1(return);
}

int setup_device(struct wrapper_dev *wd)
{
	struct net_device *dev = wd->net_dev;
	NDIS_STATUS res;
	mac_address mac;
	char buf[256];

	res = ndiswrapper_start_device(wd);
	if (res) {
		ERROR("Windows driver couldn't initialize the device (%08X)",
		      res);
		return -EINVAL;
	}

	show_supported_oids(wd);
	if (strlen(if_name) > (IFNAMSIZ-1)) {
		ERROR("interface name '%s' is too long", if_name);
		return -1;
	}
	strncpy(dev->name, if_name, IFNAMSIZ-1);
	dev->name[IFNAMSIZ-1] = '\0';

	DBGTRACE1("%s: querying for mac", DRIVER_NAME);
	res = miniport_query_info(wd, OID_802_3_CURRENT_ADDRESS,
				  mac, sizeof(mac));
	if (res) {
		ERROR("couldn't get mac address: %08X", res);
		return -EINVAL;
	}
	DBGTRACE1("mac:" MACSTR, MAC2STR(mac));
	memcpy(&dev->dev_addr, mac, ETH_ALEN);

	dev->open = ndis_open;
	dev->hard_start_xmit = start_xmit;
	dev->stop = ndis_close;
	dev->get_stats = ndis_get_stats;
	dev->do_ioctl = ndis_ioctl;
#if WIRELESS_EXT < 19
	dev->get_wireless_stats = get_wireless_stats;
#endif
	dev->wireless_handlers	= (struct iw_handler_def *)&ndis_handler_def;
	dev->set_multicast_list = ndis_set_multicast_list;
	dev->set_mac_address = ndis_set_mac_addr;
#ifdef HAVE_ETHTOOL
	dev->ethtool_ops = &ndis_ethtool_ops;
#endif
	if (wd->ndis_irq)
		dev->irq = wd->ndis_irq->irq.irq;
	dev->mem_start = wd->mem_start;
	dev->mem_end = wd->mem_end;

	res = register_netdev(dev);
	if (res) {
		ERROR("cannot register net device %s", dev->name);
		return res;
	}

	memset(buf, 0, sizeof(buf));
	res = miniport_query_info(wd, OID_GEN_VENDOR_DESCRIPTION,
				  buf, sizeof(buf));
	if (res == NDIS_STATUS_SUCCESS)
		printk(KERN_INFO "%s: vendor: '%s'\n", dev->name, buf);

	printk(KERN_INFO "%s: %s ethernet device " MACSTR " using driver %s,"
	       " %s\n",
	       dev->name, DRIVER_NAME, MAC2STR(dev->dev_addr),
	       wd->driver->name, wd->ndis_device->conf_file_name);

	check_capa(wd);
	DBGTRACE1("capbilities = %ld", wd->capa.encr);
	printk(KERN_INFO "%s: encryption modes supported: %s%s%s%s%s%s%s\n",
	       dev->name,
	       test_bit(Ndis802_11Encryption1Enabled, &wd->capa.encr) ?
	       "WEP" : "none",

	       test_bit(Ndis802_11Encryption2Enabled, &wd->capa.encr) ?
	       "; TKIP with WPA" : "",
	       test_bit(Ndis802_11AuthModeWPA2, &wd->capa.auth) ?
	       ", WPA2" : "",
	       test_bit(Ndis802_11AuthModeWPA2PSK, &wd->capa.auth) ?
	       ", WPA2PSK" : "",

	       test_bit(Ndis802_11Encryption3Enabled, &wd->capa.encr) ?
	       "; AES/CCMP with WPA" : "",
	       test_bit(Ndis802_11AuthModeWPA2, &wd->capa.auth) ?
	       ", WPA2" : "",
	       test_bit(Ndis802_11AuthModeWPA2PSK, &wd->capa.auth) ?
	       ", WPA2PSK" : "");

	if (test_bit(ATTR_SERIALIZED, &wd->attributes)) {
		res = miniport_query_int(wd, OID_GEN_MAXIMUM_SEND_PACKETS,
					 &wd->max_send_packets);
		if (res == NDIS_STATUS_NOT_SUPPORTED)
			wd->max_send_packets = 1;
		if (wd->max_send_packets > XMIT_RING_SIZE)
			wd->max_send_packets = XMIT_RING_SIZE;
	} else {
		/* deserialized drivers don't have a limit, but we
		 * keep max at XMIT_RING_SIZE to allocate xmit_array
		 * below */
		wd->max_send_packets = XMIT_RING_SIZE;
	}

	DBGTRACE1("maximum send packets: %d", wd->max_send_packets);
	wd->xmit_array =
		kmalloc(sizeof(struct ndis_packet *) * wd->max_send_packets,
			GFP_KERNEL);
	if (!wd->xmit_array) {
		ERROR("couldn't allocate memory for tx_packets");
		goto xmit_array_err;

	}
	/* we need at least one extra packet for
	 * EthRxIndicateHandler */
	NdisAllocatePacketPoolEx(&res, &wd->wrapper_packet_pool,
				 wd->max_send_packets + 1, 0,
				 PROTOCOL_RESERVED_SIZE_IN_PACKET);
	if (res != NDIS_STATUS_SUCCESS) {
		ERROR("couldn't allocate packet pool");
		goto packet_pool_err;
	}
	NdisAllocateBufferPool(&res, &wd->wrapper_buffer_pool,
			       wd->max_send_packets + 4);
	if (res != NDIS_STATUS_SUCCESS) {
		ERROR("couldn't allocate buffer pool");
		goto buffer_pool_err;
	}
	DBGTRACE1("pool: %p", wd->wrapper_buffer_pool);
	miniport_set_int(wd, OID_802_11_NETWORK_TYPE_IN_USE,
			 Ndis802_11Automode);
	/* check_capa changes auth_mode and encr_mode, so set them again */
	set_scan(wd);
	set_infra_mode(wd, Ndis802_11Infrastructure);
	set_auth_mode(wd, Ndis802_11AuthModeOpen);
	set_encr_mode(wd, Ndis802_11EncryptionDisabled);
	set_privacy_filter(wd, Ndis802_11PrivFilterAcceptAll);

	ndiswrapper_procfs_add_iface(wd);

	return 0;

buffer_pool_err:
	wd->wrapper_buffer_pool = NULL;
	if (wd->wrapper_packet_pool) {
		NdisFreePacketPool(wd->wrapper_packet_pool);
		wd->wrapper_packet_pool = NULL;
	}
packet_pool_err:
	kfree(wd->xmit_array);
	wd->xmit_array = NULL;
xmit_array_err:
	unregister_netdev(wd->net_dev);
	return -ENOMEM;
}

struct net_device *ndis_init_netdev(struct wrapper_dev **pwd,
				    struct ndis_device *device,
				    struct ndis_driver *driver)
{
	struct net_device *dev;
	struct wrapper_dev *wd;
	struct ndis_miniport_block *nmb;

	dev = alloc_etherdev(sizeof(*wd) + sizeof(*nmb));
	if (!dev) {
		ERROR("couldn't allocate device");
		return NULL;
	}
	SET_MODULE_OWNER(dev);
	wd = netdev_priv(dev);
	DBGTRACE1("wd: %p", wd);

	nmb = ((void *)wd) + sizeof(*wd);
	wd->nmb = nmb;
	nmb->wd = wd;
	nmb->filterdbs.eth_db = nmb;
	nmb->filterdbs.tr_db = nmb;
	nmb->filterdbs.fddi_db = nmb;
	nmb->filterdbs.arc_db = nmb;

	wd->driver = driver;
	wd->ndis_device = device;
	wd->net_dev = dev;
	wd->ndis_irq = NULL;
	kspin_lock_init(&wd->xmit_lock);
	init_MUTEX(&wd->ndis_comm_mutex);
	init_waitqueue_head(&wd->ndis_comm_wq);
	wd->ndis_comm_done = 0;
	/* don't send packets until the card is associated */
	wd->send_ok = 0;
	INIT_WORK(&wd->xmit_work, xmit_worker, wd);
	wd->xmit_ring_start = 0;
	wd->xmit_ring_pending = 0;
	kspin_lock_init(&wd->send_packet_done_lock);
	wd->encr_mode = Ndis802_11EncryptionDisabled;
	wd->auth_mode = Ndis802_11AuthModeOpen;
	wd->capa.encr = 0;
	wd->capa.auth = 0;
	wd->attributes = 0;
	wd->map_count = 0;
	wd->map_dma_addr = NULL;
	wd->nick[0] = 0;
	wd->hangcheck_interval = hangcheck_interval;
	init_timer(&wd->hangcheck_timer);
	wd->scan_timestamp = 0;
	init_timer(&wd->stats_timer);
	wd->hw_status = 0;
	wd->wrapper_work = 0;
	memset(&wd->essid, 0, sizeof(wd->essid));
	memset(&wd->encr_info, 0, sizeof(wd->encr_info));
	wd->infrastructure_mode = Ndis802_11Infrastructure;
	INIT_WORK(&wd->wrapper_worker, wrapper_worker_proc, wd);
	set_bit(HW_AVAILABLE, &wd->hw_status);
	wd->stats_enabled = TRUE;

	*pwd = wd;
	return dev;
}

#ifdef USE_OWN_WORKQUEUE
/* we need to get kthread for the task running ndiswrapper_wq, so
 * schedule a worker for it soon after initializing ndiswrapper_wq */

static struct work_struct _ndiswrapper_wq_init;
static int _ndiswrapper_wq_init_state;
#define NDISWRAPPER_WQ_INIT 1
#define NDISWRAPPER_WQ_EXIT 2

static void _ndiswrapper_wq_init_worker(void *data)
{
	struct task_struct *task;
	struct kthread *kthread;

	task = get_current();
	if (_ndiswrapper_wq_init_state == NDISWRAPPER_WQ_INIT) {
		kthread = wrap_create_thread(task);
		DBGTRACE1("task: %p, pid: %d, thread: %p",
			  task, task->pid, kthread);
		if (!kthread) {
			_ndiswrapper_wq_init_state = -1;
			return;
		}
	} else {
		kthread = KeGetCurrentThread();
		if (kthread) {
			DBGTRACE1("task: %p, pid: %d, thread: %p",
				  task, task->pid, kthread);
			wrap_remove_thread(kthread);
		}
	}
	_ndiswrapper_wq_init_state = 0;
}
#endif

static void module_cleanup(void)
{
	loader_exit();
#ifdef CONFIG_USB
	usb_exit();
#endif
	ndiswrapper_procfs_remove();
	ndis_exit();
	ntoskernel_exit();
	misc_funcs_exit();
#ifdef USE_OWN_WORKQUEUE
	_ndiswrapper_wq_init_state = NDISWRAPPER_WQ_EXIT;
	schedule_work(&_ndiswrapper_wq_init);
	while (_ndiswrapper_wq_init_state) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(4);
	}
	destroy_workqueue(ndiswrapper_wq);
#endif
}

static int __init wrapper_init(void)
{
	char *argv[] = {"loadndisdriver", 
#if defined(DEBUG) && DEBUG >= 1
			"1"
#else
			"0"
#endif
			, UTILS_VERSION, "-a", 0};
	char *env[] = {NULL};
	int ret;

//	debug = 2;
	printk(KERN_INFO "%s version %s loaded (preempt=%s,smp=%s)\n",
	       DRIVER_NAME, DRIVER_VERSION,
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

	spin_lock_init(&spinlock_kspin_lock);
	if (misc_funcs_init() || ntoskernel_init() || ndis_init()
#ifdef CONFIG_USB
	     || usb_init()
#endif
		)
		goto err;
#ifdef USE_OWN_WORKQUEUE
	ndiswrapper_wq = create_singlethread_workqueue("ndiswrapwq");
	INIT_WORK(&_ndiswrapper_wq_init, _ndiswrapper_wq_init_worker, 0);
	_ndiswrapper_wq_init_state = NDISWRAPPER_WQ_INIT;
	schedule_work(&_ndiswrapper_wq_init);
	while (_ndiswrapper_wq_init_state > 0) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(4);
	}
	if (_ndiswrapper_wq_init_state < 0)
		goto err;
#endif
	ndiswrapper_procfs_init();
	if (loader_init())
		goto err;
	DBGTRACE1("calling loadndisdriver");
	ret = call_usermodehelper("/sbin/loadndisdriver", argv, env
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
				  , 1
#endif
		);
	if (ret) {
		ERROR("loadndiswrapper failed (%d); check system log "
		      "for messages from 'loadndisdriver'", ret);
		goto err;
	}
	TRACEEXIT1(return 0);

err:
	module_cleanup();
	ERROR("%s: initialization failed", DRIVER_NAME);
	return -EINVAL;
}

static void __exit wrapper_exit(void)
{
	TRACEENTER1("");
	module_cleanup();
}

module_init(wrapper_init);
module_exit(wrapper_exit);

MODULE_LICENSE("GPL");
