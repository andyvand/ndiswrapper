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
#include "loader.h"
#include "ndis.h"
#include "iw_ndis.h"

#ifndef DRV_VERSION
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

MODULE_PARM(if_name, "s");
MODULE_PARM_DESC(if_name, "Network interface name or template (default: wlan%d)");
MODULE_PARM(proc_uid, "i");
MODULE_PARM_DESC(proc_uid, "The uid of the files created in /proc (default: 0).");
MODULE_PARM(proc_gid, "i");
MODULE_PARM_DESC(proc_gid, "The gid of the files created in /proc (default: 0).");

/* List of loaded drivers */
LIST_HEAD(ndis_driverlist);

/* Protects driver list */
static spinlock_t driverlist_lock = SPIN_LOCK_UNLOCKED;

extern int image_offset;

extern struct list_head wrap_allocs;

int doreset(struct ndis_handle *handle)
{
	int res;
	int addressing_reset;
	down(&handle->reset_mutex);

	handle->reset_wait_done = 0;
	res = handle->driver->miniport_char.reset(&addressing_reset, handle->adapter_ctx);

	if(!res)
		goto out;

	if(res != NDIS_STATUS_PENDING)
		goto out;
		
	wait_event(handle->reset_wqhead, (handle->reset_wait_done == 1));
	 
	res = handle->reset_wait_res;

out:
	up(&handle->reset_mutex);
	return res;
	
}

/*
 * Perform a sync query and deal with the possibility of an async operation.
 * This function must be called from process context as it will sleep.
 */
int doquery(struct ndis_handle *handle, unsigned int oid, char *buf, int bufsize, unsigned int *written , unsigned int *needed)
{
	int res;

	down(&handle->query_set_mutex);

	handle->query_set_wait_done = 0;
//	DBGTRACE("Calling query at %08x rva(%08x)\n", (int)handle->driver->miniport_char.query, (int)handle->driver->miniport_char.query - image_offset);
	res = handle->driver->miniport_char.query(handle->adapter_ctx, oid, buf, bufsize, written, needed);

	if(!res)
		goto out;

	if(res != NDIS_STATUS_PENDING)
		goto out;
		
	wait_event(handle->query_set_wqhead, (handle->query_set_wait_done == 1));
	 
	res = handle->query_set_wait_res;

out:
	up(&handle->query_set_mutex);
	return res;
	
}

/*
 * Perform a sync setinfo and deal with the possibility of an async operation.
 * This function must be called from process context as it will sleep.
 */
int dosetinfo(struct ndis_handle *handle, unsigned int oid, char *buf, int bufsize, unsigned int *written , unsigned int *needed)
{
	int res;

	down(&handle->query_set_mutex);
	
	handle->query_set_wait_done = 0;
//	DBGTRACE("Calling setinfo at %08x rva(%08x)\n", (int)handle->driver->miniport_char.setinfo, (int)handle->driver->miniport_char.setinfo - image_offset);
	res = handle->driver->miniport_char.setinfo(handle->adapter_ctx, oid, buf, bufsize, written, needed);

	if(!res)
		goto out;

	if(res != NDIS_STATUS_PENDING)
		goto out;
		
	wait_event(handle->query_set_wqhead, (handle->query_set_wait_done == 1));
		
	res = handle->query_set_wait_res;

out:
	up(&handle->query_set_mutex);
	return res;

}


/*
 * Make a query that has an int as the result.
 *
 */
int query_int(struct ndis_handle *handle, int oid, int *data)
{
	unsigned int res, written, needed;

	res = doquery(handle, oid, (char*)data, sizeof(int), &written, &needed);
	if(!res)
		return 0;
	*data = 0;
	return res;
}

/*
 * Set an int
 *
 */
int set_int(struct ndis_handle *handle, int oid, int data)
{
	unsigned int written, needed;

	return dosetinfo(handle, oid, (char*)&data, sizeof(int), &written, &needed);
}

static u32 ndis_get_link(struct net_device *dev)
{
	struct ndis_handle *handle = dev->priv;
	return handle->link_status;
}


#ifdef HAVE_ETHTOOL
static struct ethtool_ops ndis_ethtool_ops = {
	.get_link		= ndis_get_link,
};
#endif

static int call_init(struct ndis_handle *handle)
{
	__u32 res, res2;
	__u32 selected_medium;
	__u32 mediumtypes[] = {0,1,2,3,4,5,6,7,8,9,10,11,12};
	DBGTRACE("Calling init at %08X rva(%08X)\n", (int)handle->driver->miniport_char.init, (int)handle->driver->miniport_char.init - image_offset);
	res = handle->driver->miniport_char.init(&res2, &selected_medium, mediumtypes, 13, handle, handle);
	DBGTRACE("past init res: %08X\n\n", res);
	return res != 0;
}

static void call_halt(struct ndis_handle *handle)
{
	DBGTRACE("Calling halt at %08X rva(%08X)\n", (int)handle->driver->miniport_char.halt, (int)handle->driver->miniport_char.halt - image_offset);

	set_int(handle, NDIS_OID_PNP_SET_POWER, NDIS_PM_STATE_D3);
	pci_set_power_state(handle->pci_dev, 3);

	handle->driver->miniport_char.halt(handle->adapter_ctx);
}

static unsigned int call_entry(struct ndis_driver *driver)
{
	int res;
	char regpath[] = {'a', 0, 'b', 0, 0, 0};
	DBGTRACE("Calling entry at %08X rva(%08X)\n", (int)driver->entry, (int)driver->entry - image_offset);
	res = driver->entry((void*)driver, regpath);
	DBGTRACE("Past entry: Version: %d.%d\n\n", driver->miniport_char.majorVersion, driver->miniport_char.minorVersion);

	/* Dump addresses of driver suppoled callbacks */
#ifdef DEBUG
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
			DBGTRACE("%08X (rva %08X):%s\n", adr[i], adr[i]?adr[i] - image_offset:0, name[i]); 
		}
	}
#endif
	return res;
}

static void hangcheck_reinit(struct ndis_handle *handle);

static void hangcheck_bh(void *data)
{
	struct ndis_handle *handle = (struct ndis_handle *)data;

	DBGTRACE("%s: Hangcheck timer\n", __FUNCTION__);
	if(handle->driver->miniport_char.hangcheck(handle->adapter_ctx))
	{
		int res;
		handle->reset_status = 0;
		printk(KERN_INFO "ndiswrapper: Hangcheck returned true. Resetting!\n");
		res = doreset(handle);
		DBGTRACE("%s : %08X, %d\n", __FUNCTION__, res, handle->reset_status);
	}
}


static void hangcheck(unsigned long data)
{
	struct ndis_handle *handle = (struct ndis_handle *)data;
	schedule_work(&handle->hangcheck_work);
	hangcheck_reinit(handle);
}


static void hangcheck_reinit(struct ndis_handle *handle)
{
	handle->hangcheck_timer.data = (unsigned long) handle;
	handle->hangcheck_timer.function = &hangcheck;
	handle->hangcheck_timer.expires = jiffies + handle->hangcheck_interval;
	add_timer(&handle->hangcheck_timer);

}

void hangcheck_add(struct ndis_handle *handle)
{
	if(!handle->driver->miniport_char.hangcheck)
		return;

	INIT_WORK(&handle->hangcheck_work, &hangcheck_bh, handle);
	init_timer(&handle->hangcheck_timer);
	hangcheck_reinit(handle);
}

void hangcheck_del(struct ndis_handle *handle)
{
	if(!handle->driver->miniport_char.hangcheck)
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
	if (!res)
		iw_stats->qual.level = rssi;

	memset(&ndis_stats, 0, sizeof(ndis_stats));
	res = doquery(handle, NDIS_OID_STATISTICS, (char *)&ndis_stats,
		      sizeof(ndis_stats), &written, &needed);
	if (!res)
	{
		iw_stats->discard.retries = (__u32)ndis_stats.retry +
			(__u32)ndis_stats.multi_retry;
		iw_stats->discard.misc = (__u32)ndis_stats.fcs_err +
			(__u32)ndis_stats.rtss_fail + (__u32)ndis_stats.ack_fail +
			(__u32)ndis_stats.frame_dup;
		
		if (ndis_stats.tx_frag)
			iw_stats->qual.qual = 100 - 100 *
				((__u32)ndis_stats.retry + 2 * (__u32)ndis_stats.multi_retry +
				 3 * (__u32)ndis_stats.failed) /
				(6 * (__u32)ndis_stats.tx_frag);
		else
			iw_stats->qual.qual = 100;
	}
}

static void statcollector_timer(unsigned long data)
{
	struct ndis_handle *handle = (struct ndis_handle *)data;
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
	INIT_WORK(&handle->statcollector_work, &statcollector_bh, handle);
	init_timer(&handle->statcollector_timer);
	statcollector_reinit(handle);
}

void statcollector_del(struct ndis_handle *handle)
{
	del_timer_sync(&handle->statcollector_timer);
}

static int ndis_open(struct net_device *dev)
{
	DBGTRACE("%s\n", __FUNCTION__);
	netif_start_queue(dev);
	return 0;
}


static int ndis_close(struct net_device *dev)
{
	DBGTRACE("%s\n", __FUNCTION__);
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

static void set_multicast_list(struct net_device *dev, struct ndis_handle *handle)
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
	DBGTRACE("%s: %d entries. size=%d\n", __FUNCTION__, dev->mc_count, size);

	res = dosetinfo(handle, OID_802_3_MULTICAST_LIST, list,
	                size, &written, &needed);
	if (res)
		printk(KERN_ERR "%s: Unable to set multicast list (%08X)\n",
		       DRV_NAME, res);
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

	DBGTRACE("%s\n", __FUNCTION__);
	packet_filter = (NDIS_PACKET_TYPE_DIRECTED |
	                 NDIS_PACKET_TYPE_BROADCAST |
	                 NDIS_PACKET_TYPE_ALL_MULTICAST);

	if (dev->flags & IFF_PROMISC) {
		DBGTRACE("%s: Going into promiscuous mode\n", __FUNCTION__);
		packet_filter |= NDIS_PACKET_TYPE_PROMISCUOUS;
	}
	else if ((dev->mc_count > handle->multicast_list_size) ||
	         (dev->flags & IFF_ALLMULTI) ||
	         (handle->multicast_list == 0))
	{
		/* Too many to filter perfectly -- accept all multicasts. */
		DBGTRACE("%s: Multicast list to long. Accepting all\n", __FUNCTION__);
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
		printk(KERN_ERR "%s: Unable to set packet filter (%08X)\n",
		       DRV_NAME, res);
}


/*
 * This function is called fom BH context...no sleep!
 */
static void ndis_set_rx_mode(struct net_device *dev)
{
	struct ndis_handle *handle = dev->priv;
	schedule_work(&handle->set_rx_mode_work);
}


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
		packet->dataphys =
			PCI_DMA_MAP_SINGLE(handle->pci_dev,
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

	//DBGTRACE("Buffer: %08X, data %08X, len %d\n", (int)buffer, (int)buffer->data, (int)buffer->len); 	
	return packet;
}

static void free_packet(struct ndis_handle *handle, struct ndis_packet *packet)
{
	if(packet->dataphys)
	{
		PCI_DMA_UNMAP_SINGLE(handle->pci_dev, packet->dataphys,
				     packet->len, PCI_DMA_TODEVICE);
	}
	
	kfree(packet);
}

static void free_buffer(struct ndis_handle *handle, struct ndis_packet *packet)
{
	kfree(packet->buffer_head->data);
	kfree(packet->buffer_head);
	free_packet(handle, packet);
}


static int send_packet(struct ndis_handle *handle, struct ndis_packet *packet)
{
	int res;

	DBGTRACE("%s: packet = %p\n", __FUNCTION__, packet);

	if(handle->driver->miniport_char.send_packets)
	{
		struct ndis_packet *packets[1];
		packets[0] = packet;
//		DBGTRACE("Calling send_packets at %08X rva(%08X)\n", (int)handle->driver->miniport_char.send_packets, (int)handle->driver->miniport_char.send_packets - image_offset);
		handle->driver->miniport_char.send_packets(handle->adapter_ctx, &packets[0], 1);
		

		if(handle->serialized)
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
	else if(handle->driver->miniport_char.send)
	{
//		DBGTRACE("Calling send at %08X rva(%08X)\n", (int)handle->driver->miniport_char.send, (int)handle->driver->miniport_char.send_packets - image_offset);
		res = handle->driver->miniport_char.send(handle->adapter_ctx, packet, 0);
	}
	else
	{
		DBGTRACE("%s: No send handler\n", __FUNCTION__);
		res = NDIS_STATUS_FAILURE;
	}

	DBGTRACE("send_packets returning %08X\n", res);

	return res;
}


static void xmit_bh(void *param)
{
	struct ndis_handle *handle = (struct ndis_handle*) param;
	struct ndis_buffer *buffer;
	int res;

	DBGTRACE("%s: Enter: send status is %08X\n", __FUNCTION__, handle->send_status);
	while (1)
	{
		res = handle->send_status;

		spin_lock_bh(&handle->xmit_ring_lock);
		if (res || !handle->xmit_ring_pending)
		{
			spin_unlock_bh(&handle->xmit_ring_lock);
			break;
		}
		buffer = handle->xmit_ring[handle->xmit_ring_start];
		spin_unlock_bh(&handle->xmit_ring_lock);

		/* if we are resending a packet due to NDIS_STATUS_RESOURCES
		   then just pick up the packet already created
		*/
		if (!handle->packet)
		{
			/* otherwise, get a new packet */
			handle->packet = init_packet(handle, buffer);
			if (!handle->packet)
			{
				printk(KERN_ERR "%s: couldn't get a packet\n",
				       __FUNCTION__);
				return;
			}
		}

		res = send_packet(handle, handle->packet);
		/* If the driver returns...
		 * NDIS_STATUS_SUCCESS - we own the packet and
		 *    driver will not call NdisMSendComplete.
		 * NDIS_STATUS_PENDING - the driver owns the packet 
		 *    and will return it using NdisMSendComplete.
		 * NDIS_STATUS_RESOURCES - (driver is serialized)
		 *    Requeue it when resources are available.
		 * NDIS_STATUS_FAILURE - drop the packet?
		 */
		switch(res)
		{
		case NDIS_STATUS_SUCCESS:
			sendpacket_done(handle, handle->packet);
			handle->send_status = 0;
			break;
		case NDIS_STATUS_PENDING:
			break;
		case NDIS_STATUS_RESOURCES:
			/* should be serialized driver */
			if (!handle->serialized)
				printk(KERN_ERR "%s: deserialized driver returning NDIS_STATUS_RESOURCES!\n", __FUNCTION__);
			handle->send_status = res;
			/* this packet will be tried again later */
			return;

			/* free buffer, drop the packet */
		case NDIS_STATUS_FAILURE:
			free_buffer(handle, handle->packet);
			break;
		default:
			printk(KERN_ERR "%s: Incorrect status code %08X\n",
			       __FUNCTION__, res);
			free_buffer(handle, handle->packet);
			break;
		}

		spin_lock_bh(&handle->xmit_ring_lock);
		/* mark the packet as done */
		handle->packet = NULL;
		handle->xmit_ring_start =
			(handle->xmit_ring_start + 1) % XMIT_RING_SIZE;
		handle->xmit_ring_pending--;
		if (netif_queue_stopped(handle->net_dev))
			netif_wake_queue(handle->net_dev);
		spin_unlock_bh(&handle->xmit_ring_lock);
	}
	DBGTRACE("%s: Exit, send status = %08X\n", __FUNCTION__, res);
}

/*
 * This function is called in BH disabled context and ndis drivers must have their
 * send-functions called from sleepeable context so we just queue the packets up here
 * and schedule a workqueue to run later.
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

	spin_lock_bh(&handle->xmit_ring_lock);
	xmit_ring_next_slot =
		(handle->xmit_ring_start + handle->xmit_ring_pending) % XMIT_RING_SIZE;
	handle->xmit_ring[xmit_ring_next_slot] = buffer;
	handle->xmit_ring_pending++;
	if (handle->xmit_ring_pending == XMIT_RING_SIZE)
		netif_stop_queue(handle->net_dev);
	spin_unlock_bh(&handle->xmit_ring_lock);

	schedule_work(&handle->xmit_work);

	return 0;
}


/*
 * Free and unmap a packet created in xmit
 */
void sendpacket_done(struct ndis_handle *handle, struct ndis_packet *packet)
{
	DBGTRACE("%s: Enter\n", __FUNCTION__);
	handle->stats.tx_bytes += packet->len;
	handle->stats.tx_packets++;

	free_buffer(handle, packet);
}

static int ndis_suspend(struct pci_dev *pdev, u32 state)
{
	struct net_device *dev;
	struct ndis_handle *handle;
	int res;

	DBGTRACE("%s called with %p, %d\n",
			 __FUNCTION__, pdev, state);
	if (!pdev)
		return -1;
	handle = pci_get_drvdata(pdev);
	if (!handle)
		return -1;
	dev = handle->net_dev;

	if (handle->pm_state != NDIS_PM_STATE_D0)
		return 0;

	res = query_int(handle, NDIS_OID_PNP_QUERY_POWER, &handle->pm_state);
	DBGTRACE("%s: query power to state %d returns %d\n",
			 dev->name, handle->pm_state, res);
	if (res)
		printk(KERN_INFO "%s: device doesn't support pnp capabilities for power management? (%08X)\n", dev->name, res);

	/* do we need this? */
//		DBGTRACE("%s: stopping queue\n", dev->name);
//		netif_stop_queue(dev);

	DBGTRACE("%s: detaching device\n", dev->name);
	netif_device_detach(dev);
	
	if (state == 1)
		handle->pm_state = NDIS_PM_STATE_D1;
	else if (state == 2)
		handle->pm_state = NDIS_PM_STATE_D2;
	else
		handle->pm_state = NDIS_PM_STATE_D3;
	res = set_int(handle, NDIS_OID_PNP_SET_POWER, handle->pm_state);
	pci_save_state(pdev, handle->pci_state);
	pci_set_power_state(pdev, state);
	DBGTRACE("%s: setting power to state %d returns %d\n",
			 dev->name, handle->pm_state, res);
	if (res)
		printk(KERN_INFO "%s: device doesn't support pnp capabilities for power management? (%08X)\n", dev->name, res);
	DBGTRACE(KERN_INFO "%s: device suspended!\n", dev->name);
	return 0;
}

static int ndis_resume(struct pci_dev *pdev)
{
	struct net_device *dev;
	struct ndis_handle *handle;
	int res;

	DBGTRACE("%s called with %p\n",
		 __FUNCTION__, pdev);
	if (!pdev)
		return -1;
	handle = pci_get_drvdata(pdev);
	if (!handle)
		return -1;
	dev = handle->net_dev;

	if (handle->pm_state == NDIS_PM_STATE_D0)
		return 0;
	
	handle->pm_state = NDIS_PM_STATE_D0;
	pci_set_power_state(pdev, 0);
	pci_restore_state(pdev, handle->pci_state);
	res = set_int(handle, NDIS_OID_PNP_SET_POWER, handle->pm_state);
	DBGTRACE("%s: setting power to state %d returns %d\n",
			 dev->name, handle->pm_state, res);
	if (res)
		printk(KERN_INFO "%s: device doesn't support pnp capabilities for power management? (%08X)\n", dev->name, res);
	
	DBGTRACE("%s: attaching device\n", dev->name);
	netif_device_attach(dev);
	
	/* do we need this? */
//		DBGTRACE("%s: starting queue\n", dev->name);
//		netif_wake_queue(dev);
	
	DBGTRACE("%s: device resumed!\n", dev->name);
	return 0;
}

static int setup_dev(struct net_device *dev)
{
	struct ndis_handle *handle = dev->priv;

	unsigned char mac[ETH_ALEN];
	unsigned int written;
	unsigned int needed;

	unsigned int res;
	int i;
	union iwreq_data wrqu;

	if (strlen(if_name) > (IFNAMSIZ-1))
	{
		printk(KERN_ERR "%s: interface name '%s' is too long\n",
		       DRV_NAME, if_name);
		return -1;
	}
	strncpy(dev->name, if_name, IFNAMSIZ-1);
	dev->name[IFNAMSIZ-1] = '\0';

	DBGTRACE("%s: Querying for mac\n", __FUNCTION__);
	res = doquery(handle, 0x01010102, &mac[0], sizeof(mac),
		      &written, &needed);
	DBGTRACE("mac:%02x:%02x:%02x:%02x:%02x:%02x\n",
		 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	if(res)
	{
		printk(KERN_ERR "%s: unable to get mac address from driver\n",
			DRV_NAME);
		return -1;
	}

	memset(&wrqu, 0, sizeof(wrqu));

	wrqu.mode = IW_MODE_INFRA;

	if (ndis_set_mode(dev, NULL, &wrqu, NULL))
		printk(KERN_ERR "%s: Unable to set managed mode\n", DRV_NAME);


	res = query_int(handle, OID_802_3_MAXIMUM_LIST_SIZE, &i);
	if(res == NDIS_STATUS_SUCCESS)
	{
		DBGTRACE("Multicast list size is %d\n", i);
		handle->multicast_list_size = i;
	}

	if(handle->multicast_list_size)
		handle->multicast_list = kmalloc(handle->multicast_list_size * 6, GFP_KERNEL);

	ndis_set_rx_mode_proc(dev);
	
	dev->open = ndis_open;
	dev->hard_start_xmit = start_xmit;
	dev->stop = ndis_close;
	dev->get_stats = ndis_get_stats;
	dev->do_ioctl = ndis_ioctl;
	dev->get_wireless_stats = ndis_get_wireless_stats;
	dev->wireless_handlers	= (struct iw_handler_def *)&ndis_handler_def;
	dev->set_multicast_list = ndis_set_rx_mode;
#ifdef HAVE_ETHTOOL
	dev->ethtool_ops = &ndis_ethtool_ops;
#endif	
	for(i = 0; i < ETH_ALEN; i++)
	{
		dev->dev_addr[i] = mac[i];
	}
	dev->irq = handle->irq;
	dev->mem_start = handle->mem_start;		
	dev->mem_end = handle->mem_end;		
	
	res = register_netdev(dev);
	if (res)
		printk(KERN_ERR "%s: cannot register net device %s\n",
		       DRV_NAME, dev->name);
	else
		printk(KERN_INFO "%s: %s ethernet device "
		       "%02x:%02x:%02x:%02x:%02x:%02x using driver %s\n",
		       dev->name, DRV_NAME,
		       mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], handle->driver->name);
	return res;
}

/*
 * Called by PCI-subsystem for each PCI-card found.
 *
 * This function should not be marked __devinit because ndiswrapper 
 * adds PCI_id's dynamically.
 */
static int ndis_init_one(struct pci_dev *pdev,
                                   const struct pci_device_id *ent)
{
	int res;
	struct ndis_device *device = (struct ndis_device *) ent->driver_data;
	struct ndis_driver *driver = device->driver;
	struct ndis_handle *handle;
	struct net_device *dev;

	DBGTRACE("%s %04x:%04x:%04x:%04x\n", __FUNCTION__, ent->vendor, ent->device, ent->subvendor, ent->subdevice);
	if(device->fuzzy)
	{
		printk(KERN_WARNING "This driver (%s) is not for your hardware. " \
		       "It's likely to work anyway but have it in " \
		       "mind if you have problem.\n", device->driver->name); 
	}
	
	dev = alloc_etherdev(sizeof(*handle));
	if(!dev)
	{
		printk(KERN_ERR "Unable to alloc etherdev\n");
		res = -ENOMEM;
		goto out_nodev;
	}

	SET_MODULE_OWNER(dev);
//	SET_NETDEV_DEV(dev, &pdev->dev);
	handle = dev->priv;

	handle->driver = driver;
	handle->device = device;
	handle->net_dev = dev;
	pci_set_drvdata(pdev, handle);

	init_MUTEX(&handle->query_set_mutex);
	init_waitqueue_head(&handle->query_set_wqhead);

	init_MUTEX(&handle->reset_mutex);
	init_waitqueue_head(&handle->reset_wqhead);

	handle->send_status = 0;
	handle->packet = NULL;

	INIT_WORK(&handle->xmit_work, xmit_bh, handle); 	
	spin_lock_init(&handle->xmit_ring_lock);
	handle->xmit_ring_start = 0;
	handle->xmit_ring_pending = 0;

	spin_lock_init(&handle->recycle_packets_lock);
	INIT_WORK(&handle->packet_recycler, packet_recycler, handle);
	INIT_LIST_HEAD(&handle->recycle_packets);

	INIT_WORK(&handle->set_rx_mode_work, ndis_set_rx_mode_proc, dev);

	INIT_LIST_HEAD(&handle->timers);

	/* Poision this because it may contain function pointers */
	memset(&handle->fill1, 0x12, sizeof(handle->fill1));
	memset(&handle->fill3, 0x14, sizeof(handle->fill3));
	memset(&handle->fill4, 0x15, sizeof(handle->fill4));
	memset(&handle->fill5, 0x16, sizeof(handle->fill5));

	handle->indicate_receive_packet = &NdisMIndicateReceivePacket;
	handle->send_complete = &NdisMSendComplete;
	handle->send_resource_avail = &NdisMSendResourcesAvailable;
	handle->indicate_status = &NdisIndicateStatus;	
	handle->indicate_status_complete = &NdisIndicateStatusComplete;	
	handle->query_complete = &NdisMQueryInformationComplete;	
	handle->set_complete = &NdisMSetInformationComplete;
	handle->reset_complete = &NdisMResetComplete;
	
	handle->map_count = 0;
	handle->map_dma_addr = NULL; 

	handle->ndis_irq_enabled = 0;

	handle->nick[0] = 0;

	handle->pci_dev = pdev;

	handle->hangcheck_interval = 3*HZ;
	handle->scan_timestamp = 0;

	memset(&handle->essid, 0, sizeof(handle->essid));
	memset(&handle->wep_info, 0, sizeof(handle->wep_info));
	
	res = pci_enable_device(pdev);
	if(res)
		goto out_enable;

	res = pci_request_regions(pdev, driver->name);
	if(res)
		goto out_regions;

	pci_set_power_state(pdev, 0);
	pci_restore_state(pdev, NULL);

	if(call_init(handle))
	{
		printk(KERN_ERR "ndiswrapper: Driver init returned error\n");
		res = -EINVAL;
		goto out_start;
	}

	doreset(handle);
	
	if(setup_dev(handle->net_dev))
	{
		printk(KERN_ERR "ndiswrapper: Unable to set up driver\n");
		res = -EINVAL;
		goto out_setup;
	}
	handle->pm_state = NDIS_PM_STATE_D0;
	hangcheck_add(handle);
	statcollector_add(handle);
	ndiswrapper_procfs_add_iface(handle);
	return 0;

out_setup:
	call_halt(handle);
out_start:
	pci_release_regions(pdev);
out_regions:
	pci_disable_device(pdev);
out_enable:
	free_netdev(dev);
out_nodev:
	return res;
}

/*
 * Free the memory that is allocated when a timer is initialized. Also make sure all timers
 * are inactive.
 */
static void fixup_timers(struct ndis_handle *handle)
{
	char x;
	while(!list_empty(&handle->timers))
	{
		struct wrapper_timer *timer = (struct wrapper_timer*) handle->timers.next;
#ifdef DEBUG_TIMER
		printk(KERN_INFO "%s: fixing up timer %p, timer->list %p\n",
		       __FUNCTION__, timer, &timer->list);
#endif
		list_del(&timer->list);
		if(timer->active)
		{
			printk(KERN_WARNING "%s Buggy windows driver %s left "
			       "an active timer. Trying to fix\n",
			       DRV_NAME, handle->driver->name);
			       wrapper_cancel_timer(timer, &x); 
		}
		wrap_kfree(timer);
	}
}


/*
 * Remove one PCI-card (adaptor).
 */
static void __devexit ndis_remove_one(struct pci_dev *pdev)
{
	struct ndis_handle *handle = (struct ndis_handle *) pci_get_drvdata(pdev);

	DBGTRACE("\n%s\n", __FUNCTION__);

	ndiswrapper_procfs_remove_iface(handle);
	statcollector_del(handle);
	hangcheck_del(handle);

	if (!netif_queue_stopped(handle->net_dev))
		netif_stop_queue(handle->net_dev);

	/* Make sure all queued packets have been pushed out from xmit_bh before we call halt */
	flush_scheduled_work();

#ifndef DEBUG_CRASH_ON_INIT
	set_int(handle, NDIS_OID_DISASSOCIATE, 0);
	if(handle->net_dev)
		unregister_netdev(handle->net_dev);
	call_halt(handle);

	fixup_timers(handle);

	/* Make sure any scheduled work is flushed before freeing the handle */
	flush_scheduled_work();

	if(handle->multicast_list)
		kfree(handle->multicast_list);
	if(handle->net_dev)
		free_netdev(handle->net_dev);
#endif


	pci_release_regions(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
}


/*
 * Register one ndis driver with pci subsystem.
 */
static int start_driver(struct ndis_driver *driver)
{
	int res = 0;
	int i;
	struct ndis_device *device;
	
	if(call_entry(driver))
	{
		printk(KERN_ERR "ndiswrapper: Driver entry return error\n");
		return -EINVAL;
	}

	DBGTRACE("%s: Nr devices: %d\n", __FUNCTION__, driver->nr_devices);

	driver->pci_idtable = kmalloc(sizeof(struct pci_device_id)*(driver->nr_devices+1), GFP_KERNEL);
	if(!driver->pci_idtable)
		return -ENOMEM;
	memset(driver->pci_idtable, 0, sizeof(struct pci_device_id)*(driver->nr_devices+1));
	
	device = (struct ndis_device*) driver->devices.next;
	for(i = 0; i < driver->nr_devices; i++)
	{
		driver->pci_idtable[i].vendor = device->pci_vendor;
		driver->pci_idtable[i].device = device->pci_device;
		driver->pci_idtable[i].subvendor = device->pci_subvendor;
		driver->pci_idtable[i].subdevice = device->pci_subdevice;
		driver->pci_idtable[i].class = 0;
		driver->pci_idtable[i].class_mask = 0;
		driver->pci_idtable[i].driver_data = (unsigned long) device;

		DBGTRACE("%s Adding %04x:%04x:%04x:%04x to pci idtable\n", __FUNCTION__, device->pci_vendor, device->pci_device, device->pci_subvendor, device->pci_subdevice);

		device = (struct ndis_device*) device->list.next;
	}

	DBGTRACE("%s", "\n");
	memset(&driver->pci_driver, 0, sizeof(driver->pci_driver));
	driver->pci_driver.name = driver->name;
	driver->pci_driver.id_table = driver->pci_idtable;
	driver->pci_driver.probe = ndis_init_one;
	driver->pci_driver.remove = __devexit_p(ndis_remove_one);	
	driver->pci_driver.suspend = ndis_suspend;
	driver->pci_driver.resume = ndis_resume;
#ifndef DEBUG_CRASH_ON_INIT
	res = pci_module_init(&driver->pci_driver);
	if(!res)
		driver->pci_registered = 1;
#endif
	return res;
	
}


/*
 * Load the driver from userspace.
 */
static struct ndis_driver *load_driver(struct put_file *put_driver)
{
	void *entry;
	struct ndis_driver *driver;
	int namelen;

	DBGTRACE("Putting driver size %d\n", put_driver->size);

	driver = kmalloc(sizeof(struct ndis_driver), GFP_KERNEL);
	if(!driver)
	{
		printk(KERN_ERR "Unable to alloc driver struct\n");
		goto out_nodriver;
	}
	memset(driver, 0, sizeof(struct ndis_driver));
	
	INIT_LIST_HEAD(&driver->devices);
	INIT_LIST_HEAD(&driver->files);

	namelen = sizeof(put_driver->name);
	if(sizeof(driver->name) < namelen)
		namelen = sizeof(driver->name);

	strncpy(driver->name, put_driver->name, namelen-1);
	driver->name[namelen-1] = 0;

	driver->image = vmalloc(put_driver->size);
	DBGTRACE("Image is at %08X\n", (int)driver->image);
	if(!driver->image)
	{
		printk(KERN_ERR "Unable to allocate mem for driver\n");
		goto out_vmalloc;
	}

	if(copy_from_user(driver->image, put_driver->data, put_driver->size))
	{
		printk(KERN_ERR "Failed to copy from user\n");
		goto out_baddriver;
	}

	if(prepare_coffpe_image(&entry, driver->image, put_driver->size))
	{
		printk(KERN_ERR "Unable to prepare driver\n");		
		goto out_baddriver;
	}
	driver->entry = entry;

	return driver;

out_baddriver:
	vfree(driver->image);
out_vmalloc:
	kfree(driver);
out_nodriver:
	return 0;
}

/*
 * Add driver to list of loaded driver but make sure this driver is
 * not loaded before.
 */
static int add_driver(struct ndis_driver *driver)
{
	struct ndis_driver *tmp;
	int dup = 0;
	spin_lock(&driverlist_lock);

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
	spin_unlock(&driverlist_lock);
	if(dup)
	{
		printk(KERN_ERR "Cannot add duplicate driver\n");
		return -EBUSY;
	}
	
	printk(KERN_INFO "ndiswrapper adding %s\n", driver->name);  
	return 0;
}

/*
 * Load a file from userspace and put on list of files.
 */
static int add_file(struct ndis_driver *driver, struct put_file *put_file)
{
	struct ndis_file *file;
	int namelen;

	DBGTRACE("Putting file size %d\n", put_file->size);

	file = kmalloc(sizeof(struct ndis_file), GFP_KERNEL);
	if(!file)
	{
		printk(KERN_ERR "Unable to alloc file struct\n");
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
		printk(KERN_ERR "Unable to allocate mem for file\n");
		goto err;
	}

	if(copy_from_user(file->data, put_file->data, put_file->size))
	{
		printk(KERN_ERR "Failed to copy from user\n");
		goto err;
	}

	list_add(&file->list, &driver->files);

	return 0;
err:
	if(file)
	{
		if(file->data)
			vfree(file->data);
		kfree(file);
	}
	return -ENOMEM;
}



/*
 * Add a new device to a driver.
 */
static struct ndis_device *add_device(struct ndis_driver *driver, struct put_device *put_device)
{
	struct ndis_device *device;
	if (!(device = kmalloc(sizeof(*device), GFP_KERNEL)))
		return NULL;

	memset(device, 0, sizeof(*device));
	INIT_LIST_HEAD(&device->settings);

	device->pci_vendor = put_device->pci_vendor;
	device->pci_device = put_device->pci_device;
	device->pci_subvendor = put_device->pci_subvendor;
	device->pci_subdevice = put_device->pci_subdevice;
	device->fuzzy = put_device->fuzzy;

	DBGTRACE("%s %04x:%04x:%04x:%04x %d\n", __FUNCTION__, device->pci_vendor, device->pci_device, device->pci_subvendor, device->pci_subdevice, device->fuzzy);
	
	if(put_device->pci_subvendor == -1)
	{
		device->pci_subvendor = PCI_ANY_ID;
		device->pci_subdevice = PCI_ANY_ID;
		list_add_tail(&device->list, &driver->devices);
	}
	else
	{
		list_add(&device->list, &driver->devices);
	}
	
	return device;
}


/*
 * Add setting to the list of settings for the device.
 */
static int add_setting(struct ndis_device *device, struct put_setting *put_setting)
{
	struct ndis_setting *setting;

	if (!(setting = kmalloc(sizeof(*setting), GFP_KERNEL)))
		return -ENOMEM;

	memset(setting, 0, sizeof(*setting));

	if (!(setting->name = kmalloc(put_setting->name_len+1, GFP_KERNEL)))
		goto setting_fail;

	if (!(setting->val_str = kmalloc(put_setting->val_str_len+1, GFP_KERNEL)))
		goto name_fail;

	if(copy_from_user(setting->name, put_setting->name,
			  put_setting->name_len))
		goto val_str_fail;

	setting->name[put_setting->name_len] = 0;

	if(copy_from_user(setting->val_str, put_setting->value,
			  put_setting->val_str_len))
		goto val_str_fail;

	setting->val_str[put_setting->val_str_len] = 0;
	setting->value.type = NDIS_SETTING_NONE;

	list_add(&setting->list, &device->settings);
	return 0;

val_str_fail:
	kfree(setting->val_str);
name_fail:
	kfree(setting->name);
setting_fail:
	kfree(setting);
	return -EINVAL;
}


/*
 * Delete a device and all info about it.
 */
static void delete_device(struct ndis_device *device)
{
	struct list_head *curr, *tmp2;
	DBGTRACE("%s\n", __FUNCTION__);

	list_for_each_safe(curr, tmp2, &device->settings)
	{
		struct ndis_setting *setting = (struct ndis_setting*) curr;
		kfree(setting->name);
		kfree(setting->val_str);
		kfree(setting);
	}
	kfree(device);
}


/*
 * Delete a driver. This implies deleting all cards for the handle too.
 */
static void unload_driver(struct ndis_driver *driver)
{
	struct list_head *curr, *tmp2;

	if(driver->pci_registered)
		pci_unregister_driver(&driver->pci_driver);
#ifdef DEBUG_CRASH_ON_INIT
	{
		struct pci_dev *pdev = 0;
		pdev = pci_find_device(driver->pci_idtable[0].vendor, driver->pci_idtable[0].device, pdev);
		if(pdev)
			ndis_remove_one(pdev);
	}
#endif
	spin_lock(&driverlist_lock);
	if(driver->list.next)
		list_del(&driver->list);
	spin_unlock(&driverlist_lock);

	if(driver->image)
		vfree(driver->image);

	if(driver->pci_idtable)
		kfree(driver->pci_idtable);

	list_for_each_safe(curr, tmp2, &driver->files)
	{
		struct ndis_file *file = (struct ndis_file*) curr;
		DBGTRACE("%s Deleting file %s\n", __FUNCTION__, file->name);
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

	DBGTRACE("%s Removing partially loaded driver\n", __FUNCTION__);
	unload_driver((struct ndis_driver *)file->private_data);
	file->private_data = 0;
	DBGTRACE("%s Remove done\n", __FUNCTION__);
	return 0;	
}


static int misc_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg)
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
			device = add_device(driver, &put_device);
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
			{
				struct pci_dev *pdev = 0;
				pdev = pci_find_device(driver->pci_idtable[0].vendor, driver->pci_idtable[0].device, pdev);
				if (pdev)
					ndis_init_one(pdev, &driver->pci_idtable[0]);
			}
#endif
			file->private_data = NULL;
			
			if (res)
				unload_driver(driver);
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
		printk(KERN_ERR "Unknown ioctl %08X\n", cmd);
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


static int __init wrapper_init(void)
{
	char *argv[] = {"loadndisdriver", "-a", 0};
	char *env[] = {0};	
	int err;

	printk(KERN_INFO "ndiswrapper version %s loaded\n", DRV_VERSION);
        if ( (err = misc_register(&wrapper_misc)) < 0 ) {
                printk(KERN_ERR "misc_register failed\n");
		return err;
        }

	ndiswrapper_procfs_init();

	INIT_LIST_HEAD(&wrap_allocs);

	init_ndis_work();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	call_usermodehelper("/sbin/loadndisdriver", argv, env, 1);
#else
	call_usermodehelper("/sbin/loadndisdriver", argv, env);
#endif

	/* Wait a little to let card power up otherwise ifup might fail on boot */
	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(2*HZ);
	return 0;
}

static void __exit wrapper_exit(void)
{
	while(!list_empty(&ndis_driverlist))
	{
		struct ndis_driver *driver = (struct ndis_driver*) ndis_driverlist.next;
		unload_driver(driver);
	}
	
	ndiswrapper_procfs_remove();
	misc_deregister(&wrapper_misc);
	wrap_kfree_all();
}

module_init(wrapper_init);
module_exit(wrapper_exit);

MODULE_LICENSE("GPL");

