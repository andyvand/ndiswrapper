/*
 *  Copyright (C) 2003 Pontus Fuchs
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

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/miscdevice.h>
#include <linux/pci.h>

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/wireless.h>
#include <linux/if_arp.h>
#include <net/iw_handler.h>

#include <asm/uaccess.h>

#include "wrapper.h"
#include "loader.h"
#include "ndis.h"

#define DRV_NAME "ndiswrapper"
#define DRV_VERSION "0.1+CVS"

/* Define this if you are developing and ndis_init_one crashes.
   When using the old PCI-API a reboot is not needed when this
   function crashes. A simple rmmod -f will do the trick and
   you can try again.
*/

/*#define DEBUG_CRASH_ON_INIT*/

/* List of loaded drivers */
static LIST_HEAD(driverlist);

/* Protects driver list */
static spinlock_t driverlist_lock = SPIN_LOCK_UNLOCKED;

extern int image_offset;


/*
 * Perform a sync query and deal with the possibility of an async query.
 *
 */
static int doquery(struct ndis_handle *handle, unsigned int oid, char *buf, int bufsize, unsigned int *written , unsigned int *needed)
{
	int res;

	spin_lock(&handle->query_lock);

	handle->query_wait_done = 0;
	DBGTRACE("Calling query at %08x rva(%08x)\n", (int)handle->driver->miniport_char.query, (int)handle->driver->miniport_char.query - image_offset);
	res = handle->driver->miniport_char.query(handle->adapter_ctx, oid, buf, bufsize, written, needed);

	if(!res)
		goto out;

	if(res != NDIS_STATUS_PENDING)
		goto out;
		
	/* This is a very bad way to wait but we cannot sleap here as when ifconfig gathers statistics we
	 * get a query from a context where is_atomic() = 1
	 */
	while(handle->query_wait_done == 0);
	 
	res = handle->query_wait_res;

out:
	spin_unlock(&handle->query_lock);
	return res;
	
}


/*
 *
 *
 * Called via function pointer if query returns NDIS_STATUS_PENDING
 */
STDCALL void NdisMQueryInformationComplete(struct ndis_handle *handle, unsigned int status)
{
	DBGTRACE("%s: %08x\n", __FUNCTION__, status);
	handle->query_wait_res = status;
	handle->query_wait_done = 1;
}



/*
 * Make a query that has an int as the result.
 *
 */
static int query_int(struct ndis_handle *handle, int oid, int *data)
{
	unsigned int res, written, needed;

	res = doquery(handle, oid, (char*)data, 4, &written, &needed);
	if(!res)
		return 0;
	*data = 0;
	return res;
}

/*
 * Set an int
 *
 */
static int set_int(struct ndis_handle *handle, int oid, int data)
{
	unsigned int written, needed;

	return handle->driver->miniport_char.setinfo(handle->adapter_ctx, oid, (char*)&data, sizeof(int), &written, &needed);
}


static int ndis_set_essid(struct net_device *dev,
			    struct iw_request_info *info,
			    union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv; 
	unsigned int res, written, needed;
	struct essid_req req;

	if(wrqu->essid.length > 33)
	{
		printk(KERN_ERR "%s: ESSID too long\n", __FUNCTION__);
		return -1;
	}

	memset(&req.essid, 0, sizeof(req.essid));
	memcpy(&req.essid, extra, wrqu->essid.length-1);
	
	req.len = wrqu->essid.length-1;
	res = handle->driver->miniport_char.setinfo(handle->adapter_ctx, NDIS_OID_ESSID, (char*)&req, sizeof(req), &written, &needed);
	if(res)
	{
		DBGTRACE("set_essid returned failure: %08x\n", res); 
		return -1;
	}
	
	return 0;
}

static int ndis_get_essid(struct net_device *dev,
			    struct iw_request_info *info,
			    union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv; 
	unsigned int res, written, needed;
	struct essid_req req;

	res = doquery(handle, NDIS_OID_ESSID, (char*)&req, sizeof(req), &written, &needed);
	if(res)
		return -1;

	memcpy(extra, &req.essid, req.len);	
	extra[req.len] = 0;
	wrqu->essid.flags  = 1;
	wrqu->essid.length = req.len + 1;
	return 0;
}


static int ndis_set_mode(struct net_device *dev, struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	int ndis_mode;
	int res;
	switch(wrqu->mode)
	{
	case IW_MODE_ADHOC:
		ndis_mode = 0;
		break;	
	case IW_MODE_INFRA:
		ndis_mode = 1;
		break;	
	default:
		printk(KERN_ERR "%s Unknown mode %d\n", __FUNCTION__, wrqu->mode);	
		return -1;
	}
	
	res = set_int(dev->priv, NDIS_OID_MODE, ndis_mode);
	if(res)
	{
		DBGTRACE("set_mode returned failure: %08x\n", res); 
		return -1;
	}
	
	return 0;
}

static int ndis_get_mode(struct net_device *dev, struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv; 
	int ndis_mode, mode;

	int res = query_int(handle, NDIS_OID_MODE, &ndis_mode);
	if(res)
		return -1;

	switch(ndis_mode)
	{
	case 0:
		mode = IW_MODE_ADHOC;
		break;
	case 1:
		mode = IW_MODE_INFRA;
		break;
	default:
		printk(KERN_ERR "%s Unknown mode\n", __FUNCTION__);
		return -1;
		break;
	}
	wrqu->mode = mode;
	return 0;
}


static int ndis_get_name(struct net_device *dev, struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv;
	unsigned int network_type, res;
	const char *types[] = {"IEEE 802.11b", "IEEE 802.11-DS",
		"IEEE 802.11-FDM5", "IEEE 802.11g"};

	res = query_int(handle, NDIS_OID_NETWORK_TYPE_IN_USE, &network_type);
	if (res)
		strncpy(wrqu->name, "IEEE 802.11", sizeof(wrqu->name)-1);
	else
		if (network_type >= 0 && 
			network_type <= (sizeof(types)/sizeof(types[0])))
			strncpy(wrqu->name, types[network_type], sizeof(wrqu->name)-1);
		else
			strncpy(wrqu->name, "IEEE 802.11", sizeof(wrqu->name)-1);

	wrqu->name[sizeof(wrqu->name)-1] = 0;
	return 0;
}

static int ndis_get_freq(struct net_device *dev, struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv;
	unsigned int res, written, needed;
	struct ndis_configuration req;

	res = doquery(handle, NDIS_OID_CONFIGURATION, (char*)&req, sizeof(req), &written, &needed);
	if(res)
		return -1;

	memset(&(wrqu->freq), 0, sizeof(struct iw_freq));

	/* see comment in wireless.h above the "struct iw_freq"
	   definition for an explanation of this if
	   NOTE: 1000000 is due to the kHz
	*/
	if (req.ds_config > 1000000)
	{
		wrqu->freq.m = req.ds_config / 10;
		wrqu->freq.e = 1;
	}
	else
		wrqu->freq.m = req.ds_config;

	/* convert from kHz to Hz */
	wrqu->freq.e += 3;
	return 0;
}

static int ndis_get_tx_power(struct net_device *dev, struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv; 
	int ndis_power;

	int res = query_int(handle, NDIS_OID_MODE, &ndis_power);
	if(res)
		return -1;

	/* TODO: convert mW to dBm but, without floating point we
	   could at best do a table, so for now just
	   return the mW * 1000 as an obviously bogus value.
	*/
	wrqu->power.value = ndis_power * 1000;
	return 0;
}

static int ndis_get_bitrate(struct net_device *dev, struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv; 
	int ndis_rate;

	/* not sure if this is the corrent OID or if it gives only the max rate */
	int res = query_int(handle, NDIS_OID_GEN_SPEED, &ndis_rate);
	if(res)
		return -1;

	/* *of course* windows specifies the rate in multiples of 100 */
	wrqu->bitrate.value = ndis_rate * 100;
	return 0;
}

static int ndis_get_rts_threshold(struct net_device *dev, struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv;
	int ndis_rts_threshold;

	int res = query_int(handle, NDIS_OID_RTS_THRESH, &ndis_rts_threshold);
	if(res)
		return -1;

	wrqu->rts.value = ndis_rts_threshold;
	return 0;
}

static int ndis_get_frag_threshold(struct net_device *dev, struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv; 
	int ndis_frag_threshold;

	int res = query_int(handle, NDIS_OID_FRAG_THRESH, &ndis_frag_threshold);
	if(res)
		return -1;

	wrqu->frag.value = ndis_frag_threshold;
	return 0;
}

static int ndis_get_ap_address(struct net_device *dev, struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv; 
	unsigned int res, written, needed;
	__u8 mac_address[6];

	res = doquery(handle, NDIS_OID_BSSID, (char*)&mac_address, sizeof(mac_address), &written, &needed);
	if(res)
		return -1;

        memcpy(wrqu->ap_addr.sa_data, mac_address, 6);
        wrqu->ap_addr.sa_family = ARPHRD_ETHER;
        return 0;
}

static int ndis_set_wep(struct net_device *dev, struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv;
	unsigned int res, written, needed, auth_mode;
	struct wep_req req;

	if (wrqu->data.flags & IW_ENCODE_NOKEY)
	{
		res = set_int(handle, NDIS_OID_WEP_STATUS, NDIS_ENCODE_NOKEY);
		if (res)
			return -1;
		else
			return 0;
	}
	if (wrqu->data.flags & IW_ENCODE_DISABLED)
	{
		res = set_int(handle, NDIS_OID_WEP_STATUS, NDIS_ENCODE_DISABLED);
	}
	else
	{
		req.len = sizeof(struct wep_req);
		req.keyindex = wrqu->data.flags & IW_ENCODE_INDEX;
		req.keyindex |= (1 << 31);
		req.keylength = wrqu->data.length;
		
		handle->driver->key_len = req.keylength;
		memcpy(handle->driver->key_val, wrqu->data.pointer,
				req.keylength);
		memcpy(req.keymaterial, handle->driver->key_val, req.keylength);
		
		res = handle->driver->miniport_char.setinfo(handle->adapter_ctx, NDIS_OID_ADD_WEP, (char*)&req, sizeof(req), &written, &needed);

		if (res)
			return -1;
		
		res = set_int(handle, NDIS_OID_WEP_STATUS, NDIS_ENCODE_ENABLED);
		if (res)
			return -1;

		if (wrqu->data.flags & IW_ENCODE_OPEN)
			auth_mode = NDIS_ENCODE_OPEN;
		else
			auth_mode = NDIS_ENCODE_RESTRICTED;
		/* Ndis has another flag Ndis802_11AuthModeAutoSwitch
		 * However, there is no equivalent IW_ENCODE flag for it
		 */
		res = set_int(handle, NDIS_OID_AUTH_MODE, auth_mode);

		if (res)
			return -1;
	}
	return 0;
}

static int ndis_get_wep(struct net_device *dev, struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv;
	int status, res;

	res = query_int(handle, NDIS_OID_WEP_STATUS, &status);
	if (res)
		return -1;
	
	if (status & NDIS_ENCODE_ENABLED)
		wrqu->data.flags |= IW_ENCODE_ENABLED;
	else if (status & NDIS_ENCODE_DISABLED)
		wrqu->data.flags |= IW_ENCODE_DISABLED;
	else if (status & NDIS_ENCODE_NOKEY)
		wrqu->data.flags |= IW_ENCODE_NOKEY;

	res = query_int(handle, NDIS_OID_AUTH_MODE, &status);
	if (res)
		return -1;
	if (status & NDIS_ENCODE_OPEN)
		wrqu->data.flags |= IW_ENCODE_OPEN;
	if (status & NDIS_ENCODE_RESTRICTED)
		wrqu->data.flags |= IW_ENCODE_RESTRICTED;
	if (status & NDIS_ENCODE_OPEN_RESTRICTED)
		wrqu->data.flags |= (IW_ENCODE_OPEN | IW_ENCODE_RESTRICTED);

	wrqu->data.length = handle->driver->key_len;
	memcpy(extra, handle->driver->key_val, handle->driver->key_len);

	return 0;
}
	
static const iw_handler	ndis_handler[] = {
	//[SIOCGIWSENS    - SIOCIWFIRST] = ndis_get_sens,
	[SIOCGIWNAME	- SIOCIWFIRST] = ndis_get_name,
	[SIOCSIWESSID	- SIOCIWFIRST] = ndis_set_essid,
	[SIOCGIWESSID	- SIOCIWFIRST] = ndis_get_essid,
	[SIOCSIWMODE	- SIOCIWFIRST] = ndis_set_mode,
	[SIOCGIWMODE	- SIOCIWFIRST] = ndis_get_mode,
	[SIOCGIWFREQ	- SIOCIWFIRST] = ndis_get_freq,
	[SIOCGIWTXPOW	- SIOCIWFIRST] = ndis_get_tx_power,
	[SIOCGIWRATE	- SIOCIWFIRST] = ndis_get_bitrate,
	[SIOCGIWRTS	- SIOCIWFIRST] = ndis_get_rts_threshold,
	[SIOCGIWFRAG	- SIOCIWFIRST] = ndis_get_frag_threshold,
	//[SIOCSIWRETRY	- SIOCIWFIRST] = ndis_get_rety_limit,
	[SIOCGIWAP	- SIOCIWFIRST] = ndis_get_ap_address,
	[SIOCSIWENCODE	- SIOCIWFIRST] = ndis_set_wep,
	[SIOCGIWENCODE	- SIOCIWFIRST] = ndis_get_wep,
};

static const struct iw_handler_def ndis_handler_def = {
	.num_standard	= sizeof(ndis_handler) / sizeof(iw_handler),
	.standard	= (iw_handler *)ndis_handler,
};


static int call_init(struct ndis_handle *handle)
{
	__u32 res, res2;
	__u32 selected_medium;
	__u32 mediumtypes[] = {0,1,2,3,4,5,6,7,8,9,10,11,12};
	DBGTRACE("Calling init at %08x rva(%08x)\n", (int)handle->driver->miniport_char.init, (int)handle->driver->miniport_char.init - image_offset);
	res = handle->driver->miniport_char.init(&res2, &selected_medium, mediumtypes, 13, handle, handle);
	DBGTRACE("past init res: %08x\n\n", res);
	return res != 0;
}

static void call_halt(struct ndis_handle *handle)
{
	DBGTRACE("Calling halt at %08x rva(%08x)\n", (int)handle->driver->miniport_char.halt, (int)handle->driver->miniport_char.halt - image_offset);
	handle->driver->miniport_char.halt(handle->adapter_ctx);
}

static unsigned int call_entry(struct ndis_driver *driver)
{
	int res;
	char regpath[] = {'a', 0, 'b', 0, 0, 0};
	DBGTRACE("Calling entry at %08x rva(%08x)\n", (int)driver->entry, (int)driver->entry - image_offset);
	res = driver->entry((void*)driver, regpath);
	DBGTRACE("Past entry: Version: %d.%d\n\n\n", driver->miniport_char.majorVersion, driver->miniport_char.minorVersion);

	/* Dump addresses of driver suppoled callbacks */
#ifdef DEBUG
	{
		int i;
		int *adr = (int*) &driver->miniport_char.CheckForHangTimer;
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
/*
				"CoCreateVcHandler",
				"CoDeleteVcHandler",	
				"CoActivateVcHandler",
				"CoDeactivateVcHandler",
				"CoSendPacketsHandler",
				"CoRequestHandler"
*/
		};
		
		for(i = 0; i < 16; i++)
		{
			DBGTRACE("%08x (rva %08x):%s\n", adr[i], adr[i]?adr[i] - image_offset:0, name[i]); 
		}
	}
#endif
	return res;
}


static int ndis_open(struct net_device *dev)
{
	DBGTRACE("%s\n", __FUNCTION__);
	return 0;
}


static int ndis_close(struct net_device *dev)
{
	DBGTRACE("%s\n", __FUNCTION__);
	return 0;
}


static struct net_device_stats *ndis_get_stats(struct net_device *dev)
{
	struct ndis_handle *handle = dev->priv;
	struct net_device_stats *stats = &handle->stats;
	unsigned int x;

	if(!query_int(handle, NDIS_OID_STAT_TX_OK, &x))
		stats->tx_packets = x; 
	if(!query_int(handle, NDIS_OID_STAT_RX_OK, &x))
		stats->rx_packets = x; 	
	if(!query_int(handle, NDIS_OID_STAT_TX_ERROR, &x))
		stats->tx_errors = x; 	
	if(!query_int(handle, NDIS_OID_STAT_RX_ERROR, &x))
		stats->rx_errors = x; 	
	return stats;
}


static struct iw_statistics *ndis_get_wireless_stats(struct net_device *dev)
{
	struct ndis_handle *handle = dev->priv;
	struct iw_statistics *stats = &handle->wireless_stats;
	int x;

	if(!query_int(handle, NDIS_OID_RSSI, &x))
		stats->qual.level = x;
		
	return stats;
}


static int ndis_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	int rc = -ENODEV;
	return rc;
}

/*
 * This can probably be done a lot more effective (no copy of data needed).
 *
 *
 */
static int ndis_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ndis_handle *handle = dev->priv;
	struct ndis_buffer *buffer;
	struct ndis_packet *packet;
	int i = 0;
	
	char *data = kmalloc(skb->len, GFP_ATOMIC);
	if(!data)
	{
		return 0;
	}

	buffer = kmalloc(sizeof(struct ndis_buffer), GFP_ATOMIC);
	if(!buffer)
	{
		kfree(data);
		return 0;
	}

	packet = kmalloc(sizeof(struct ndis_packet), GFP_ATOMIC);
	if(!packet)
	{
		kfree(data);
		kfree(buffer);
		return 0;
	}
	
	memset(packet, 0, sizeof(*packet));

#ifdef DEBUG
	{
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
		packet->dataphys = pci_map_single(handle->pci_dev, data, skb->len, PCI_DMA_TODEVICE);
		packet->scatterlist.len = 1;
		packet->scatterlist.entry.physlo = packet->dataphys;		
		packet->scatterlist.entry.physhi = 0;		
		packet->scatterlist.entry.len = skb->len;
		packet->scatter_gather_ext = &packet->scatterlist; 
	}

	packet->oob_offset = (int)(&packet->timesent1) - (int)packet;

	buffer->data = data;
	buffer->next = 0;
	buffer->len = skb->len;

	packet->nr_pages = 1;
	packet->len = buffer->len;
	packet->count = 1;
	packet->valid_counts = 1;

	packet->buffer_head = buffer;
	packet->buffer_tail = buffer;

	//DBGTRACE("Buffer: %08x, data %08x, len %d\n", (int)buffer, (int)buffer->data, (int)buffer->len); 	

	skb_copy_and_csum_dev(skb, data);
	dev_kfree_skb(skb);
//	DBGTRACE("Calling send_packets at %08x rva(%08x). sp:%08x\n", (int)handle->miniport_char.send_packets, (int)handle->miniport_char.send_packets - image_offset, getSp());

	if(handle->driver->miniport_char.send_packets)
	{
		struct ndis_packet *packets[1];
		packets[0] = packet;
		handle->driver->miniport_char.send_packets(handle->adapter_ctx, &packets[0], 1);
	}
	else if(handle->driver->miniport_char.send)
	{
		int res = handle->driver->miniport_char.send(handle->adapter_ctx, packet, 0);

		if(res == NDIS_STATUS_PENDING)
		{
			return 0;
		}
		ndis_sendpacket_done(handle, packet);
		return 0;
	}
	else
	{
		DBGTRACE("%s: No send handler\n", __FUNCTION__);
	}

	return 0;
}

/*
 * Free and unmap a packet created in xmit
 */
void ndis_sendpacket_done(struct ndis_handle *handle, struct ndis_packet *packet)
{
	if(packet->dataphys)
	{
		pci_unmap_single(handle->pci_dev, packet->dataphys, packet->len, PCI_DMA_TODEVICE);
	}
	
	kfree(packet->buffer_head->data);
	kfree(packet->buffer_head);
	kfree(packet);
}






static int setup_dev(struct net_device *dev)
{
	struct ndis_handle *handle = dev->priv;

	unsigned char mac[6];
	unsigned int written;
	unsigned int needed;

	unsigned int res;
	int i;

	DBGTRACE("%s: Querying for mac\n", __FUNCTION__);
	res = doquery(handle, 0x01010102, &mac[0], sizeof(mac), &written, &needed);
	DBGTRACE("mac:%02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	if(res)
	{
		printk(KERN_ERR "Unable to get MAC-addr from driver\n");
		return -1;
	}

	dev->open = ndis_open;
	dev->hard_start_xmit = ndis_start_xmit;
	dev->stop = ndis_close;
	dev->get_stats = ndis_get_stats;
	dev->do_ioctl = ndis_ioctl;
	dev->get_wireless_stats = ndis_get_wireless_stats;
	dev->wireless_handlers	= (struct iw_handler_def *)&ndis_handler_def;
	
	for(i = 0; i < 6; i++)
	{
		dev->dev_addr[i] = mac[i];
	}
	dev->irq = handle->irq;
	dev->mem_start = handle->mem_start;		
	dev->mem_end = handle->mem_end;		

	handle->driver->key_len = 0;

	return register_netdev(dev);
}


/*
 * Called by PCI-subsystem for each PCI-card found.
 */
static int __devinit ndis_init_one(struct pci_dev *pdev,
                                   const struct pci_device_id *ent)
{
	int res;
	struct ndis_driver *driver = (struct ndis_driver *) ent->driver_data;
	struct ndis_handle *handle;
	struct net_device *dev;

	DBGTRACE("%s\n", __FUNCTION__);

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
	handle->net_dev = dev;
	pci_set_drvdata(pdev, handle);

	/* Poision this because it may contain function pointers */
	memset(&handle->fill1, 0x12, sizeof(handle->fill1));
	memset(&handle->fill2, 0x13, sizeof(handle->fill2));
	memset(&handle->fill3, 0x14, sizeof(handle->fill3));
	memset(&handle->fill4, 0x15, sizeof(handle->fill3));

	handle->indicate_receive_packet = &NdisMIndicateReceivePacket;
	handle->send_complete = &NdisMSendComplete;
	handle->indicate_status = &NdisIndicateStatus;	
	handle->indicate_status_complete = &NdisIndicateStatusComplete;	
	handle->query_complete = &NdisMQueryInformationComplete;	

	handle->pci_dev = pdev;
	
	res = pci_enable_device(pdev);
	if(res)
		goto out_enable;

	res = pci_request_regions(pdev, driver->name);
	if(res)
		goto out_regions;

	if(call_init(handle))
	{
		printk(KERN_ERR "ndiswrapper: Driver init returned error\n");
		res = -EINVAL;
		goto out_start;
	}
	
	if(setup_dev(handle->net_dev))
	{
		printk(KERN_ERR "ndiswrapper: Unable to set up driver\n");
		res = -EINVAL;
		goto out_start;
	}
	return 0;

out_start:
	pci_release_regions(pdev);
out_regions:
	pci_disable_device(pdev);
out_enable:
	free_netdev(dev);
out_nodev:
	return res;
}

static void __devexit ndis_remove_one(struct pci_dev *pdev)
{
	struct ndis_handle *handle = (struct ndis_handle *) pci_get_drvdata(pdev);

	DBGTRACE("%s\n", __FUNCTION__);

#ifndef DEBUG_CRASH_ON_INIT
	unregister_netdev(handle->net_dev);
	call_halt(handle);

	if(handle->net_dev)
		free_netdev(handle->net_dev);
#endif
	pci_release_regions(pdev);
	pci_disable_device(pdev);
}


static int misc_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg);


static struct file_operations wrapper_fops = {
	.owner          = THIS_MODULE,
	.ioctl		= misc_ioctl,
};

static struct miscdevice wrapper_misc = {
	.name   = DRV_NAME,
	.fops   = &wrapper_fops
};


/*
 * Register driver with pci subsystem.
 */
static int start_driver(struct ndis_driver *driver)
{
	int res = 0;

	if(call_entry(driver))
	{
		printk(KERN_ERR "ndiswrapper: Driver entry return error\n");
		return -EINVAL;
	}


	driver->pci_driver.name = driver->name;
	driver->pci_driver.id_table = driver->pci_id;
	driver->pci_driver.probe = ndis_init_one;
	driver->pci_driver.remove = ndis_remove_one;	
	
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
static struct ndis_driver *load_driver(struct put_driver *put_driver)
{
	void *entry;
	struct ndis_driver *driver;
	struct pci_dev *pdev = 0;
	int namelen;

	DBGTRACE("Putting driver size %d\n", put_driver->size);

	driver = kmalloc(sizeof(struct ndis_driver), GFP_KERNEL);
	if(!driver)
	{
		printk(KERN_ERR "Unable to alloc driver struct\n");
		goto out_nodriver;
	}
	memset(driver, 0, sizeof(struct ndis_driver));
	
	INIT_LIST_HEAD(&driver->settings);

	namelen = sizeof(put_driver->name);
	if(sizeof(driver->name) < namelen)
		namelen = sizeof(driver->name);

	strncpy(driver->name, put_driver->name, namelen-1);
	driver->name[namelen-1] = 0;

	driver->image = vmalloc(put_driver->size);
	DBGTRACE("Image is at %08x\n", (int)driver->image);
	if(!driver->image)
	{
		printk(KERN_ERR "Unable to allocate mem for driver\n");
		goto out_vmalloc;
	}

	if(copy_from_user(driver->image, put_driver->data, put_driver->size))
	{
		printk(KERN_ERR "Failed to copy from user\n");
		goto out_vmalloc;
	}


	if(prepare_coffpe_image(&entry, driver->image, put_driver->size))
	{
		printk(KERN_ERR "Unable to prepare driver\n");		
		goto out_baddriver;
	}

	/* Make sure PCI device is present */
	pdev = pci_find_device(put_driver->pci_vendor, put_driver->pci_device, pdev);
	if(!pdev)
	{
		printk(KERN_ERR "PCI device %04x:%04x not present\n", put_driver->pci_vendor, put_driver->pci_device);
		goto out_baddriver;
	}
	
	driver->pci_id[0].vendor = put_driver->pci_vendor;
	driver->pci_id[0].device = put_driver->pci_device;
	driver->pci_id[0].subvendor = PCI_ANY_ID;
	driver->pci_id[0].subdevice = PCI_ANY_ID;
	driver->pci_id[0].class = 0;
	driver->pci_id[0].class_mask = 0;
	driver->pci_id[0].driver_data = (int)driver;
	
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

	list_for_each_entry(tmp, &driverlist, list)
	{
		if(tmp->pci_id[0].vendor == driver->pci_id[0].vendor &&
		   tmp->pci_id[0].device == driver->pci_id[0].device)
	   	{
			dup = 1;
			break;
		}

		if(strcmp(tmp->name, driver->name) == 0)
		{
			dup = 1;
			break;
		}
		
	}
	if(!dup)
		list_add(&driver->list, &driverlist);
	spin_unlock(&driverlist_lock);
	if(dup)
	{
		printk(KERN_ERR "Cannot add duplicate driver\n");
		return -EBUSY;
	}
	

	return 0;
}



/*
 * Add setting to the list of settings for the driver.
 */
static int add_setting(struct ndis_driver *driver, struct put_setting *put_setting)
{
	struct ndis_setting *setting;

	char *name;
	unsigned int val;
	
	if(put_setting->payload_len != sizeof(val))
	{
		return -EINVAL;
	}
	if(copy_from_user(&val, put_setting->payload, sizeof(val)))
		return -EINVAL;

	name = kmalloc(put_setting->name_len+1, GFP_KERNEL);
	if(!name)
		return -ENOMEM;


	setting = kmalloc(sizeof(*setting), GFP_KERNEL);
	if(!setting)
	{
		kfree(name);
		return -ENOMEM;
	}
	memset(setting, 0, sizeof(*setting));
	
	if(copy_from_user(name, put_setting->name, put_setting->name_len))
	{
		kfree(name);
		kfree(setting);
		return -EINVAL;
	}
	name[put_setting->name_len] = 0;

	setting->val.type = 0;
	setting->name = name;
	setting->val.type = 0;
	setting->val.data.intval = val;	
	
	list_add(&setting->list, &driver->settings);
	return 0;
}

/*
 * Delete a driver. This implies deleting all cards for the handle too.
 */
static void unload_driver(struct ndis_driver *driver)
{
	struct list_head *curr, *tmp2;

	DBGTRACE("%s\n", __FUNCTION__);
	if(driver->pci_registered)
		pci_unregister_driver(&driver->pci_driver);
#ifdef DEBUG_CRASH_ON_INIT
	{
		struct pci_dev *pdev = 0;
		pdev = pci_find_device(driver->pci_id[0].vendor, driver->pci_id[0].device, pdev);
		if(pdev)
			ndis_remove_one(pdev);
	}
#endif
	spin_lock(&driverlist_lock);
	list_del(&driver->list);
	spin_unlock(&driverlist_lock);

	if(driver->image)
		vfree(driver->image);

	list_for_each_safe(curr, tmp2, &driver->settings)
	{
		struct ndis_setting *setting = (struct ndis_setting*) curr;
		kfree(setting->name);
		kfree(setting);
	}
	kfree(driver);
}

static int misc_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg)
{
	struct put_setting put_setting;
	struct put_driver put_driver;
	struct ndis_driver *driver;

	switch(cmd) {
	case NDIS_PUTDRIVER:
		if(copy_from_user(&put_driver, (void*)arg, sizeof(struct put_driver)))
			return -EINVAL;

		driver = load_driver(&put_driver);
		if(!driver)
			return -EINVAL;
		file->private_data = driver;

		return add_driver(driver);
		break;

	case NDIS_STARTDRIVER:
		if(file->private_data)
		{
			struct ndis_driver *driver= file->private_data;
			int res = start_driver(driver);
#ifdef DEBUG_CRASH_ON_INIT
			{
				struct pci_dev *pdev = 0;
				pdev = pci_find_device(driver->pci_id[0].vendor, driver->pci_id[0].device, pdev);
				if(pdev)
					ndis_init_one(pdev, &driver->pci_id[0]);
			}
#endif
			file->private_data = NULL;

			if(res)
			{
				unload_driver(driver);
				return res;
			}
		}
		break;
	case NDIS_PUTSETTING:
		if(file->private_data)
		{
			int res;
			struct ndis_driver *driver = file->private_data;
			if(copy_from_user(&put_setting, (void*)arg, sizeof(struct put_setting)))
				return -EINVAL;
			res = add_setting(driver, &put_setting);
			if(res)
				return res;
		}
	
		break;
	case NDIS_CANCELLOAD:
		if(file->private_data)
		{
			struct ndis_driver *driver = file->private_data;
			unload_driver(driver);
		}
		
		break;	
	default:
		printk(KERN_ERR "Unknown ioctl %08x\n", cmd);
		return -EINVAL;
		break;
	}	

	return 0;
}

void init_ndis_work(void);

static int __init wrapper_init(void)
{
	int err;

	printk(KERN_INFO "ndiswrapper version %s loaded\n", DRV_VERSION);
        if ( (err = misc_register(&wrapper_misc)) < 0 ) {
                printk(KERN_ERR "misc_register failed\n");
		return err;
        }

	init_ndis_work();
	return 0;
}

static void __exit wrapper_exit(void)
{
	while(!list_empty(&driverlist))
	{
		struct ndis_driver *driver = (struct ndis_driver*) driverlist.next;
		unload_driver(driver);
	}
	
	misc_deregister(&wrapper_misc);
}

module_init(wrapper_init);
module_exit(wrapper_exit);

MODULE_LICENSE("GPL");

