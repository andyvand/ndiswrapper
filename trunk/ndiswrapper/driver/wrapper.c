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
#include <linux/workqueue.h>

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/wireless.h>
#include <net/iw_handler.h>

#include <asm/uaccess.h>

#include "wrapper.h"
#include "loader.h"
#include "ndis.h"

static int pci_vendor = 0x14e4;
static int pci_device = 0x4301;

static struct net_device *thedev;

static int misc_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg);

extern int image_offset;

static struct file_operations wrapper_fops = {
	.owner          = THIS_MODULE,
	.ioctl		= misc_ioctl,
};

static struct miscdevice wrapper_misc = {
	.name   = "ndiswrapper",
	.fops   = &wrapper_fops
};

/*
 * Make a query that has an int as the result.
 *
 */
static int query_int(struct ndis_handle *handle, int oid, int *data)
{
	unsigned int res, written, needed;

	res = handle->miniport_char.query(handle->adapter_ctx, oid, (char*)data, 4, &written, &needed);
	if(!res)
		return 0;
	*data = 0;
	return -1;
}

/*
 * Set an int
 *
 */
static int set_int(struct ndis_handle *handle, int oid, int data)
{
	unsigned int res, written, needed;

	res = handle->miniport_char.setinfo(handle->adapter_ctx, oid, (char*)&data, sizeof(int), &written, &needed);
	if(!res)
		return 0;
	return -1;
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
		DBGTRACE("%s: ESSID too long\n", __FUNCTION__);
		return -1;
	}

	
	memset(&req.essid, 0, sizeof(req.essid));
	memcpy(&req.essid, extra, wrqu->essid.length-1);

	res = handle->miniport_char.setinfo(handle->adapter_ctx, NDIS_OID_ESSID, (char*)&req, sizeof(req), &written, &needed);
	DBGTRACE("set essid status %08x, %d, %d\n", res, written, needed);
	if(res)
		return -1;
	return 0;


}

static int ndis_get_essid(struct net_device *dev,
			    struct iw_request_info *info,
			    union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv; 
	unsigned int res, written, needed;
	struct essid_req req;

	res = handle->miniport_char.query(handle->adapter_ctx, NDIS_OID_ESSID, (char*)&req, sizeof(req), &written, &needed);
	DBGTRACE("get essid status %08x, %d, %d\n", res, written, needed);
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
	DBGTRACE("%s\n", __FUNCTION__);

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
	
	set_int(dev->priv, NDIS_OID_MODE, ndis_mode);
	return 0;
}

static int ndis_get_mode(struct net_device *dev, struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv; 
	int ndis_mode, mode;

	DBGTRACE("%s\n", __FUNCTION__);
	int res = query_int(handle, NDIS_OID_MODE, &ndis_mode);
	if(!res)
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
	DBGTRACE("returned mode %d\n", mode);
	return 0;	
}


static int ndis_get_name(struct net_device *dev, struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	strlcpy(wrqu->name, "IEEE 802.11-DS", sizeof(wrqu->name));
	return 0;
}


static const iw_handler	ndis_handler[] = {
	//[SIOCGIWSENS    - SIOCIWFIRST] = ndis_get_sens,
	[SIOCGIWNAME	- SIOCIWFIRST] = ndis_get_name,
	[SIOCSIWESSID	- SIOCIWFIRST] = ndis_set_essid,
	[SIOCGIWESSID	- SIOCIWFIRST] = ndis_get_essid,
	[SIOCSIWMODE	- SIOCIWFIRST] = ndis_set_mode,
	[SIOCGIWMODE	- SIOCIWFIRST] = ndis_get_mode,
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
	DBGTRACE("Calling init at %08x rva(%08x)\n", (int)handle->miniport_char.init, (int)handle->miniport_char.init - image_offset);
	res = handle->miniport_char.init(&res2, &selected_medium, mediumtypes, 13, handle, handle);
	DBGTRACE("past init res: %08x\n\n", res);
	return res != 0;
}

static void call_halt(struct ndis_handle *handle)
{
	DBGTRACE("Calling halt at %08x rva(%08x)\n", (int)handle->miniport_char.halt, (int)handle->miniport_char.halt - image_offset);
	handle->miniport_char.halt(handle->adapter_ctx);
}

static unsigned int call_entry(struct ndis_handle *handle)
{
	int res;
	char regpath[] = {'a', 0, 'b', 0, 0, 0};
	DBGTRACE("Calling entry at %08x rva(%08x)\n", (int)handle->entry, (int)handle->entry - image_offset);
	res = handle->entry((void*)handle, regpath);
	DBGTRACE("Past entry: Version: %d.%d\n\n\n", handle->miniport_char.majorVersion, handle->miniport_char.minorVersion);

	/* Dump addresses of driver suppoled callbacks */
#ifdef DEBUG
	{
		int i;
		int *adr = (int*) &handle->miniport_char.CheckForHangTimer;
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


static int ndis_open (struct net_device *dev)
{
	DBGTRACE("%s\n", __FUNCTION__);
	return 0;
}


static int ndis_close (struct net_device *dev)
{
	DBGTRACE("%s\n", __FUNCTION__);
	return 0;
}


static struct net_device_stats *ndis_get_stats (struct net_device *dev)
{
	struct ndis_handle *handle = dev->priv;
	unsigned int x;

	if(!query_int(handle, NDIS_OID_STAT_TX_OK, &x))
		handle->stats.tx_packets = x; 
	if(!query_int(handle, NDIS_OID_STAT_RX_OK, &x))
		handle->stats.rx_packets = x; 	
	if(!query_int(handle, NDIS_OID_STAT_TX_ERROR, &x))
		handle->stats.tx_errors = x; 	
	if(!query_int(handle, NDIS_OID_STAT_RX_ERROR, &x))
		handle->stats.rx_errors = x; 	
	return &handle->stats;
}


static struct iw_statistics *ndis_get_wireless_stats(struct net_device *dev)
{
	DBGTRACE("%s\n", __FUNCTION__);
	return NULL;
}


static int ndis_ioctl (struct net_device *dev, struct ifreq *rq, int cmd)
{
	int rc = -ENODEV;
	DBGTRACE("%s\n", __FUNCTION__);
	return rc;
}


/*
 * This can probably be done a lot more effective (no copy of data needed).
 *
 *
 */
 static int ndis_start_xmit (struct sk_buff *skb, struct net_device *dev)
{
	struct ndis_handle *handle = dev->priv;

	char *data = kmalloc(skb->len, GFP_KERNEL);
	if(!data)
	{
		return 0;
	}

	struct ndis_buffer *buffer = kmalloc(sizeof(struct ndis_buffer), GFP_KERNEL);
	if(!buffer)
	{
		kfree(data);
		return 0;
	}

	struct ndis_packet *packet = kmalloc(sizeof(struct ndis_packet), GFP_KERNEL);
	if(!packet)
	{
		kfree(data);
		kfree(buffer);
		return 0;
	}
	
	memset(packet, 0, sizeof(*packet));
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
	handle->miniport_char.send_packets(handle->adapter_ctx, &packet, 1);

	return 0;
}


static int setup_dev(struct net_device *dev)
{
	struct ndis_handle *handle = dev->priv;

	unsigned int res;
	unsigned int written;
	unsigned int needed;
	int i;
	unsigned char mac[6];

	DBGTRACE("Calling query to find mac at %08x rva(%08x)\n", (int)handle->miniport_char.query, (int)handle->miniport_char.query - image_offset);
	res = handle->miniport_char.query(handle->adapter_ctx, 0x01010102, &mac[0], 1024, &written, &needed);
	DBGTRACE("past query res %08x\n\n", res);
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

	return register_netdev(dev);
}


static int load_ndis_driver(int size, char *src)
{
	void *entry;
	struct ndis_handle *handle;
	struct net_device *dev;
	
	DBGTRACE("Putting driver size %d\n", size);
	dev = alloc_etherdev(sizeof *handle);
	if(!dev)
	{
		printk(KERN_ERR "Unable to alloc etherdev\n");
		goto out_nomem;
	}
	handle = dev->priv;
	handle->net_dev = dev;

	handle->image = vmalloc(size);
	if(!handle->image)
	{
		printk(KERN_ERR "Unable to allocate mem for driver\n");
		goto out_vmalloc;
	}
	copy_from_user(handle->image, src, size);

	handle->pci_dev = pci_find_device(pci_vendor, pci_device, handle->pci_dev);
	if(!handle->pci_dev)
	{
		printk(KERN_ERR "PCI device %04x:%04x not found\n", pci_vendor, pci_device);
		goto out_baddriver;
	}

	if(pci_enable_device(handle->pci_dev))
	{
		printk(KERN_ERR "PCI enable failed\n");
	}

	if(prepare_coffpe_image(&entry, handle->image, size))
	{
		printk(KERN_ERR "Unable to prepare driver\n");		
		goto out_baddriver;
	}


	DBGTRACE("size: %08x\n", sizeof(handle->fill1));

	/* Poision this because it may contain function pointers */
	memset(&handle->fill1, 0x11, sizeof(handle->fill1));
	memset(&handle->fill2, 0x11, sizeof(handle->fill2));
	memset(&handle->fill3, 0x11, sizeof(handle->fill3));

	extern void (*NdisMIndicateReceivePacket)(void*);
	extern void (*NdisMSendComplete)(void*);
	extern void (*NdisIndicateStatus)(void*);	
	extern void (*NdisIndicateStatusComplete)(void*);	
	
	handle->indicate_receive_packet = &NdisMIndicateReceivePacket;
	handle->send_complete = &NdisMSendComplete;
	handle->indicate_status = &NdisIndicateStatus;	
	handle->indicate_status_complete = &NdisIndicateStatusComplete;	
	
	handle->entry = entry;

	
	DBGTRACE("Image is at %08x\n", (int)handle->image);
	DBGTRACE("Handle is at: %08x.\n", (int)handle);

	if(call_entry(handle))
	{
		printk(KERN_ERR "Driver entry return error\n");
		goto out_baddriver;

	}

	call_init(handle);
	//test_query(handle);
	if(setup_dev(dev))
	{
		printk(KERN_ERR "Unable to set up driver\n");
		goto out_baddriver;
	}
	thedev = dev;
	
	return 0;

out_baddriver:
	vfree(handle->image);
	free_netdev(dev);
	return -EINVAL;	

out_vmalloc:
	vfree(handle->image);
	free_netdev(dev);
	return -ENOMEM;	
	
out_nomem:
	return -ENOMEM;
}


static int misc_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg)
{
	size_t size;

	switch(cmd) {
	case WDIOC_PUTDRIVER:
		size = *(size_t*)arg;
		return load_ndis_driver(size, (char*) (arg+4));
		break;
	case WDIOC_TEST:
		if(thedev)
		{
			switch(arg)
			{
			default:
				printk(KERN_ERR "Unknown test %ld\n", arg);
				break;				
			}
		}
	default:
		printk(KERN_ERR "Unknown ioctl %08x\n", cmd);
		return -EINVAL;
		break;
	}	

	return 0;
}

static int __init wrapper_init(void)
{
	int err;
        if ( (err = misc_register(&wrapper_misc)) < 0 ) {
                printk(KERN_ERR "misc_register failed\n");
		return err;
        }
	return 0;
}

static void __exit wrapper_exit(void)
{
	struct ndis_handle *handle;
	if(thedev)
	{
		handle = thedev->priv;
		unregister_netdev(thedev);
		call_halt(handle);

		if(handle->image)
		{
			vfree(handle->image);
		}
		free_netdev(thedev);
	}
	misc_deregister(&wrapper_misc);
}

module_init(wrapper_init);
module_exit(wrapper_exit);

MODULE_LICENSE("GPL");
