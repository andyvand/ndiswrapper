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
#include <linux/ethtool.h>
#include <linux/wireless.h>
#include <linux/if_arp.h>
#include <net/iw_handler.h>
#include <linux/rtnetlink.h>

#include <asm/uaccess.h>

#include "wrapper.h"
#include "loader.h"
#include "ndis.h"

#define DRV_NAME "ndiswrapper"
#define DRV_VERSION "0.3+CVS"

/* Define this if you are developing and ndis_init_one crashes.
   When using the old PCI-API a reboot is not needed when this
   function crashes. A simple rmmod -f will do the trick and
   you can try again.
*/

/*#define DEBUG_CRASH_ON_INIT*/

static char *basename = "eth";
int proc_uid, proc_gid;

MODULE_PARM(basename, "s");
MODULE_PARM_DESC(basename, "Basename for network device name (default: eth)");
MODULE_PARM(proc_uid, "i");
MODULE_PARM_DESC(proc_uid, "The uid of the files created in /proc (default: 0).");
MODULE_PARM(proc_gid, "i");
MODULE_PARM_DESC(proc_gid, "The gid of the files created in /proc. (default: 0).");

/* List of loaded drivers */
static LIST_HEAD(driverlist);

/* Protects driver list */
static spinlock_t driverlist_lock = SPIN_LOCK_UNLOCKED;

extern int image_offset;
int freq_chan[] = { 2412, 2417, 2422, 2427, 2432, 2437, 2442,
		    2447, 2452, 2457, 2462, 2467, 2472, 2484 };


/*
 * Perform a sync query and deal with the possibility of an async operation.
 * This function must be called from process context as it will sleep.
 */
int doquery(struct ndis_handle *handle, unsigned int oid, char *buf, int bufsize, unsigned int *written , unsigned int *needed)
{
	int res;

	down(&handle->query_mutex);

	handle->query_wait_done = 0;
	DBGTRACE("Calling query at %08x rva(%08x)\n", (int)handle->driver->miniport_char.query, (int)handle->driver->miniport_char.query - image_offset);
	res = handle->driver->miniport_char.query(handle->adapter_ctx, oid, buf, bufsize, written, needed);

	if(!res)
		goto out;

	if(res != NDIS_STATUS_PENDING)
		goto out;
		
	wait_event(handle->query_wqhead, (handle->query_wait_done == 1));
	 
	res = handle->query_wait_res;

out:
	up(&handle->query_mutex);
	return res;
	
}

/*
 *
 * Called via function pointer if query returns NDIS_STATUS_PENDING
 */
STDCALL void NdisMQueryInformationComplete(struct ndis_handle *handle, unsigned int status)
{
	DBGTRACE("%s: %08x\n", __FUNCTION__, status);
	handle->query_wait_res = status;
	handle->query_wait_done = 1;
	wake_up(&handle->query_wqhead);
}


/*
 * Perform a sync setinfo and deal with the possibility of an async operation.
 * This function must be called from process context as it will sleep.
 */
int dosetinfo(struct ndis_handle *handle, unsigned int oid, char *buf, int bufsize, unsigned int *written , unsigned int *needed)
{
	int res;

	down(&handle->setinfo_mutex);
	
	handle->setinfo_wait_done = 0;
	DBGTRACE("Calling setinfo at %08x rva(%08x)\n", (int)handle->driver->miniport_char.setinfo, (int)handle->driver->miniport_char.setinfo - image_offset);
	res = handle->driver->miniport_char.setinfo(handle->adapter_ctx, oid, buf, bufsize, written, needed);

	if(!res)
		goto out;

	if(res != NDIS_STATUS_PENDING)
		goto out;
		
	wait_event(handle->setinfo_wqhead, (handle->setinfo_wait_done == 1));
		
	res = handle->setinfo_wait_res;

out:
	up(&handle->setinfo_mutex);
	return res;

}


/*
 *
 * Called via function pointer if setinfo returns NDIS_STATUS_PENDING
 */
STDCALL void NdisMSetInformationComplete(struct ndis_handle *handle, unsigned int status)
{
	DBGTRACE("%s: %08x\n", __FUNCTION__, status);
	handle->setinfo_wait_res = status;
	handle->setinfo_wait_done = 1;
	wake_up(&handle->setinfo_wqhead);
}


/*
 * Make a query that has an int as the result.
 *
 */
int query_int(struct ndis_handle *handle, int oid, int *data)
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
int set_int(struct ndis_handle *handle, int oid, int data)
{
	unsigned int written, needed;

	return dosetinfo(handle, oid, (char*)&data, sizeof(int), &written, &needed);
}



static int ndis_set_essid(struct net_device *dev,
			    struct iw_request_info *info,
			    union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv; 
	unsigned int res, written, needed;
	struct essid_req req;

	memset(&req.essid, 0, sizeof(req.essid));

	if (wrqu->essid.flags == 0)
		req.len = 0;
	else
	{
		if(wrqu->essid.length > (IW_ESSID_MAX_SIZE + 1))
			return -EINVAL;

		memcpy(&req.essid, extra, wrqu->essid.length-1);
		req.len = wrqu->essid.length-1;
	}
	
	res = dosetinfo(handle, NDIS_OID_ESSID, (char*)&req, sizeof(req), &written, &needed);
	if(res)
	{
		printk(KERN_INFO "%s: setting essid failed (%08xx)\n", dev->name, res); 
		return -EINVAL;
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
	{
		printk(KERN_INFO "%s: getting essid failed (%08x)\n",
		       dev->name, res);
		return -EOPNOTSUPP;
	}

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
		ndis_mode = NDIS_MODE_BSS;
		break;	
	case IW_MODE_INFRA:
		ndis_mode = NDIS_MODE_INFRA;
		break;	
	default:
		return -EOPNOTSUPP;
	}
	
	res = set_int(dev->priv, NDIS_OID_MODE, ndis_mode);
	if(res)
	{
		printk(KERN_INFO "%s: setting operating mode failed (%08x)\n",
		       dev->name, res); 
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
	{
		printk(KERN_INFO "%s: getting operating mode failed (%08x)\n",
		       dev->name, res);
		return -EOPNOTSUPP;
	}

	switch(ndis_mode)
	{
	case 0:
		mode = IW_MODE_ADHOC;
		break;
	case 1:
		mode = IW_MODE_INFRA;
		break;
	default:
		printk(KERN_INFO "%s: invalid operating mode (%u)\n",
		       dev->name, ndis_mode);
		return -1;
		break;
	}
	wrqu->mode = mode;
	return 0;
}

const char *net_type_to_name(int net_type)
{
	static const char *net_names[] = {"IEEE 802.11FH", "IEEE 802.11b",
	              "IEEE 802.11a", "IEEE 802.11g"};
	static const char *unknown = "Unknown";

	if (net_type >= 0 &&
	    net_type < (sizeof(net_names)/sizeof(net_names[0])))
		return net_names[net_type];
	else
		return unknown;
}

static int ndis_get_name(struct net_device *dev, struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv;
	unsigned int network_type, res;
	
	res = query_int(handle, NDIS_OID_NETWORK_TYPE_IN_USE, &network_type);
	if (res)
		network_type = -1;

	strncpy(wrqu->name, net_type_to_name(network_type),
	        sizeof(wrqu->name) - 1);
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
	{
		printk(KERN_INFO "%s: getting configuration failed (%08x)\n",
		       dev->name, res);
		return -EOPNOTSUPP;
	}

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

static int ndis_set_freq(struct net_device *dev, struct iw_request_info *info,
			 union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv;
	unsigned int res, written, needed;
	struct ndis_configuration req;

	memset(&req, 0, sizeof(req));
	
	if (wrqu->freq.m < 1000 && wrqu->freq.e == 0)
	{
		if (wrqu->freq.m >= 1 &&
		    wrqu->freq.m <= (sizeof(freq_chan)/sizeof(freq_chan[0])))
			req.ds_config = freq_chan[wrqu->freq.m - 1] * 1000;
		else
			return -1;
	}
	else
	{
		int i;
		for (req.ds_config = wrqu->freq.m, i = wrqu->freq.e ;
		     i > 0 ; i--)
			req.ds_config *= 10;
		req.ds_config /= 1000;
		
	}
	res = dosetinfo(handle, NDIS_OID_CONFIGURATION, (char*)&req,
			sizeof(req), &written, &needed);
	if(res)
	{
		printk(KERN_INFO "%s: setting configuration failed (%08x)\n",
		       dev->name, res);
		return -EINVAL;
	}
	return 0;
}

static int ndis_get_tx_power(struct net_device *dev, struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv; 
	unsigned long ndis_power;
	unsigned int written, needed, res;

	res = doquery(handle, NDIS_OID_TX_POWER_LEVEL, (char*)&ndis_power,
		      sizeof(ndis_power), &written, &needed);
	if(res)
		return -EOPNOTSUPP;

	wrqu->txpower.flags = IW_TXPOW_MWATT;
	wrqu->txpower.disabled = 0;
	wrqu->txpower.fixed = 0;
	wrqu->txpower.value = ndis_power;
	return 0;
}

static int ndis_set_tx_power(struct net_device *dev, struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv; 
	unsigned long ndis_power;
	unsigned int written, needed, res;

	if (wrqu->txpower.disabled)
	{
		res = set_int(handle, NDIS_OID_DISASSOCIATE, 0);
		if (res)
			return -EINVAL;
		netif_carrier_off(handle->net_dev);
		return 0;
	}
	else 
	{
		if (wrqu->txpower.flags == IW_TXPOW_MWATT)
			ndis_power = wrqu->txpower.value;
		else // wrqu->txpower.flags == IW_TXPOW_DBM
		{
			if (wrqu->txpower.value > 20)
				ndis_power = 128;
			else if (wrqu->txpower.value < -43)
				ndis_power = 127;
			else
			{
				signed char tmp;
				tmp = wrqu->txpower.value;
				tmp = -12 - tmp;
				tmp <<= 2;
				ndis_power = (unsigned char)tmp;
			}
		}
	}
	res = dosetinfo(handle, NDIS_OID_TX_POWER_LEVEL, (char*)&ndis_power,
		      sizeof(ndis_power), &written, &needed);
	if(res)
	{
		printk(KERN_INFO "%s: setting tx_power failed (%08x)\n",
		       dev->name, res);
		return -EINVAL;
	}
	if (!netif_carrier_ok(handle->net_dev))
		netif_carrier_on(handle->net_dev);

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
	{
		printk(KERN_INFO "%s: getting bitrate failed (%08x)\n",
		       dev->name, res);
		return -EOPNOTSUPP;
	}

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
	{
		printk(KERN_INFO "%s: getting RTS threshold failed (%08x)\n",
		       dev->name, res);
		return -EOPNOTSUPP;
	}

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
	{
		printk(KERN_INFO "%s: getting fragmentation threshold failed (%08x)\n",
		       dev->name, res);
		return -EOPNOTSUPP;
	}

	wrqu->frag.value = ndis_frag_threshold;
	return 0;
}

static int ndis_get_ap_address(struct net_device *dev, struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv; 
	unsigned int res, written, needed;
	__u8 mac_address[ETH_ALEN];

	res = doquery(handle, NDIS_OID_BSSID, (char*)&mac_address, sizeof(mac_address), &written, &needed);
	if(res)
		memset(mac_address, 255, ETH_ALEN);

        memcpy(wrqu->ap_addr.sa_data, mac_address, ETH_ALEN);
        wrqu->ap_addr.sa_family = ARPHRD_ETHER;
        return 0;
}

static int ndis_set_ap_address(struct net_device *dev, struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv; 
	unsigned int res, written, needed;
	__u8 mac_address[ETH_ALEN];

        memcpy(mac_address, wrqu->ap_addr.sa_data, ETH_ALEN);
	res = dosetinfo(handle, NDIS_OID_BSSID, (char*)&(mac_address[0]), sizeof(mac_address), &written, &needed);

	if(res)
	{
		printk(KERN_INFO "%s: sgetting AP mac address failed (%08x)\n",
		       dev->name, res);
		return -EINVAL;
	}

        return 0;
}

static int ndis_set_wep(struct net_device *dev, struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv;
	unsigned int res, written, needed, auth_mode;
	struct wep_req req;
	int keyindex;

	if ((wrqu->data.flags & IW_ENCODE_NOKEY) || 
	    (wrqu->data.flags & IW_ENCODE_DISABLED))
	{
		keyindex = wrqu->data.flags & IW_ENCODE_INDEX;
		keyindex |= (1 << 31);
		res = set_int(handle, NDIS_OID_WEP_STATUS,
			       NDIS_ENCODE_DISABLED);
		res |= set_int(handle, NDIS_OID_REMOVE_WEP, keyindex);
		res |= set_int(handle, NDIS_OID_AUTH_MODE, NDIS_ENCODE_OPEN);
		handle->wep.keylength = 0;
		handle->wep.keyindex = 0;
		memset(&handle->wep.keymaterial, 0, sizeof(handle->wep.keymaterial));
		if (res)
		{
			printk(KERN_INFO "%s: disabling wep failed (%08x)\n",
			       dev->name, res);
			return -EINVAL;
		}
		return 0;
	}
	else
	{
		if (wrqu->data.flags & IW_ENCODE_RESTRICTED)
			auth_mode = NDIS_ENCODE_RESTRICTED;
		else if (wrqu->data.flags & IW_ENCODE_OPEN)
			auth_mode = NDIS_ENCODE_OPEN;
		else
			auth_mode = NDIS_ENCODE_RESTRICTED;
		res = set_int(handle, NDIS_OID_AUTH_MODE, auth_mode);
		if (res)
		{
			printk(KERN_INFO "%s: setting authentication mode failed (%08x)\n", dev->name, res);
			return -EINVAL;
		}

		/* set key only if one is given */
		if (wrqu->data.length > 0)
		{
			req.len = sizeof(req);
			req.keyindex = wrqu->data.flags & IW_ENCODE_INDEX;
			req.keyindex |= (1 << 31);
			req.keylength = wrqu->data.length;
			memcpy(req.keymaterial, wrqu->data.pointer, req.keylength);
			res = dosetinfo(handle, NDIS_OID_ADD_WEP, (char*)&req, sizeof(req), &written, &needed);

			if (res)
			{
				printk(KERN_INFO "%s: setting wep key failed (%08x)\n", dev->name, res);
				return -EINVAL;
			}
			memcpy(&handle->wep, &req, sizeof(req));
		}

		res = set_int(handle, NDIS_OID_WEP_STATUS, NDIS_ENCODE_ENABLED);
		if (res)
		{
			printk(KERN_INFO "%s: setting wep status failed (%08x)\n", dev->name, res);
			return -EINVAL;
		}

		
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
	{
		printk(KERN_INFO "%s: getting wep status failed (%08x)\n",
		       dev->name, res);
		return -EOPNOTSUPP;
	}
	wrqu->data.length = 0;
	extra[0] = 0;
	
	if (status == NDIS_ENCODE_ENABLED)
	{
		wrqu->data.flags |= IW_ENCODE_ENABLED;
		wrqu->data.length = handle->wep.keylength;
		memcpy(extra, handle->wep.keymaterial, handle->wep.keylength);
	}
	else if (status == NDIS_ENCODE_DISABLED)
	{
		wrqu->data.flags |= IW_ENCODE_DISABLED;
		wrqu->data.length = handle->wep.keylength;
		memcpy(extra, handle->wep.keymaterial, handle->wep.keylength);
	}
	else if (status == NDIS_ENCODE_NOKEY)
		wrqu->data.flags |= IW_ENCODE_NOKEY;

	res = query_int(handle, NDIS_OID_AUTH_MODE, &status);
	if (res)
	{
		printk(KERN_INFO "%s: getting authentication mode failed (%08x)\n",
		       dev->name, res);
		return -EOPNOTSUPP;
	}

	if (status == NDIS_ENCODE_OPEN)
		wrqu->data.flags |= IW_ENCODE_OPEN;
	else if (status == NDIS_ENCODE_RESTRICTED)
		wrqu->data.flags |= IW_ENCODE_RESTRICTED;
	else if (status == NDIS_ENCODE_OPEN_RESTRICTED)
		wrqu->data.flags |= (IW_ENCODE_OPEN | IW_ENCODE_RESTRICTED);


	return 0;
}
	
char *ndis_translate_scan(struct net_device *dev, char *event, char *end_buf,
			  struct ssid_item *item)
{
	struct iw_event iwe;
	char *current_val;
	int i;

	/* add mac address */
	memset(&iwe, 0, sizeof(iwe));
	iwe.cmd = SIOCGIWAP;
	iwe.u.ap_addr.sa_family = ARPHRD_ETHER;
	iwe.len = IW_EV_ADDR_LEN;
	memcpy(iwe.u.ap_addr.sa_data, item->mac, ETH_ALEN);
	event = iwe_stream_add_event(event, end_buf, &iwe, IW_EV_ADDR_LEN);

	/* add essid */
	memset(&iwe, 0, sizeof(iwe));
	iwe.cmd = SIOCGIWESSID;
	iwe.u.data.length = item->ssid.len;
	if (iwe.u.data.length > IW_ESSID_MAX_SIZE)
		iwe.u.data.length = IW_ESSID_MAX_SIZE;
	iwe.u.data.flags = 1;
	iwe.len = IW_EV_POINT_LEN + iwe.u.data.length;
	event = iwe_stream_add_point(event, end_buf, &iwe, item->ssid.essid);

	/* add protocol name */
	memset(&iwe, 0, sizeof(iwe));
	iwe.cmd = SIOCGIWNAME;
	strncpy(iwe.u.name, net_type_to_name(item->net_type), IFNAMSIZ);
	event = iwe_stream_add_event(event, end_buf, &iwe, IW_EV_CHAR_LEN);

	/* add mode */
	memset(&iwe, 0, sizeof(iwe));
	iwe.cmd = SIOCGIWMODE;
	if (item->mode == NDIS_MODE_ADHOC)
		iwe.u.mode = IW_MODE_ADHOC;
	else if (item->mode == NDIS_MODE_INFRA)
		iwe.u.mode = IW_MODE_INFRA;
	else // if (item->mode == NDIS_MODE_AUTO)
		iwe.u.mode = IW_MODE_AUTO;
	event = iwe_stream_add_event(event, end_buf, &iwe, IW_EV_UINT_LEN);
	
	/* add freq */
	memset(&iwe, 0, sizeof(iwe));
	iwe.cmd = SIOCGIWFREQ;
	iwe.u.freq.m = item->config.ds_config;
	if (item->config.ds_config > 1000000)
	{
		iwe.u.freq.m = item->config.ds_config / 10;
		iwe.u.freq.e = 1;
	}
	else
		iwe.u.freq.m = item->config.ds_config;
	/* convert from kHz to Hz */
	iwe.u.freq.e += 3;
	iwe.len = IW_EV_FREQ_LEN;
	event = iwe_stream_add_event(event, end_buf, &iwe, IW_EV_FREQ_LEN);

	/* add qual */
	memset(&iwe, 0, sizeof(iwe));
	iwe.cmd = IWEVQUAL;
	iwe.u.qual.level = item->rssi;
	iwe.u.qual.noise = 0;
	iwe.u.qual.qual = 0;
	iwe.len = IW_EV_QUAL_LEN;
	event = iwe_stream_add_event(event, end_buf, &iwe, IW_EV_QUAL_LEN);

	/* add key info */
	memset(&iwe, 0, sizeof(iwe));
	iwe.cmd = SIOCGIWENCODE;
	if (item->privacy == NDIS_PRIV_ACCEPT_ALL)
		iwe.u.data.flags = IW_ENCODE_DISABLED;
	else
		iwe.u.data.flags = IW_ENCODE_ENABLED | IW_ENCODE_NOKEY;
	iwe.u.data.length = 0;
	iwe.len = IW_EV_POINT_LEN;
	event = iwe_stream_add_point(event, end_buf, &iwe, item->ssid.essid);

	/* add rate */
	memset(&iwe, 0, sizeof(iwe));
	current_val = event + IW_EV_LCP_LEN;
	iwe.cmd = SIOCGIWRATE;
	for (i = 0 ; i < NDIS_MAX_RATES ; i++)
	{
		if (item->rates[i] == 0)
			break;
		iwe.u.bitrate.value = ((item->rates[i] & 0x7f) * 500000);
		current_val = iwe_stream_add_value(event, current_val, end_buf, &iwe, IW_EV_PARAM_LEN);
	}

	if ((current_val - event) > IW_EV_LCP_LEN)
		event = current_val;
	return event;
}

static int ndis_list_scan(struct ndis_handle *handle)
{
	unsigned int res, written, needed;
	struct iw_statistics *iw_stats = &handle->wireless_stats;
	struct ndis_wireless_stats ndis_stats;
	struct net_device *dev = handle->net_dev;
	long rssi;

	res = set_int(handle, NDIS_OID_BSSID_LIST_SCAN, 0);
	if (res)
		printk(KERN_INFO "%s: BSSID list scan failed (%08x)\n",
		       dev->name, res);
	
	if (doquery(handle, NDIS_OID_RSSI, (char *)&rssi, sizeof(rssi),
		    &written, &needed))
		printk(KERN_INFO "%s: get rssi failed\n", dev->name);
	else
		iw_stats->qual.level = rssi;
		
	memset(&ndis_stats, 0, sizeof(ndis_stats));
	res = doquery(handle, NDIS_OID_STATISTICS, (char *)&ndis_stats,
		      sizeof(ndis_stats), &written, &needed);
	if (!res)
	{
		iw_stats->discard.retries = (__u32)ndis_stats.retry + (__u32)ndis_stats.multi_retry;
		iw_stats->discard.misc = (__u32)ndis_stats.fcs_err + (__u32)ndis_stats.rtss_fail + (__u32)ndis_stats.ack_fail + (__u32)ndis_stats.frame_dup;
		
		if (ndis_stats.tx_frag)
			iw_stats->qual.qual = 100 - 100 * ((__u32)ndis_stats.retry + 2 * (__u32)ndis_stats.multi_retry + 3 * (__u32)ndis_stats.failed) /(6 * (__u32)ndis_stats.tx_frag);
		else
			iw_stats->qual.qual = 100;
	}
	return res;
}

static int ndis_set_scan(struct net_device *dev, struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	/* all work is now done by timer func ndis_list_scan */
	return 0;
}

static int ndis_get_scan(struct net_device *dev, struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv;
	int i, res, written, needed;
	struct list_scan list_scan;
	char *event = extra;
	char *cur_item ;

	written = needed = 0;
	res = doquery(handle, NDIS_OID_BSSID_LIST, (char*)&list_scan, sizeof(list_scan), &written, &needed);
	if (res)
	{
		printk(KERN_INFO "%s: getting BSSID list failed (%08x)\n",
		       dev->name, res);
		return -EOPNOTSUPP;
	}

	for (i = 0, cur_item = (char *)&(list_scan.items[0]) ;
	     i < list_scan.num_items && i < MAX_SCAN_LIST_ITEMS ; i++)
	{
		char *prev_item = cur_item ;
		event = ndis_translate_scan(dev, event,
					    extra + IW_SCAN_MAX_DATA,
					    (struct ssid_item *)cur_item);
		cur_item += ((struct ssid_item *)prev_item)->length;
	}
	wrqu->data.length = event - extra;
	wrqu->data.flags = 0;

	return 0;
}

void scan_bh(void *param)
{
	struct ndis_handle *handle = (struct ndis_handle *) param;
	ndis_list_scan(handle);
}



void add_scan_timer(unsigned long param)
{
	struct ndis_handle *handle = (struct ndis_handle *)param;
	struct timer_list *timer_list = &handle->apscan_timer;

	schedule_work(&handle->apscan_work);

	timer_list->data = (unsigned long) handle;
	timer_list->function = &add_scan_timer;
	timer_list->expires = jiffies + 10 * HZ;
	add_timer(timer_list);
}

void apscan_init(struct ndis_handle *handle)
{
	INIT_WORK(&handle->apscan_work, scan_bh, handle); 	
	init_timer(&handle->apscan_timer);
	add_scan_timer((unsigned long)handle);
}

void apscan_del(struct ndis_handle *handle)
{
	del_timer_sync(&handle->apscan_timer);
}

static int ndis_set_power_mode(struct net_device *dev,
		struct iw_request_info *info, union iwreq_data *wrqu,
		char *extra)
{
	struct ndis_handle *handle = dev->priv;
	int res, power_mode;

	if (wrqu->power.disabled == 1)
		power_mode = NDIS_POWER_OFF;
	else if (wrqu->power.flags & IW_POWER_MIN)
		power_mode = NDIS_POWER_MIN;
	else // if (wrqu->power.flags & IW_POWER_MAX)
		power_mode = NDIS_POWER_MAX;

	res = set_int(handle, NDIS_OID_POWER_MODE, power_mode);
	if (res)
	{
		printk(KERN_INFO "%s: setting power mode failed (%08x)\n",
		       dev->name, res);
		return -EINVAL;
	}

	return 0;
}

static int ndis_get_power_mode(struct net_device *dev,
		struct iw_request_info *info, union iwreq_data *wrqu,
		char *extra)
{
	struct ndis_handle *handle = dev->priv;
	int res, power_mode;

	res = query_int(handle, NDIS_OID_POWER_MODE, &power_mode);
	if (res)
	{
		printk(KERN_INFO "%s: getting power mode failed (%08x)\n",
		       dev->name, res);
		return -EOPNOTSUPP;
	}
	if (power_mode == NDIS_POWER_OFF)
		wrqu->power.disabled = 0;
	else
	{
		wrqu->power.flags |= IW_POWER_ALL_R;
		wrqu->power.flags |= IW_POWER_TIMEOUT;
		wrqu->power.value = 0;

		if (power_mode == NDIS_POWER_MIN)
			wrqu->power.flags |= IW_POWER_MIN;
		else // if (power_mode == NDIS_POWER_MAX)
			wrqu->power.flags |= IW_POWER_MAX;
	}
	return 0;
}

static int ndis_get_sensitivity(struct net_device *dev,
				struct iw_request_info *info,
				union iwreq_data *wrqu,	char *extra)
{
	struct ndis_handle *handle = dev->priv;
	unsigned int res, written, needed;
	unsigned long rssi_trigger;

	res = doquery(handle, NDIS_OID_RSSI_TRIGGER, (char *)&rssi_trigger,
		      sizeof(rssi_trigger), &written, &needed);
	if (res)
		return -EOPNOTSUPP;
	wrqu->param.value = rssi_trigger;
	wrqu->param.disabled = (rssi_trigger == 0);
	wrqu->param.fixed = 1;
	return 0;
}

static int ndis_set_sensitivity(struct net_device *dev,
				struct iw_request_info *info,
				union iwreq_data *wrqu,	char *extra)
{
	struct ndis_handle *handle = dev->priv;
	unsigned int res, written, needed;
	unsigned long rssi_trigger;

	if (wrqu->param.disabled)
		rssi_trigger = 0;
	else
		rssi_trigger = wrqu->param.value;
	res = dosetinfo(handle, NDIS_OID_RSSI_TRIGGER, (char *)&rssi_trigger,
			sizeof(rssi_trigger), &written, &needed);
	if (res)
		return -EINVAL;
	return 0;
}

static struct iw_statistics *ndis_get_wireless_stats(struct net_device *dev)
{
	struct ndis_handle *handle = dev->priv;

	return &handle->wireless_stats;
}


static int ndis_get_ndis_stats(struct net_device *dev, struct iw_request_info *info,
			  union iwreq_data *wrqu, char *extra)

{
	struct iw_statistics *stats = ndis_get_wireless_stats(dev);
	memcpy(&wrqu->qual, &stats->qual, sizeof(stats->qual));
	return 0;
}

static int ndis_get_range(struct net_device *dev, struct iw_request_info *info,
			  union iwreq_data *wrqu, char *extra)
{
	struct iw_range *range = (struct iw_range *)extra;
	struct iw_point *data = &wrqu->data;
	struct ndis_handle *handle = (struct ndis_handle *)dev->priv;
	unsigned int i, written, needed;
	unsigned char rates[NDIS_MAX_RATES];
	unsigned long tx_power;

	data->length = sizeof(struct iw_range);
	memset(range, 0, sizeof(struct iw_range));
	
	range->txpower_capa = IW_TXPOW_MWATT;
	range->num_txpower = 0;

	if (!doquery(handle, NDIS_OID_TX_POWER_LEVEL, (char*)&tx_power,
		     sizeof(tx_power), &written, &needed))
	{
		range->num_txpower = 1;
		range->txpower[0] = tx_power;
	}


	range->we_version_compiled = WIRELESS_EXT;
	range->we_version_source = 0;

	range->retry_capa = IW_RETRY_LIMIT;
	range->retry_flags = IW_RETRY_LIMIT;
	range->min_retry = 0;
	range->max_retry = 255;

	range->num_channels = 1;
	
	range->max_qual.qual = 100;
	range->max_qual.level = 154;
	range->max_qual.noise = 154;
	range->sensitivity = 3;

	range->max_encoding_tokens = 4;
	range->num_encoding_sizes = 2;
	range->encoding_size[0] = 5;
	range->encoding_size[1] = 13;

	range->num_bitrates = 0;
	if (!doquery(handle, NDIS_OID_SUPPORTED_RATES, (char *)&rates,
		    sizeof(rates), &written, &needed))
	{
		for (i = 0 ; i < NDIS_MAX_RATES && rates[i] ; i++)
			if (range->num_bitrates < IW_MAX_BITRATES &&
			    rates[i] & 0x80)
			{
				range->bitrate[range->num_bitrates] =
					(rates[i] & 0x7f) * 500000;
				range->num_bitrates++;
			}
	}

	range->num_channels = (sizeof(freq_chan)/sizeof(freq_chan[0]));

	for(i = 0; i < (sizeof(freq_chan)/sizeof(freq_chan[0])) &&
		    i < IW_MAX_FREQUENCIES; i++)
	{
		range->freq[i].i = i + 1;
		range->freq[i].m = freq_chan[i] * 100000;
		range->freq[i].e = 1;
	}
	range->num_frequency = i;


	range->min_rts = 0;
	range->max_rts = 2347;
	range->min_frag = 256;
	range->max_frag = 2346;

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
	[SIOCSIWFREQ	- SIOCIWFIRST] = ndis_set_freq,
	[SIOCGIWTXPOW	- SIOCIWFIRST] = ndis_get_tx_power,
	[SIOCSIWTXPOW	- SIOCIWFIRST] = ndis_set_tx_power,
	[SIOCGIWRATE	- SIOCIWFIRST] = ndis_get_bitrate,
	[SIOCGIWRTS	- SIOCIWFIRST] = ndis_get_rts_threshold,
	[SIOCGIWFRAG	- SIOCIWFIRST] = ndis_get_frag_threshold,
	//[SIOCSIWRETRY	- SIOCIWFIRST] = ndis_get_rety_limit,
	[SIOCGIWAP	- SIOCIWFIRST] = ndis_get_ap_address,
	[SIOCSIWAP	- SIOCIWFIRST] = ndis_set_ap_address,
	[SIOCSIWENCODE	- SIOCIWFIRST] = ndis_set_wep,
	[SIOCGIWENCODE	- SIOCIWFIRST] = ndis_get_wep,
	[SIOCSIWSCAN	- SIOCIWFIRST] = ndis_set_scan,
	[SIOCGIWSCAN	- SIOCIWFIRST] = ndis_get_scan,
	[SIOCGIWPOWER	- SIOCIWFIRST] = ndis_get_power_mode,
	[SIOCSIWPOWER	- SIOCIWFIRST] = ndis_set_power_mode,
	[SIOCGIWRANGE	- SIOCIWFIRST] = ndis_get_range,
	[SIOCGIWSTATS	- SIOCIWFIRST] = ndis_get_ndis_stats,
	[SIOCGIWSENS	- SIOCIWFIRST] = ndis_get_sensitivity,
	[SIOCSIWSENS	- SIOCIWFIRST] = ndis_set_sensitivity,
};

static const struct iw_handler_def ndis_handler_def = {
	.num_standard	= sizeof(ndis_handler) / sizeof(iw_handler),
	.standard	= (iw_handler *)ndis_handler,
};




static u32 ndis_get_link(struct net_device *dev)
{
	struct ndis_handle *handle = dev->priv;
	return handle->link_status;
}


static struct ethtool_ops ndis_ethtool_ops = {
	.get_link		= ndis_get_link,
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




static void hangcheck_reinit(struct ndis_handle *handle);

STDCALL void NdisMResetComplete(struct ndis_handle *handle, int status, int reset_status) 
{
	DBGTRACE("%s: %08x, %d\n", __FUNCTION__, status, reset_status);
}


static void hangcheck_bh(void *data)
{
	struct ndis_handle *handle = (struct ndis_handle *)data;
	DBGTRACE("%s: Hangcheck timer\n", __FUNCTION__);

	if(handle->driver->miniport_char.hangcheck(handle->adapter_ctx))
	{
		int res;
		handle->reset_status = 0;
		printk("ndiswrapper: Hangcheck returned true. Resetting!\n");
		res = handle->driver->miniport_char.reset(&handle->reset_status, handle->adapter_ctx);
		DBGTRACE("%s : %08x, %d\n", __FUNCTION__, res, handle->reset_status);
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

static void send_one(struct ndis_handle *handle, struct ndis_buffer *buffer)
{
	struct ndis_packet *packet;

	packet = kmalloc(sizeof(struct ndis_packet), GFP_ATOMIC);
	if(!packet)
	{
		kfree(buffer->data);
		kfree(buffer);
		return;
	}
	
	memset(packet, 0, sizeof(*packet));

	
#ifdef DEBUG
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
		packet->dataphys = pci_map_single(handle->pci_dev, buffer->data, buffer->len, PCI_DMA_TODEVICE);
		packet->scatterlist.len = 1;
		packet->scatterlist.entry.physlo = packet->dataphys;		
		packet->scatterlist.entry.physhi = 0;		
		packet->scatterlist.entry.len = buffer->len;
		packet->scatter_gather_ext = &packet->scatterlist; 
	}

	packet->oob_offset = (int)(&packet->timesent1) - (int)packet;


	packet->nr_pages = 1;
	packet->len = buffer->len;
	packet->count = 1;
	packet->valid_counts = 1;

	packet->buffer_head = buffer;
	packet->buffer_tail = buffer;

	//DBGTRACE("Buffer: %08x, data %08x, len %d\n", (int)buffer, (int)buffer->data, (int)buffer->len); 	


	if(handle->driver->miniport_char.send_packets)
	{
		int res;
		struct ndis_packet *packets[1];
		packets[0] = packet;
//		DBGTRACE("Calling send_packets at %08x rva(%08x)\n", (int)handle->driver->miniport_char.send_packets, (int)handle->driver->miniport_char.send_packets - image_offset);
		handle->driver->miniport_char.send_packets(handle->adapter_ctx, &packets[0], 1);
		
		if (!(handle->serialized_driver))
			return;
		
		res = packet->status;
		if (res == NDIS_STATUS_SUCCESS)
		{
//			ndis_sendpacket_done(handle, packet);
		} else if (res == NDIS_STATUS_PENDING)
			return;
		else if (res == NDIS_STATUS_RESOURCES)
		{
			DBGTRACE("send packets failed, should queue for send_complete, but for now - just drop: %i \n", res);
			ndis_sendpacket_done(handle, packet);
		} else if (res == NDIS_STATUS_FAILURE)
		{
			DBGTRACE("send_packets failed: %i \n",res);
			ndis_sendpacket_done(handle, packet);
		}
	}
	else if(handle->driver->miniport_char.send)
	{
		int res;
//		DBGTRACE("Calling send at %08x rva(%08x)\n", (int)handle->driver->miniport_char.send, (int)handle->driver->miniport_char.send_packets - image_offset);
		res = handle->driver->miniport_char.send(handle->adapter_ctx, packet, 0);

		if(res == NDIS_STATUS_PENDING)
		{
			return;
		}
		ndis_sendpacket_done(handle, packet);
		if(res)
			DBGTRACE("send_packets returning %08x\n", res);

		return;
	}
	else
	{
		DBGTRACE("%s: No send handler\n", __FUNCTION__);
	}
}


static void xmit_bh(void *param)
{
	struct ndis_handle *handle = (struct ndis_handle*) param;
	struct ndis_buffer *buffer;
	unsigned long flags;

	while(1)
	{
		spin_lock_irqsave(&handle->xmit_ring_lock, flags);
		if (!handle->xmit_ring_pending)
		{
			spin_unlock_irqrestore(&handle->xmit_ring_lock, flags);
			break;
		}
		if (handle->xmit_ring_pending < 0)
		{
			printk(KERN_ERR "%s: xmit_ring_pending is %d\n",
			       DRV_NAME, handle->xmit_ring_pending);
			spin_unlock_irqrestore(&handle->xmit_ring_lock, flags);
			return;
		}
		buffer = handle->xmit_ring[handle->xmit_ring_start];
		handle->xmit_ring_start =
			(handle->xmit_ring_start + 1) % XMIT_RING_SIZE;
		handle->xmit_ring_pending--;
		if (netif_queue_stopped(handle->net_dev))
			netif_wake_queue(handle->net_dev);
		spin_unlock_irqrestore(&handle->xmit_ring_lock, flags);

		send_one(handle, buffer);
	}
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
	unsigned int xmit_ring_next_slot;
	unsigned long flags;
	
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

	spin_lock_irqsave(&handle->xmit_ring_lock, flags);
	if (handle->xmit_ring_pending >= XMIT_RING_SIZE)
	{
		printk(KERN_ERR "%s: xmit_ring overflow (%d)\n",
		       dev->name, handle->xmit_ring_pending);
		spin_unlock_irqrestore(&handle->xmit_ring_lock, flags);
		return 1;
	}
	xmit_ring_next_slot =
		(handle->xmit_ring_start + handle->xmit_ring_pending) % XMIT_RING_SIZE;
	handle->xmit_ring[xmit_ring_next_slot] = buffer;
	handle->xmit_ring_pending++;
	if (handle->xmit_ring_pending == XMIT_RING_SIZE)
		netif_stop_queue(handle->net_dev);
	spin_unlock_irqrestore(&handle->xmit_ring_lock, flags);

	schedule_work(&handle->xmit_work);

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

int ndiswrapper_pm_callback(struct pm_dev *pm_dev, pm_request_t rqst,
				   void *data)
{
	struct net_device *dev;
	struct ndis_handle *handle;
	int res;
	spinlock_t lock = SPIN_LOCK_UNLOCKED;

	DBGTRACE("%s called with %p, %d, %p\n",
		 __FUNCTION__, pm_dev, rqst, data);
	if (!pm_dev || !pm_dev->data)
		return -1;
	dev = (struct net_device *)pm_dev->data;
	handle = dev->priv;
	spin_lock(&lock);
	switch(rqst)
	{
	case PM_SUSPEND:
		if (handle->pm_state != NDIS_PM_STATE_D0)
			break;
		res = query_int(handle, NDIS_OID_PNP_QUERY_POWER, &handle->pm_state);
		DBGTRACE("%s: query power to state %d returns %d\n",
		       dev->name, handle->pm_state, res);
		if (res)
			break;
		apscan_del(handle);

		/* do we need this? */
//		DBGTRACE("%s: stopping queue\n", dev->name);
//		netif_stop_queue(dev);

		DBGTRACE("%s: detaching device\n", dev->name);
		netif_device_detach(dev);

		if ((int)data == 1)
			handle->pm_state = NDIS_PM_STATE_D1;
		else if ((int)data == 2)
			handle->pm_state = NDIS_PM_STATE_D2;
		else
			handle->pm_state = NDIS_PM_STATE_D3;
		res = set_int(handle, NDIS_OID_PNP_SET_POWER, handle->pm_state);
		DBGTRACE("%s: setting power to state %d returns %d\n",
		       dev->name, handle->pm_state, res);
		break;
	case PM_RESUME:
		if (handle->pm_state == NDIS_PM_STATE_D0)
			break;

		handle->pm_state = NDIS_PM_STATE_D0;
		res = set_int(handle, NDIS_OID_PNP_SET_POWER, handle->pm_state);
		DBGTRACE("%s: setting power to state %d returns %d\n",
		       dev->name, handle->pm_state, res);

		DBGTRACE("%s: attaching device\n", dev->name);
		netif_device_attach(dev);

		/* do we need this? */
//		DBGTRACE("%s: starting queue\n", dev->name);
//		netif_wake_queue(dev);

		add_scan_timer((unsigned long)handle);
		break;
	default:
		printk(KERN_ERR "%s: rqst didn't match %d or %d\n",
		       dev->name, PM_SUSPEND, PM_RESUME);
		break;
	}
	spin_unlock(&lock);
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
	char dev_template[IFNAMSIZ];
	union iwreq_data wrqu;

	DBGTRACE("%s: Querying for mac\n", __FUNCTION__);
	res = doquery(handle, 0x01010102, &mac[0], sizeof(mac), &written, &needed);
	DBGTRACE("mac:%02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	if(res)
	{
		printk(KERN_ERR "Unable to get MAC-addr from driver\n");
		return -1;
	}

	memset(&wrqu, 0, sizeof(wrqu));

	wrqu.essid.flags = 0;
	wrqu.essid.length = 1;
	if (ndis_set_essid(dev, NULL, &wrqu, NULL))
	{
		printk(KERN_ERR "%s: Unable to set empty essid\n", dev->name);
		return -1;
	}

	wrqu.mode = IW_MODE_INFRA;
	if (ndis_set_mode(dev, NULL, &wrqu, NULL))
	{
		printk(KERN_ERR "%s: Unable to set adhoc mode\n", dev->name);
		return -1;
	}

	dev->open = ndis_open;
	dev->hard_start_xmit = ndis_start_xmit;
	dev->stop = ndis_close;
	dev->get_stats = ndis_get_stats;
	dev->do_ioctl = ndis_ioctl;
	dev->get_wireless_stats = ndis_get_wireless_stats;
	dev->wireless_handlers	= (struct iw_handler_def *)&ndis_handler_def;
	dev->ethtool_ops = &ndis_ethtool_ops;
	
	for(i = 0; i < ETH_ALEN; i++)
	{
		dev->dev_addr[i] = mac[i];
	}
	dev->irq = handle->irq;
	dev->mem_start = handle->mem_start;		
	dev->mem_end = handle->mem_end;		

	if (strlen(basename) > (IFNAMSIZ-3))
	{
		printk(KERN_ERR "%s: basename '%s' is too long\n",
		       dev->name, basename);
		return -1;
	}
	if ((!strncpy(dev_template, basename, (IFNAMSIZ - 3))) ||
	    (!strncat(dev_template, "%d", 2)))
	{
		printk(KERN_ERR "%s: Problem creating dev_template from basename '%s'\n", dev->name, basename);
		return -1;
	}
	rtnl_lock();
	res = dev_alloc_name(dev, dev_template);
	rtnl_unlock();
	if (res >= 0)
		return register_netdev(dev);
	else
		return -1;
}

extern void ndis_timer_handler_bh(void *data);
extern STDCALL void NdisSetTimer(struct ndis_timer **timer_handle, unsigned int ms);
extern STDCALL void NdisMSetPeriodicTimer(struct ndis_timer **timer_handle,
					  unsigned int ms);

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

	init_MUTEX(&handle->query_mutex);
	init_waitqueue_head(&handle->query_wqhead);
	init_MUTEX(&handle->setinfo_mutex);
	init_waitqueue_head(&handle->setinfo_wqhead);

	INIT_WORK(&handle->xmit_work, xmit_bh, handle); 	
	handle->xmit_ring_lock = SPIN_LOCK_UNLOCKED;
	handle->xmit_ring_start = 0;
	handle->xmit_ring_pending = 0;

	/* Poision this because it may contain function pointers */
	memset(&handle->fill1, 0x12, sizeof(handle->fill1));
	memset(&handle->fill2, 0x13, sizeof(handle->fill2));
	memset(&handle->fill3, 0x14, sizeof(handle->fill3));
	memset(&handle->fill4, 0x15, sizeof(handle->fill4));
	memset(&handle->fill5, 0x16, sizeof(handle->fill5));

	handle->indicate_receive_packet = &NdisMIndicateReceivePacket;
	handle->send_complete = &NdisMSendComplete;
	handle->indicate_status = &NdisIndicateStatus;	
	handle->indicate_status_complete = &NdisIndicateStatusComplete;	
	handle->query_complete = &NdisMQueryInformationComplete;	
	handle->set_complete = &NdisMSetInformationComplete;
	handle->reset_complete = &NdisMResetComplete;
	
	handle->serialized_driver = 0;
	handle->map_count = 0;
	handle->map_dma_addr = NULL; 

	handle->pci_dev = pdev;

	handle->hangcheck_interval = 2 * HZ;
	
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
	handle->pm_state = NDIS_PM_STATE_D0;
	apscan_init(handle);
	//hangcheck_add(handle);

#ifdef TEST_PM
	handle->pm = pm_register(PM_PCI_DEV, 0, ndiswrapper_pm_callback);
#else
	handle->pm = NULL;
#endif
	if (handle->pm == NULL)
		printk(KERN_WARNING "%s: power management not possible\n",
		       dev->name);
	else
		handle->pm->data = dev;

	ndis_init_proc(handle);
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

	//hangcheck_del(handle);
	apscan_del(handle);
	if (handle->pm)
		pm_unregister(handle->pm);
	ndis_remove_proc(handle);

#ifndef DEBUG_CRASH_ON_INIT
	unregister_netdev(handle->net_dev);

	if(handle->net_dev)
		free_netdev(handle->net_dev);
	set_int(handle, NDIS_OID_DISASSOCIATE, 0);
	call_halt(handle);
#endif
	pci_disable_device(pdev);
	pci_release_regions(pdev);
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

