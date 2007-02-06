 /*
 *  Copyright (C) 2006-2007 Giridhar Pemmasani
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

#include <linux/version.h>
#include <linux/wireless.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/if_arp.h>
#include <linux/usb.h>
#include <linux/random.h>

#include <net/iw_handler.h>
#include <linux/rtnetlink.h>
#include <asm/uaccess.h>

#include "iw_ndis.h"
#include "wrapndis.h"

static int freq_chan[] = { 2412, 2417, 2422, 2427, 2432, 2437, 2442,
			   2447, 2452, 2457, 2462, 2467, 2472, 2484 };

static const char *network_names[] = {"IEEE 802.11FH", "IEEE 802.11b",
				      "IEEE 802.11a", "IEEE 802.11g", "Auto"};

int set_essid(struct wrap_ndis_device *wnd, const char *ssid, int ssid_len)
{
	TRACEEXIT2(return 0);
}

static int set_assoc_params(struct wrap_ndis_device *wnd)
{
	return 0;
}

static int iw_set_essid(struct net_device *dev, struct iw_request_info *info,
			union iwreq_data *wrqu, char *extra)
{
	TRACEEXIT2(return 0);
}

static int iw_get_essid(struct net_device *dev, struct iw_request_info *info,
			union iwreq_data *wrqu, char *extra)
{
	TRACEEXIT2(return 0);
}

int set_infra_mode(struct wrap_ndis_device *wnd,
		   enum network_infrastructure mode)
{
	TRACEEXIT2(return 0);
}

static int iw_set_infra_mode(struct net_device *dev,
			     struct iw_request_info *info,
			     union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	TRACEEXIT2(return 0);
}

static int iw_get_infra_mode(struct net_device *dev,
			     struct iw_request_info *info,
			     union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	TRACEEXIT2(return 0);
}

static const char *network_type_to_name(int net_type)
{
	if (net_type >= 0 &&
	    net_type < (sizeof(network_names) / sizeof(network_names[0])))
		return network_names[net_type];
	else
		return network_names[sizeof(network_names) /
				     sizeof(network_names[0]) - 1];
}

static int iw_get_network_type(struct net_device *dev,
			       struct iw_request_info *info,
			       union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	return 0;
}

static int iw_get_freq(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	return 0;
}

static int iw_set_freq(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	return 0;
}

static int iw_get_tx_power(struct net_device *dev, struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	return 0;
}

static int iw_set_tx_power(struct net_device *dev, struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	return 0;
}

static int iw_get_bitrate(struct net_device *dev, struct iw_request_info *info,
			  union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	return 0;
}

static int iw_set_bitrate(struct net_device *dev, struct iw_request_info *info,
			  union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	return 0;
}

static int iw_set_dummy(struct net_device *dev, struct iw_request_info *info,
			union iwreq_data *wrqu, char *extra)
{
	/* Do nothing. Used for ioctls that are not implemented. */
	return 0;
}

static int iw_get_rts_threshold(struct net_device *dev,
				struct iw_request_info *info,
				union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	return 0;
}

static int iw_set_rts_threshold(struct net_device *dev,
				struct iw_request_info *info,
				union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	return 0;
}

static int iw_get_frag_threshold(struct net_device *dev,
				 struct iw_request_info *info,
				 union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	return 0;
}

static int iw_set_frag_threshold(struct net_device *dev,
				 struct iw_request_info *info,
				 union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	return 0;
}

int get_ap_address(struct wrap_ndis_device *wnd, mac_address ap_addr)
{
	NDIS_STATUS res;
	TRACEEXIT2(return 0);
}

static int iw_get_ap_address(struct net_device *dev,
			     struct iw_request_info *info,
			     union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	TRACEEXIT2(return 0);
}

static int iw_set_ap_address(struct net_device *dev,
			     struct iw_request_info *info,
			     union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	TRACEEXIT2(return 0);
}

int set_auth_mode(struct wrap_ndis_device *wnd, ULONG auth_mode)
{
	TRACEEXIT2(return 0);
}

int get_auth_mode(struct wrap_ndis_device *wnd)
{
	TRACEEXIT2(return 0);
}

int set_encr_mode(struct wrap_ndis_device *wnd, ULONG encr_mode)
{
	TRACEEXIT2(return 0);
}

int get_encr_mode(struct wrap_ndis_device *wnd)
{
	TRACEEXIT2(return 0);
}

static int iw_get_encr(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	TRACEEXIT2(return 0);
}

/* index must be 0 - N, as per NDIS  */
int add_wep_key(struct wrap_ndis_device *wnd, char *key, int key_len,
		int index)
{
	TRACEEXIT2(return 0);
}

/* remove_key is for both wep and wpa */
static int remove_key(struct wrap_ndis_device *wnd, int index,
		      mac_address bssid)
{
	TRACEEXIT2(return 0);
}

static int iw_set_wep(struct net_device *dev, struct iw_request_info *info,
		      union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	TRACEEXIT2(return 0);
}

static int iw_set_nick(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	return 0;
}

static int iw_get_nick(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	return 0;
}

static char *ndis_translate_scan(struct net_device *dev, char *event,
				 char *end_buf, void *item)
{
	struct iw_event iwe;
	char *current_val;
	int i, nrates;
	unsigned char buf[MAX_WPA_IE_LEN * 2 + 30];
	struct ndis_dot11_bss_entry *bss;

	TRACEENTER2("%p, %p", event, item);
	bss = item;

	DBGTRACE2("0x%x, 0x%x, 0x%x", bss->phy_id, bss->bss_type,
		  bss->in_reg_domain);
	/* add mac address */
	memset(&iwe, 0, sizeof(iwe));
	iwe.cmd = SIOCGIWAP;
	iwe.u.ap_addr.sa_family = ARPHRD_ETHER;
	iwe.len = IW_EV_ADDR_LEN;
	memcpy(iwe.u.ap_addr.sa_data, bss->bss_id, ETH_ALEN);
	event = iwe_stream_add_event(event, end_buf, &iwe, IW_EV_ADDR_LEN);

	DBGTRACE2("0x%x", bss->bss_type);

	TRACEEXIT2(return event);
}

int set_scan(struct wrap_ndis_device *wnd)
{
	struct ndis_dot11_scan_request_v2 ndis_scan_req;
	NDIS_STATUS res;

	TRACEENTER2("");
	memset(&ndis_scan_req, 0, sizeof(ndis_scan_req));
	ndis_scan_req.bss_type = ndis_dot11_bss_type_any;
	memset(&ndis_scan_req.bssid, 0xff, sizeof(ndis_scan_req.bssid));
	ndis_scan_req.scan_type = ndis_dot11_scan_type_auto;
	ndis_scan_req.restricted_scan = FALSE;
	res = miniport_set_info(wnd, OID_DOT11_SCAN_REQUEST, &ndis_scan_req, 
				sizeof(ndis_scan_req));
	if (res && res != NDIS_STATUS_DOT11_MEDIA_IN_USE) {
		WARNING("scanning failed (%08X)", res);
		TRACEEXIT2(return -EOPNOTSUPP);
	}
	wnd->scan_timestamp = jiffies;
	TRACEEXIT2(return 0);
}

static int iw_set_scan(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	return set_scan(wnd);
}

static int iw_get_scan(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	unsigned int i, list_len, needed;
	NDIS_STATUS res;
	char *event = extra;
	struct ndis_dot11_byte_array *byte_array;
	struct ndis_dot11_bss_entry *bss_entry, *cur_item;

	TRACEENTER2("");
	if (time_before(jiffies, wnd->scan_timestamp + 3 * HZ))
		return -EAGAIN;
	/* try with space for a few scan items */
	list_len = sizeof(*byte_array) + sizeof(*bss_entry) * 8;
	byte_array = kzalloc(list_len, GFP_KERNEL);
	if (!byte_array) {
		ERROR("couldn't allocate memory");
		return -ENOMEM;
	}
	memcpy(byte_array, wnd->country_string, sizeof(wnd->country_string));
	needed = 0;
	res = miniport_query_info_needed(wnd, OID_DOT11_ENUM_BSS_LIST,
					 byte_array, list_len, &needed);
	if (res == NDIS_STATUS_INVALID_LENGTH ||
	    res == NDIS_STATUS_BUFFER_TOO_SHORT) {
		/* now try with required space */
		kfree(byte_array);
		list_len = needed;
		byte_array = kzalloc(list_len, GFP_KERNEL);
		if (!byte_array) {
			ERROR("couldn't allocate memory");
			return -ENOMEM;
		}
		memcpy(byte_array, wnd->country_string,
		       sizeof(wnd->country_string));
		res = miniport_query_info(wnd, OID_DOT11_ENUM_BSS_LIST,
					  byte_array, list_len);
	}
	if (res) {
		WARNING("getting BSSID list failed (%08X)", res);
		kfree(byte_array);
		TRACEEXIT2(return -EOPNOTSUPP);
	}
	DBGTRACE2("%d, %d", byte_array->num_bytes, byte_array->num_total_bytes);
	cur_item = byte_array->buffer;
	i = 0;
	while (i < byte_array->num_bytes) {
		event = ndis_translate_scan(dev, event,
					    extra + IW_SCAN_MAX_DATA, cur_item);
		i += sizeof(*cur_item) + cur_item->buffer_length - 1;
		cur_item = (typeof(cur_item))
			((char *)cur_item + sizeof(*cur_item) +
			 cur_item->buffer_length - 1);
	}
	wrqu->data.length = event - extra;
	wrqu->data.flags = 0;
	kfree(byte_array);
	TRACEEXIT2(return 0);
}

static int iw_set_power_mode(struct net_device *dev,
			     struct iw_request_info *info,
			     union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	return 0;
}

static int iw_get_power_mode(struct net_device *dev,
			     struct iw_request_info *info,
			     union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	return 0;
}

static int iw_get_sensitivity(struct net_device *dev,
			      struct iw_request_info *info,
			      union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	return 0;
}

static int iw_set_sensitivity(struct net_device *dev,
			      struct iw_request_info *info,
			      union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	return 0;
}

static int iw_get_ndis_stats(struct net_device *dev,
			     struct iw_request_info *info,
			     union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	struct iw_statistics *stats = &wnd->wireless_stats;
	memcpy(&wrqu->qual, &stats->qual, sizeof(stats->qual));
	return 0;
}

static int iw_get_range(struct net_device *dev, struct iw_request_info *info,
			union iwreq_data *wrqu, char *extra)
{
	struct iw_range *range = (struct iw_range *)extra;
	struct iw_point *data = &wrqu->data;
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	return 0;
}

static int disassociate(struct wrap_ndis_device *wnd)
{
	return 0;
}


static int deauthenticate(struct wrap_ndis_device *wnd)
{
	TRACEEXIT2(return 0);
}

int set_priv_filter(struct wrap_ndis_device *wnd, int flags)
{
	TRACEEXIT2(return 0);
}

static int iw_set_mlme(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	struct iw_mlme *mlme = (struct iw_mlme *)extra;

	return 0;
}

static int iw_set_genie(struct net_device *dev,
			struct iw_request_info *info,
			union iwreq_data *wrqu, char *extra)
{
	/*
	 * NDIS drivers do not allow IEs to be configured; this is
	 * done by the driver based on other configuration. Return 0
	 * to avoid causing issues with user space programs that
	 * expect this function to succeed.
	 */
	return 0;
}

static int iw_set_auth(struct net_device *dev,
		       struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	return 0;
}

static int iw_get_auth(struct net_device *dev,
		       struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);

	return 0;
}

static int iw_set_encodeext(struct net_device *dev,
			    struct iw_request_info *info,
			    union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	TRACEEXIT2(return 0);
}

static int iw_get_encodeext(struct net_device *dev,
			    struct iw_request_info *info,
			    union iwreq_data *wrqu, char *extra)
{
	/* struct iw_encode_ext *ext = (struct iw_encode_ext *) extra; */
	/* TODO */
	TRACEENTER2("");
	return 0;
}

static int iw_set_pmksa(struct net_device *dev, struct iw_request_info *info,
			union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);

	return 0;
}

static const iw_handler	ndis_handler[] = {
	[SIOCGIWNAME	- SIOCIWFIRST] = iw_get_network_type,
	[SIOCSIWESSID	- SIOCIWFIRST] = iw_set_essid,
	[SIOCGIWESSID	- SIOCIWFIRST] = iw_get_essid,
	[SIOCSIWMODE	- SIOCIWFIRST] = iw_set_infra_mode,
	[SIOCGIWMODE	- SIOCIWFIRST] = iw_get_infra_mode,
	[SIOCGIWFREQ	- SIOCIWFIRST] = iw_get_freq,
	[SIOCSIWFREQ	- SIOCIWFIRST] = iw_set_freq,
	[SIOCGIWTXPOW	- SIOCIWFIRST] = iw_get_tx_power,
	[SIOCSIWTXPOW	- SIOCIWFIRST] = iw_set_tx_power,
	[SIOCGIWRATE	- SIOCIWFIRST] = iw_get_bitrate,
	[SIOCSIWRATE	- SIOCIWFIRST] = iw_set_bitrate,
	[SIOCGIWRTS	- SIOCIWFIRST] = iw_get_rts_threshold,
	[SIOCSIWRTS	- SIOCIWFIRST] = iw_set_rts_threshold,
	[SIOCGIWFRAG	- SIOCIWFIRST] = iw_get_frag_threshold,
	[SIOCSIWFRAG	- SIOCIWFIRST] = iw_set_frag_threshold,
	[SIOCGIWAP	- SIOCIWFIRST] = iw_get_ap_address,
	[SIOCSIWAP	- SIOCIWFIRST] = iw_set_ap_address,
	[SIOCSIWENCODE	- SIOCIWFIRST] = iw_set_wep,
	[SIOCGIWENCODE	- SIOCIWFIRST] = iw_get_encr,
	[SIOCSIWSCAN	- SIOCIWFIRST] = iw_set_scan,
	[SIOCGIWSCAN	- SIOCIWFIRST] = iw_get_scan,
	[SIOCGIWPOWER	- SIOCIWFIRST] = iw_get_power_mode,
	[SIOCSIWPOWER	- SIOCIWFIRST] = iw_set_power_mode,
	[SIOCGIWRANGE	- SIOCIWFIRST] = iw_get_range,
	[SIOCGIWSTATS	- SIOCIWFIRST] = iw_get_ndis_stats,
	[SIOCGIWSENS	- SIOCIWFIRST] = iw_get_sensitivity,
	[SIOCSIWSENS	- SIOCIWFIRST] = iw_set_sensitivity,
	[SIOCGIWNICKN	- SIOCIWFIRST] = iw_get_nick,
	[SIOCSIWNICKN	- SIOCIWFIRST] = iw_set_nick,
	[SIOCSIWCOMMIT	- SIOCIWFIRST] = iw_set_dummy,

	[SIOCSIWMLME	- SIOCIWFIRST] = iw_set_mlme,
	[SIOCSIWGENIE	- SIOCIWFIRST] = iw_set_genie,
	[SIOCSIWAUTH	- SIOCIWFIRST] = iw_set_auth,
	[SIOCGIWAUTH	- SIOCIWFIRST] = iw_get_auth,
	[SIOCSIWENCODEEXT - SIOCIWFIRST] = iw_set_encodeext,
	[SIOCGIWENCODEEXT - SIOCIWFIRST] = iw_get_encodeext,
	[SIOCSIWPMKSA	- SIOCIWFIRST] = iw_set_pmksa,
};

/* private ioctl's */

static int priv_reset(struct net_device *dev, struct iw_request_info *info,
		      union iwreq_data *wrqu, char *extra)
{
	int res;
	TRACEENTER2("");
	res = miniport_reset(netdev_priv(dev));
	if (res) {
		WARNING("reset failed: %08X", res);
		return -EOPNOTSUPP;
	}
	return 0;
}

static int priv_usb_reset(struct net_device *dev, struct iw_request_info *info,
			  union iwreq_data *wrqu, char *extra)
{
	int res;
	struct wrap_ndis_device *wnd;

	TRACEENTER2("");
	wnd = netdev_priv(dev);
	res = 0;
#if defined(CONFIG_USB) && LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
	res = usb_reset_configuration(wnd->wd->usb.udev);
	if (res) {
		WARNING("reset failed: %08X", res);
		return -EOPNOTSUPP;
	}
#endif
	return 0;
}

static int priv_power_profile(struct net_device *dev,
			      struct iw_request_info *info,
			      union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);

	TRACEENTER2("");
	TRACEEXIT2(return 0);
}

static int priv_network_type(struct net_device *dev,
			     struct iw_request_info *info,
			     union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	TRACEEXIT2(return 0);
}

static int priv_media_stream_mode(struct net_device *dev,
				  struct iw_request_info *info,
				  union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	TRACEEXIT2(return 0);
}

static int priv_set_encr_mode(struct net_device *dev,
			      struct iw_request_info *info,
			      union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	TRACEEXIT2(return 0);
}

static int priv_set_auth_mode(struct net_device *dev,
			      struct iw_request_info *info,
			      union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	TRACEEXIT2(return 0);
}

static int priv_reload_defaults(struct net_device *dev,
				struct iw_request_info *info,
				union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	return 0;
}


static const struct iw_priv_args priv_args[] = {
	{PRIV_RESET, 0, 0, "ndis_reset"},
	{PRIV_POWER_PROFILE, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0,
	 "power_profile"},
	{PRIV_NETWORK_TYPE, IW_PRIV_TYPE_CHAR | IW_PRIV_SIZE_FIXED | 1, 0,
	 "network_type"},
	{PRIV_USB_RESET, 0, 0, "usb_reset"},
	{PRIV_MEDIA_STREAM_MODE, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0,
	 "media_stream"},

	{PRIV_SET_ENCR_MODE, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0,
	 "set_encr_mode"},
	{PRIV_SET_AUTH_MODE, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0,
	 "set_auth_mode"},
	{PRIV_RELOAD_DEFAULTS, 0, 0, "reload_defaults"},
};

static const iw_handler priv_handler[] = {
	[PRIV_RESET 		- SIOCIWFIRSTPRIV] = priv_reset,
	[PRIV_POWER_PROFILE 	- SIOCIWFIRSTPRIV] = priv_power_profile,
	[PRIV_NETWORK_TYPE 	- SIOCIWFIRSTPRIV] = priv_network_type,
	[PRIV_USB_RESET		- SIOCIWFIRSTPRIV] = priv_usb_reset,
	[PRIV_MEDIA_STREAM_MODE	- SIOCIWFIRSTPRIV] = priv_media_stream_mode,
	[PRIV_SET_ENCR_MODE 	- SIOCIWFIRSTPRIV] = priv_set_encr_mode,
	[PRIV_SET_AUTH_MODE 	- SIOCIWFIRSTPRIV] = priv_set_auth_mode,
	[PRIV_RELOAD_DEFAULTS 	- SIOCIWFIRSTPRIV] = priv_reload_defaults,
};

const struct iw_handler_def ndis_handler_def = {
	.num_standard	= sizeof(ndis_handler) / sizeof(ndis_handler[0]),
	.num_private	= sizeof(priv_handler) / sizeof(priv_handler[0]),
	.num_private_args = sizeof(priv_args) / sizeof(priv_args[0]),

	.standard	= (iw_handler *)ndis_handler,
	.private	= (iw_handler *)priv_handler,
	.private_args	= (struct iw_priv_args *)priv_args,
#if WIRELESS_EXT >= 19
	.get_wireless_stats = get_wireless_stats,
#endif
};
