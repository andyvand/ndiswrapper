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
	struct ndis_dot11_ssid_list ssid_list;
	NDIS_STATUS res;

	if (ssid_len > DOT11_SSID_MAX_LENGTH)
		return -EINVAL;
	memset(&ssid_list, 0, sizeof(ssid_list));
	init_ndis_object_header(&ssid_list, NDIS_OBJECT_TYPE_DEFAULT,
				DOT11_SSID_LIST_REVISION_1);
	ssid_list.num_entries = 1;
	ssid_list.num_total_entries = 1;
	ssid_list.ssids[0].length = ssid_len;
	memcpy(ssid_list.ssids[0].ssid, ssid, ssid_len);
	res = miniport_set_info(wnd, OID_DOT11_DESIRED_SSID_LIST, &ssid_list,
				sizeof(ssid_list));
	if (res)
		WARNING("setting essid failed: %08X", res);
//	res = miniport_set_info(wnd, OID_DOT11_CONNECT_REQUEST, NULL, 0);
	TRACEEXIT2(return res);
}

static int set_assoc_params(struct wrap_ndis_device *wnd)
{
	return 0;
}

static int iw_set_essid(struct net_device *dev, struct iw_request_info *info,
			union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	int res, length;

	if (wrqu->essid.flags) {
		length = wrqu->essid.length - 1;
		if (length > 0)
			length--;
		while (length < wrqu->essid.length && extra[length])
			length++;
		if (length <= 0 || length > DOT11_SSID_MAX_LENGTH)
			return -EINVAL;
	} else
		length = 0;

	if (wnd->iw_auth_set) {
		res = set_assoc_params(wnd);
		wnd->iw_auth_set = 0;
		if (res < 0)
			return res;
	}

	res = set_essid(wnd, extra, length);
	TRACEEXIT2(return res);
}

static int iw_get_essid(struct net_device *dev, struct iw_request_info *info,
			union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	struct ndis_dot11_ssid_list ssid_list;
	NDIS_STATUS res;

	memset(&ssid_list, 0, sizeof(ssid_list));
	init_ndis_object_header(&ssid_list, NDIS_OBJECT_TYPE_DEFAULT,
				DOT11_SSID_LIST_REVISION_1);
	res = miniport_query_info(wnd, OID_DOT11_DESIRED_SSID_LIST, &ssid_list,
				  sizeof(ssid_list));
	if (res)
		WARNING("getting essid failed: %08X", res);
	else if (ssid_list.ssids[0].length < IW_ESSID_MAX_SIZE)
		memcpy(extra, ssid_list.ssids[0].ssid, ssid_list.ssids[0].length);
	else
		res = -EOPNOTSUPP;
	TRACEEXIT2(return res);
}

int set_infra_mode(struct wrap_ndis_device *wnd, enum ndis_dot11_bss_type mode)
{
	NDIS_STATUS res;
	res = miniport_set_info(wnd, OID_DOT11_DESIRED_BSS_TYPE,
				&mode, sizeof(mode));
	if (res)
		WARNING("setting mode to %d failed: %08X", mode, res);
	TRACEEXIT2(return res);
}

static int iw_set_infra_mode(struct net_device *dev,
			     struct iw_request_info *info,
			     union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	enum ndis_dot11_bss_type bss_type;

	TRACEENTER2("");
	switch (wrqu->mode) {
	case IW_MODE_ADHOC:
		bss_type = ndis_dot11_bss_type_independent;
		break;
	case IW_MODE_INFRA:
		bss_type = ndis_dot11_bss_type_infrastructure;
		break;
	default:
		TRACEEXIT2(return -EINVAL);
	}

	if (set_infra_mode(wnd, bss_type))
		TRACEEXIT2(return -EINVAL);
	TRACEEXIT2(return 0);
}

static int iw_get_infra_mode(struct net_device *dev,
			     struct iw_request_info *info,
			     union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	NDIS_STATUS res;
	enum ndis_dot11_bss_type bss_type;

	res = miniport_query_info(wnd, OID_DOT11_DESIRED_BSS_TYPE,
				  &bss_type, sizeof(bss_type));
	if (res) {
		WARNING("getting mode failed: %08X", res);
		return -EOPNOTSUPP;
	}
	switch (bss_type) {
	case ndis_dot11_bss_type_independent:
		wrqu->mode = IW_MODE_ADHOC;
		break;
	case ndis_dot11_bss_type_infrastructure:
		wrqu->mode = IW_MODE_INFRA;
		break;
	case ndis_dot11_bss_type_any:
		wrqu->mode = IW_MODE_AUTO;
		break;
	default:
		ERROR("invalid operating mode (%u)", bss_type);
		TRACEEXIT2(return -EINVAL);
	}
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
	return 0;
}

static int iw_get_freq(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	return 0;
}

static int iw_set_freq(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	return 0;
}

static int iw_get_tx_power(struct net_device *dev, struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	return 0;
}

static int iw_set_tx_power(struct net_device *dev, struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	return 0;
}

static int iw_get_bitrate(struct net_device *dev, struct iw_request_info *info,
			  union iwreq_data *wrqu, char *extra)
{
	return 0;
}

static int iw_set_bitrate(struct net_device *dev, struct iw_request_info *info,
			  union iwreq_data *wrqu, char *extra)
{
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
	return 0;
}

static int iw_set_rts_threshold(struct net_device *dev,
				struct iw_request_info *info,
				union iwreq_data *wrqu, char *extra)
{
	return 0;
}

static int iw_get_frag_threshold(struct net_device *dev,
				 struct iw_request_info *info,
				 union iwreq_data *wrqu, char *extra)
{
	return 0;
}

static int iw_set_frag_threshold(struct net_device *dev,
				 struct iw_request_info *info,
				 union iwreq_data *wrqu, char *extra)
{
	return 0;
}

int get_ap_address(struct wrap_ndis_device *wnd, mac_address ap_addr)
{
	struct ndis_dot11_bssid_list bssid_list;
	NDIS_STATUS res;

	memset(&bssid_list, 0, sizeof(bssid_list));
	init_ndis_object_header(&bssid_list, NDIS_OBJECT_TYPE_DEFAULT,
				DOT11_BSSID_LIST_REVISION_1);
	bssid_list.num_entries = 1;
	bssid_list.num_total_entries = 1;
	res = miniport_query_info(wnd, OID_DOT11_DESIRED_BSSID_LIST,
				  &bssid_list, sizeof(bssid_list));
	if (res) {
		WARNING("getting bssid list failed: %08X", res);
		return -EOPNOTSUPP;
	}
	memcpy(ap_addr, bssid_list.bssids[0], sizeof(ap_addr));
	TRACEEXIT2(return 0);
}

static int iw_get_ap_address(struct net_device *dev,
			     struct iw_request_info *info,
			     union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	int res;
	res = get_ap_address(wnd, wrqu->ap_addr.sa_data);
	if (res == 0)
		wrqu->ap_addr.sa_family = ARPHRD_ETHER;
	TRACEEXIT2(return res);
}

static int iw_set_ap_address(struct net_device *dev,
			     struct iw_request_info *info,
			     union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	struct ndis_dot11_bssid_list bssid_list;
	NDIS_STATUS res;

	memset(&bssid_list, 0, sizeof(bssid_list));
	init_ndis_object_header(&bssid_list, NDIS_OBJECT_TYPE_DEFAULT,
				DOT11_BSSID_LIST_REVISION_1);
	bssid_list.num_entries = 1;
	bssid_list.num_total_entries = 1;
	memcpy(bssid_list.bssids[0], wrqu->ap_addr.sa_data,
	       sizeof(bssid_list.bssids[0]));
	res = miniport_set_info(wnd, OID_DOT11_DESIRED_BSSID_LIST,
				&bssid_list, sizeof(bssid_list));
	if (res) {
		WARNING("setting bssid list failed: %08X", res);
		return -EINVAL;
	}
	TRACEEXIT2(return 0);
}

int set_auth_algo(struct wrap_ndis_device *wnd,
		  enum ndis_dot11_auth_algorithm algo_id)
{
	struct ndis_dot11_auth_algorithm_list auth_algos;
	NDIS_STATUS res;

	memset(&auth_algos, 0, sizeof(auth_algos));
	init_ndis_object_header(&auth_algos, NDIS_OBJECT_TYPE_DEFAULT,
				DOT11_AUTH_ALGORITHM_LIST_REVISION_1);
	auth_algos.num_entries = 1;
	auth_algos.num_total_entries = 1;
	auth_algos.algo_ids[0] = algo_id;
	res = miniport_set_info(wnd, OID_DOT11_ENABLED_AUTHENTICATION_ALGORITHM,
				&auth_algos, sizeof(auth_algos));
	if (res) {
		WARNING("setting authentication mode to %d failed: %08X",
			algo_id, res);
		return -EINVAL;
	}
	TRACEEXIT2(return 0);
}

enum ndis_dot11_auth_algorithm get_auth_algo(struct wrap_ndis_device *wnd)
{
	struct ndis_dot11_auth_algorithm_list auth_algos;
	NDIS_STATUS res;

	memset(&auth_algos, 0, sizeof(auth_algos));
	init_ndis_object_header(&auth_algos, NDIS_OBJECT_TYPE_DEFAULT,
				DOT11_AUTH_ALGORITHM_LIST_REVISION_1);
	auth_algos.num_entries = 1;
	auth_algos.num_total_entries = 1;
	res = miniport_query_info(wnd, OID_DOT11_ENABLED_AUTHENTICATION_ALGORITHM,
				  &auth_algos, sizeof(auth_algos));
	if (res) {
		WARNING("getting authentication mode failed: %08X", res);
		return -EOPNOTSUPP;
	}
	TRACEEXIT2(return auth_algos.algo_ids[0]);
}

int set_cipher_mode(struct wrap_ndis_device *wnd,
		    enum ndis_dot11_cipher_algorithm algo_id)
{
	struct ndis_dot11_cipher_algorithm_list cipher_algos;
	NDIS_STATUS res;

	memset(&cipher_algos, 0, sizeof(cipher_algos));
	init_ndis_object_header(&cipher_algos, NDIS_OBJECT_TYPE_DEFAULT,
				DOT11_CIPHER_ALGORITHM_LIST_REVISION_1);
	cipher_algos.num_entries = 1;
	cipher_algos.num_total_entries = 1;
	cipher_algos.algo_ids[0] = algo_id;
	res = miniport_set_info(wnd, OID_DOT11_ENABLED_UNICAST_CIPHER_ALGORITHM,
				&cipher_algos, sizeof(cipher_algos));
	if (res) {
		WARNING("setting cipher algorithm to %d failed: %08X",
			algo_id, res);
		return -EINVAL;
	}
	TRACEEXIT2(return 0);
}

enum ndis_dot11_cipher_algorithm get_cipher_mode(struct wrap_ndis_device *wnd)
{
	struct ndis_dot11_cipher_algorithm_list cipher_algos;
	NDIS_STATUS res;

	memset(&cipher_algos, 0, sizeof(cipher_algos));
	init_ndis_object_header(&cipher_algos, NDIS_OBJECT_TYPE_DEFAULT,
				DOT11_CIPHER_ALGORITHM_LIST_REVISION_1);
	cipher_algos.num_entries = 1;
	cipher_algos.num_total_entries = 1;
	res = miniport_query_info(wnd, OID_DOT11_ENABLED_UNICAST_CIPHER_ALGORITHM,
				  &cipher_algos, sizeof(cipher_algos));
	if (res) {
		WARNING("getting cipher algorithm failed: %08X", res);
		return -EINVAL;
	}
	TRACEEXIT2(return cipher_algos.algo_ids[0]);
}

static int iw_get_cipher(struct net_device *dev, struct iw_request_info *info,
			 union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	int index, mode;
	struct cipher_info *cipher_info = &wnd->cipher_info;

	TRACEENTER2("wnd = %p", wnd);
	wrqu->data.length = 0;
	extra[0] = 0;

	index = (wrqu->encoding.flags & IW_ENCODE_INDEX);
	DBGTRACE2("index = %u", index);
	if (index > 0)
		index--;
	else
		index = cipher_info->tx_index;

	if (index < 0 || index >= MAX_CIPHER_KEYS) {
		WARNING("encryption index out of range (%u)", index);
		TRACEEXIT2(return -EINVAL);
	}

	if (index != cipher_info->tx_index) {
		if (cipher_info->keys[index].length > 0) {
			wrqu->data.flags |= IW_ENCODE_ENABLED;
			wrqu->data.length = cipher_info->keys[index].length;
			memcpy(extra, cipher_info->keys[index].key,
			       cipher_info->keys[index].length);
		}
		else
			wrqu->data.flags |= IW_ENCODE_DISABLED;

		TRACEEXIT2(return 0);
	}

	/* transmit key */
	mode = get_cipher_mode(wnd);
	if (mode < 0)
		TRACEEXIT2(return -EOPNOTSUPP);

	if (mode == DOT11_CIPHER_ALGO_NONE)
		wrqu->data.flags |= IW_ENCODE_DISABLED;
	else {
		wrqu->data.flags |= IW_ENCODE_ENABLED;
		wrqu->encoding.flags |= index + 1;
		wrqu->data.length = cipher_info->keys[index].length;
		memcpy(extra, cipher_info->keys[index].key,
		       cipher_info->keys[index].length);
	}
	mode = get_auth_algo(wnd);
	if (mode < 0)
		TRACEEXIT2(return -EOPNOTSUPP);

	if (mode == DOT11_AUTH_ALGO_80211_OPEN)
		wrqu->data.flags |= IW_ENCODE_OPEN;
	else if (mode == DOT11_AUTH_ALGO_80211_SHARED_KEY)
		wrqu->data.flags |= IW_ENCODE_RESTRICTED;
	else // WPA / RSNA etc
		wrqu->data.flags |= IW_ENCODE_RESTRICTED;

	TRACEEXIT2(return 0);
}

/* index must be 0 - N, as per NDIS  */
int add_cipher_key(struct wrap_ndis_device *wnd, char *key, int key_len,
		   int index, enum ndis_dot11_cipher_algorithm algo,
		   mac_address mac)
{
	struct ndis_dot11_cipher_default_key_value *ndis_key;
	NDIS_STATUS res;

	TRACEENTER2("key index: %d, length: %d", index, key_len);
	if (key_len <= 0 || key_len > NDIS_ENCODING_TOKEN_MAX) {
		WARNING("invalid key length (%d)", key_len);
		TRACEEXIT2(return -EINVAL);
	}
	if (index < 0 || index >= MAX_CIPHER_KEYS) {
		WARNING("invalid key index (%d)", index);
		TRACEEXIT2(return -EINVAL);
	}
	if (wnd->cipher_info.algo != DOT11_CIPHER_ALGO_NONE &&
	    wnd->cipher_info.algo != algo) {
		WARNING("invalid algorithm: %d/%d", wnd->cipher_info.algo, algo);
		return -EINVAL;
	}
	ndis_key = kzalloc(sizeof(*ndis_key) + key_len - 1, GFP_KERNEL);
	if (!ndis_key)
		return -ENOMEM;

	init_ndis_object_header(ndis_key, NDIS_OBJECT_TYPE_DEFAULT,
				DOT11_CIPHER_DEFAULT_KEY_VALUE_REVISION_1);
	
	ndis_key->key_index = index;
	DBGTRACE2("key %d/%d: " MACSTRSEP, index, key_len, MAC2STR(key));

	ndis_key->algo_id = algo;
	if (mac)
		memcpy(ndis_key->mac, mac, sizeof(ndis_key->mac));
	ndis_key->is_static = TRUE;
	ndis_key->key_length = key_len;
	memcpy(ndis_key->key, key, key_len);

	res = miniport_set_info(wnd, OID_DOT11_CIPHER_DEFAULT_KEY, ndis_key,
				sizeof(*ndis_key));
	if (res) {
		WARNING("adding key %d failed (%08X)", index + 1, res);
		kfree(ndis_key);
		TRACEEXIT2(return -EINVAL);
	}

	wnd->cipher_info.keys[index].length = key_len;
	memcpy(&wnd->cipher_info.keys[index].key, key, key_len);
	wnd->cipher_info.algo = algo;
	kfree(ndis_key);
	TRACEEXIT2(return 0);
}

static int delete_cipher_key(struct wrap_ndis_device *wnd, int index,
			     mac_address mac)
{
	struct ndis_dot11_cipher_default_key_value *ndis_key;
	char key_buf[sizeof(*ndis_key) + NDIS_ENCODING_TOKEN_MAX - 1];
	NDIS_STATUS res;

	TRACEENTER2("key index: %d, length: %d", index, key_len);
	if (wnd->cipher_info.keys[index].length == 0)
		TRACEEXIT2(return 0);

	memset(key_buf, 0, sizeof(key_buf));
	ndis_key = (typeof(ndis_key))key_buf;
	init_ndis_object_header(ndis_key, NDIS_OBJECT_TYPE_DEFAULT,
				DOT11_CIPHER_DEFAULT_KEY_VALUE_REVISION_1);
	
	ndis_key->key_index = index;
	ndis_key->algo_id = wnd->cipher_info.algo;
	if (mac)
		memcpy(ndis_key->mac, mac, sizeof(ndis_key->mac));
	ndis_key->delete = TRUE;
	ndis_key->is_static = TRUE;
	ndis_key->key_length = wnd->cipher_info.keys[index].length;

	DBGTRACE2("key %d: " MACSTRSEP, index, MAC2STR(key));
	res = miniport_set_info(wnd, OID_DOT11_CIPHER_DEFAULT_KEY, ndis_key,
				sizeof(*ndis_key));
	if (res) {
		WARNING("deleting key %d failed (%08X)", index + 1, res);
		TRACEEXIT2(return -EINVAL);
	}
	wnd->cipher_info.keys[index].length = 0;
	memset(&wnd->cipher_info.keys[index].key, 0,
	       sizeof(wnd->cipher_info.keys[index].length));
	TRACEEXIT2(return 0);
}

static int iw_set_wep(struct net_device *dev, struct iw_request_info *info,
		      union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	NDIS_STATUS res;
	unsigned int index, key_len;
	struct cipher_info *cipher_info = &wnd->cipher_info;
	unsigned char *key;
	enum ndis_dot11_cipher_algorithm algo;

	TRACEENTER2("");
	index = (wrqu->encoding.flags & IW_ENCODE_INDEX);
	DBGTRACE2("index = %u", index);

	/* iwconfig gives index as 1 - N */
	if (index > 0)
		index--;
	else
		index = cipher_info->tx_index;

	if (index < 0 || index >= MAX_CIPHER_KEYS) {
		WARNING("encryption index out of range (%u)", index);
		TRACEEXIT2(return -EINVAL);
	}

	/* remove key if disabled */
	if (wrqu->data.flags & IW_ENCODE_DISABLED) {
		if (delete_cipher_key(wnd, index, NULL))
			TRACEEXIT2(return -EINVAL);
		else
			TRACEEXIT2(return 0);
	}

	/* global encryption state (for all keys) */
	if (wrqu->data.flags & IW_ENCODE_OPEN)
		res = set_auth_algo(wnd, DOT11_AUTH_ALGO_80211_OPEN);
	else // if (wrqu->data.flags & IW_ENCODE_RESTRICTED)
		res = set_auth_algo(wnd, DOT11_AUTH_ALGO_80211_SHARED_KEY);

	if (res) {
		WARNING("setting authentication mode failed (%08X)", res);
		TRACEEXIT2(return -EINVAL);
	}

	DBGTRACE2("key length: %d", wrqu->data.length);

	if (wrqu->data.length > 0) {
		key_len = wrqu->data.length;
		key = extra;
	} else { // must be set as tx key
		if (cipher_info->keys[index].length == 0) {
			WARNING("key %d is not set", index+1);
			TRACEEXIT2(return -EINVAL);
		}
		key_len = cipher_info->keys[index].length;
		key = cipher_info->keys[index].key;
		cipher_info->tx_index = index;
	}

	if (key_len == 8)
		algo = DOT11_CIPHER_ALGO_WEP40;
	else if (key_len == 16)
		algo = DOT11_CIPHER_ALGO_WEP104;
	else
		return -EINVAL;
	if (add_cipher_key(wnd, key, key_len, index, algo, NULL))
		TRACEEXIT2(return -EINVAL);

	if (index == cipher_info->tx_index) {
		/* if transmit key is at index other than 0, some
		 * drivers, at least Atheros and TI, want another
		 * (global) non-transmit key to be set; don't know why */
		if (index != 0) {
			int i;
			for (i = 0; i < MAX_CIPHER_KEYS; i++)
				if (i != index &&
				    cipher_info->keys[i].length != 0)
					break;
			if (i == MAX_CIPHER_KEYS) {
				algo = wnd->cipher_info.algo;
				if (index == 0)
					i = index + 1;
				else
					i = index - 1;
				if (add_cipher_key(wnd, key, key_len, i, algo,
						   NULL))
					WARNING("couldn't add broadcast key"
						" at %d", i);
			}
		}
		/* ndis drivers want essid to be set after setting encr */
		set_essid(wnd, wnd->essid.essid, wnd->essid.length);
	}
	TRACEEXIT2(return 0);
}

static int iw_set_nick(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);

	if (wrqu->data.length > IW_ESSID_MAX_SIZE || wrqu->data.length <= 0)
		return -EINVAL;
	memcpy(wnd->nick, extra, wrqu->data.length);
	wnd->nick[wrqu->data.length-1] = 0;
	return 0;
}

static int iw_get_nick(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);

	wrqu->data.length = strlen(wnd->nick);
	memcpy(extra, wnd->nick, wrqu->data.length);
	return 0;
}

static char *ndis_translate_scan(struct net_device *dev, char *event,
				 char *end_buf, void *item)
{
	struct iw_event iwe;
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
	cur_item = (typeof(cur_item))byte_array->buffer;
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
	return 0;
}

static int iw_get_power_mode(struct net_device *dev,
			     struct iw_request_info *info,
			     union iwreq_data *wrqu, char *extra)
{
	return 0;
}

static int iw_get_sensitivity(struct net_device *dev,
			      struct iw_request_info *info,
			      union iwreq_data *wrqu, char *extra)
{
	return 0;
}

static int iw_set_sensitivity(struct net_device *dev,
			      struct iw_request_info *info,
			      union iwreq_data *wrqu, char *extra)
{
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
	return 0;
}

static int disassociate(struct wrap_ndis_device *wnd)
{
	NDIS_STATUS res;

	res = miniport_set_info(wnd, OID_DOT11_DISCONNECT_REQUEST, NULL, 0);
	return res;
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
	return 0;
}

static int iw_get_auth(struct net_device *dev,
		       struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	return 0;
}

static int iw_set_encodeext(struct net_device *dev,
			    struct iw_request_info *info,
			    union iwreq_data *wrqu, char *extra)
{
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
	[SIOCGIWENCODE	- SIOCIWFIRST] = iw_get_cipher,
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
	TRACEENTER2("");
	TRACEEXIT2(return 0);
}

static int priv_network_type(struct net_device *dev,
			     struct iw_request_info *info,
			     union iwreq_data *wrqu, char *extra)
{
	TRACEEXIT2(return 0);
}

static int priv_media_stream_mode(struct net_device *dev,
				  struct iw_request_info *info,
				  union iwreq_data *wrqu, char *extra)
{
	TRACEEXIT2(return 0);
}

static int priv_set_cipher_mode(struct net_device *dev,
				struct iw_request_info *info,
				union iwreq_data *wrqu, char *extra)
{
	TRACEEXIT2(return 0);
}

static int priv_set_auth_mode(struct net_device *dev,
			      struct iw_request_info *info,
			      union iwreq_data *wrqu, char *extra)
{
	TRACEEXIT2(return 0);
}

static int priv_reload_defaults(struct net_device *dev,
				struct iw_request_info *info,
				union iwreq_data *wrqu, char *extra)
{
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

	{PRIV_SET_CIPHER_MODE, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0,
	 "set_cipher_mode"},
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
	[PRIV_SET_CIPHER_MODE 	- SIOCIWFIRSTPRIV] = priv_set_cipher_mode,
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
