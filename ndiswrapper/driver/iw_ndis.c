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

#ifdef CONFIG_WIRELESS_EXT

static int freq_chan[] = { 2412, 2417, 2422, 2427, 2432, 2437, 2442,
			   2447, 2452, 2457, 2462, 2467, 2472, 2484 };

NDIS_STATUS set_essid(struct ndis_device *wnd,
		      const char *ssid, int ssid_len)
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
	res = mp_set(wnd, OID_DOT11_DESIRED_SSID_LIST, &ssid_list,
		     sizeof(ssid_list));
	if (res)
		WARNING("setting ssid list failed: %08X", res);
#if 0
	res = set_auth_algo(wnd, DOT11_AUTH_ALGO_80211_OPEN);
	if (res)
		WARNING("setting authentication mode failed: %08X", res);
	res = set_cipher_algo(wnd, DOT11_CIPHER_ALGO_NONE);
	if (res)
		WARNING("setting encryption mode failed: %08X", res);
#endif
	sleep_hz(HZ);
	res = mp_set(wnd, OID_DOT11_CONNECT_REQUEST, NULL, 0);
	if (res)
		WARNING("connection request failed: %08X", res);
	EXIT2(return res);
}

static int set_assoc_params(struct ndis_device *wnd)
{
	return 0;
}

static int iw_set_essid(struct net_device *dev, struct iw_request_info *info,
			union iwreq_data *wrqu, char *extra)
{
	struct ndis_device *wnd = netdev_priv(dev);
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
	if (res != NDIS_STATUS_SUCCESS)
		res = -EOPNOTSUPP;
	EXIT2(return res);
}

static int iw_get_essid(struct net_device *dev, struct iw_request_info *info,
			union iwreq_data *wrqu, char *extra)
{
	struct ndis_device *wnd = netdev_priv(dev);
	struct ndis_dot11_ssid_list ssid_list;
	NDIS_STATUS res;

	memset(&ssid_list, 0, sizeof(ssid_list));
	init_ndis_object_header(&ssid_list, NDIS_OBJECT_TYPE_DEFAULT,
				DOT11_SSID_LIST_REVISION_1);
	res = mp_query(wnd, OID_DOT11_DESIRED_SSID_LIST, &ssid_list,
		       sizeof(ssid_list));
	if (res) {
		WARNING("getting essid failed: %08X", res);
		res = -EOPNOTSUPP;
	} else if (ssid_list.ssids[0].length < IW_ESSID_MAX_SIZE) {
		memcpy(extra, ssid_list.ssids[0].ssid, ssid_list.ssids[0].length);
		wrqu->essid.length = ssid_list.ssids[0].length;
		if (wrqu->essid.length > 0)
			wrqu->essid.flags  = 1;
		else
			wrqu->essid.flags = 0;
		if (ssid_list.ssids[0].length == DOT11_SSID_MAX_LENGTH)
			ssid_list.ssids[0].length--;
		ssid_list.ssids[0].ssid[ssid_list.ssids[0].length] = 0;
		TRACE2("\"%s\"", ssid_list.ssids[0].ssid);
		res = 0;
	} else
		res = -EOPNOTSUPP;
	EXIT2(return res);
}

NDIS_STATUS set_infra_mode(struct ndis_device *wnd,
			   enum ndis_dot11_bss_type type)
{
	NDIS_STATUS res;
	res = mp_set_int(wnd, OID_DOT11_DESIRED_BSS_TYPE, type);
	if (res)
		WARNING("setting mode to %d failed: %08X", type, res);
	else
		wnd->bss_type = type;
	EXIT2(return res);
}

static int iw_set_infra_mode(struct net_device *dev,
			     struct iw_request_info *info,
			     union iwreq_data *wrqu, char *extra)
{
	struct ndis_device *wnd = netdev_priv(dev);
	enum ndis_dot11_bss_type bss_type;

	ENTER2("%d", wrqu->mode);
	switch (wrqu->mode) {
	case IW_MODE_INFRA:
		bss_type = ndis_dot11_bss_type_infrastructure;
		break;
	case IW_MODE_ADHOC:
		bss_type = ndis_dot11_bss_type_independent;
		break;
	default:
		EXIT2(return -EINVAL);
	}

	if (set_infra_mode(wnd, bss_type))
		EXIT2(return -EINVAL);
	EXIT2(return 0);
}

static int iw_get_infra_mode(struct net_device *dev,
			     struct iw_request_info *info,
			     union iwreq_data *wrqu, char *extra)
{
	struct ndis_device *wnd = netdev_priv(dev);
	NDIS_STATUS res;
	enum ndis_dot11_bss_type bss_type;

	res = mp_query_int(wnd, OID_DOT11_DESIRED_BSS_TYPE, &bss_type);
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
		EXIT2(return -EINVAL);
	}
	EXIT2(return 0);
}

static const char *network_type_to_name(enum ndis_dot11_phy_type type)
{
	switch (type) {
	case ndis_dot11_phy_type_any:
		return "Auto";
	case ndis_dot11_phy_type_fhss:
		return "IEEE 802.11FH";
	case ndis_dot11_phy_type_dsss:
		return "IEEE 802.11";
	case ndis_dot11_phy_type_ofdm:
		return "IEEE 802.11a";
	case ndis_dot11_phy_type_hrdsss:
		return "IEEE 802.11b";
	case ndis_dot11_phy_type_erp:
		return "IEEE 802.11g";
	default:
		WARNING("invalid type: %d", type);
		return "Unkown";
	}
}

static int iw_get_network_type(struct net_device *dev,
			       struct iw_request_info *info,
			       union iwreq_data *wrqu, char *extra)
{
	struct ndis_device *wnd = netdev_priv(dev);
	NDIS_STATUS res;
	int n;

	res = mp_query_int(wnd, OID_DOT11_CURRENT_PHY_ID, &n);
	TRACE2("%08X, %d", res, n);
	if (res || n > wnd->phy_types->num_entries)
		EXIT2(return -EOPNOTSUPP);
	if (n != wnd->phy_id) {
		WARNING("%u != %u", n, wnd->phy_id);
		wnd->phy_id = n;
	}
	strncpy(wrqu->name,
		network_type_to_name(wnd->phy_types->phy_types[n]),
		sizeof(wrqu->name) - 1);
	wrqu->name[sizeof(wrqu->name)-1] = 0;
	return 0;
}

static int iw_get_freq(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct ndis_device *wnd = netdev_priv(dev);
	NDIS_STATUS res;
	ULONG ndis_freq;

	res = mp_query(wnd, OID_DOT11_CURRENT_CHANNEL,
		       &ndis_freq, sizeof(ndis_freq));
	if (res) {
		WARNING("getting frequency failed: %08X", res);
		return -EOPNOTSUPP;
	}
	TRACE2("%d", ndis_freq);
	if (ndis_freq >= 1 &&
	    ndis_freq <= sizeof(freq_chan) / sizeof(freq_chan[0]))
		wrqu->freq.m = freq_chan[ndis_freq - 1];
	else
		wrqu->freq.m = 0;
	wrqu->freq.e = 0;
	return 0;
}

static int iw_set_freq(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct ndis_device *wnd = netdev_priv(dev);
	NDIS_STATUS res;
	ULONG ndis_freq;

	if (wrqu->freq.m < 1000 && wrqu->freq.e == 0)
		ndis_freq = wrqu->freq.m;
	else {
		int i;
		ndis_freq = wrqu->freq.m;
		for (i = wrqu->freq.e; i > 0; i--)
			ndis_freq *= 10;
		for (i = 0; i < sizeof(freq_chan) / sizeof(freq_chan[0]); i++)
			if (ndis_freq <= freq_chan[i])
				break;
		ndis_freq = i;
	}

	res = mp_set(wnd, OID_DOT11_CURRENT_CHANNEL,
		     &ndis_freq, sizeof(ndis_freq));
	if (res) {
		WARNING("setting frequency failed: %08X", res);
		return -EINVAL;
	}
	return 0;
}

static int iw_get_tx_power(struct net_device *dev, struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	struct ndis_device *wnd = netdev_priv(dev);
	struct ndis_dot11_supported_power_levels power_levels;
	NDIS_STATUS res;
	ULONG n;

	res = mp_query(wnd, OID_DOT11_SUPPORTED_POWER_LEVELS, &power_levels,
		       sizeof(power_levels));
	if (res) {
		WARNING("query failed: %08X", res);
		return -EOPNOTSUPP;
	}
	res = mp_query(wnd, OID_DOT11_CURRENT_TX_POWER_LEVEL, &n, sizeof(n));
	TRACE2("%d", n);
	if (res || n < 1 || n > power_levels.num_levels) {
		WARNING("query failed: %08X, %d", res, n);
		return -EOPNOTSUPP;
	}
	wrqu->txpower.flags = IW_TXPOW_MWATT;
	wrqu->txpower.disabled = 0;
	wrqu->txpower.fixed = 0;
	wrqu->txpower.value = power_levels.levels[n - 1];
	return 0;
}

static int iw_set_tx_power(struct net_device *dev, struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	struct ndis_device *wnd = netdev_priv(dev);
	struct ndis_dot11_supported_power_levels power_levels;
	NDIS_STATUS res;
	ULONG i, n;


	res = mp_query(wnd, OID_DOT11_SUPPORTED_POWER_LEVELS, &power_levels,
		       sizeof(power_levels));
	if (res) {
		WARNING("query failed: %08X", res);
		return -EOPNOTSUPP;
	}
	if (wrqu->txpower.flags == IW_TXPOW_MWATT)
		n = wrqu->txpower.value;
	else { // wrqu->txpower.flags == IW_TXPOW_DBM
		if (wrqu->txpower.value > 20)
			n = 128;
		else if (wrqu->txpower.value < -43)
			n = 127;
		else {
			signed char tmp;
			tmp = wrqu->txpower.value;
			tmp = -12 - tmp;
			tmp <<= 2;
			n = (unsigned char)tmp;
		}
	}
	for (i = 1; i < power_levels.num_levels; i++) {
		if (n >= power_levels.levels[i-1] &&
		    n <= power_levels.levels[i])
			break;
	}
	i = max(i, power_levels.num_levels-1);
	res = mp_set_int(wnd, OID_DOT11_CURRENT_TX_POWER_LEVEL, i+1);
	if (res) {
		WARNING("query failed: %08X", res);
		return -EOPNOTSUPP;
	}
	return 0;
}

static int iw_get_bitrate(struct net_device *dev, struct iw_request_info *info,
			  union iwreq_data *wrqu, char *extra)
{
	struct ndis_device *wnd = netdev_priv(dev);
	ULONG ndis_rate;
	int res;

	ENTER2("");
	res = mp_query(wnd, OID_GEN_LINK_SPEED, &ndis_rate, sizeof(ndis_rate));
	if (res) {
		WARNING("getting bitrate failed (%08X)", res);
		ndis_rate = 0;
	}

	wrqu->bitrate.value = ndis_rate * 100;
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
	struct ndis_device *wnd = netdev_priv(dev);
	NDIS_STATUS res;

	res = mp_query_int(wnd, OID_DOT11_RTS_THRESHOLD, &wrqu->rts.value);
	if (res) {
		WARNING("getting fragmentation threshold failed: %08X", res);
		return -EOPNOTSUPP;
	}
	return 0;
}

static int iw_set_rts_threshold(struct net_device *dev,
				struct iw_request_info *info,
				union iwreq_data *wrqu, char *extra)
{
	struct ndis_device *wnd = netdev_priv(dev);
	NDIS_STATUS res;

	res = mp_set_int(wnd, OID_DOT11_RTS_THRESHOLD, wrqu->rts.value);
	if (res) {
		WARNING("setting fragmentation threshold failed: %08X", res);
		return -EINVAL;
	}
	return 0;
}

static int iw_get_frag_threshold(struct net_device *dev,
				 struct iw_request_info *info,
				 union iwreq_data *wrqu, char *extra)
{
	struct ndis_device *wnd = netdev_priv(dev);
	NDIS_STATUS res;

	res = mp_query_int(wnd, OID_DOT11_FRAGMENTATION_THRESHOLD,
			   &wrqu->frag.value);
	if (res) {
		WARNING("getting fragmentation threshold failed: %08X", res);
		return -EOPNOTSUPP;
	}
	return 0;
}

static int iw_set_frag_threshold(struct net_device *dev,
				 struct iw_request_info *info,
				 union iwreq_data *wrqu, char *extra)
{
	struct ndis_device *wnd = netdev_priv(dev);
	NDIS_STATUS res;

	res = mp_set_int(wnd, OID_DOT11_FRAGMENTATION_THRESHOLD,
			 wrqu->frag.value);
	if (res) {
		WARNING("setting fragmentation threshold failed: %08X", res);
		return -EINVAL;
	}
	return 0;
}

static int iw_get_ap_address(struct net_device *dev,
			     struct iw_request_info *info,
			     union iwreq_data *wrqu, char *extra)
{
	struct ndis_device *wnd = netdev_priv(dev);
	struct ndis_dot11_association_info_list *assoc_list;
	struct ndis_dot11_association_info_ex *assoc_info;
	NDIS_STATUS res;

	assoc_list = kzalloc(sizeof(*assoc_list) + 20, GFP_KERNEL);
	if (!assoc_list)
		return -ENOMEM;

	init_ndis_object_header(assoc_list, NDIS_OBJECT_TYPE_DEFAULT,
				DOT11_ASSOCIATION_INFO_LIST_REVISION_1);

	res = mp_query(wnd, OID_DOT11_ENUM_ASSOCIATION_INFO, assoc_list,
		       sizeof(*assoc_list) + 20);
	if (res) {
		WARNING("getting association info failed: %08X", res);
		kfree(assoc_list);
		return -EOPNOTSUPP;
	}
	TRACE2("%d, %d", assoc_list->num_entries, assoc_list->num_total_entries);
	assoc_info = &assoc_list->assoc_info[0];
	TRACE2("ap: " MACSTRSEP ", " MACSTRSEP
	       ", %d, %d, %d, %lld, %llu, %llu, %llu, %llu",
	       MAC2STR(assoc_info->peer_mac), MAC2STR(assoc_info->bssid),
	       assoc_info->assoc_id, assoc_info->assoc_state,
	       assoc_info->power_mode,
	       assoc_info->assoc_uptime,
	       assoc_info->num_tx_packet_success,
	       assoc_info->num_tx_packet_failure,
	       assoc_info->num_rx_packet_success,
	       assoc_info->num_rx_packet_failure);
	memcpy(wrqu->ap_addr.sa_data, assoc_info->peer_mac,
	       sizeof(assoc_info->peer_mac));
	wrqu->ap_addr.sa_family = ARPHRD_ETHER;
	kfree(assoc_list);
	EXIT2(return 0);
}

static int iw_set_ap_address(struct net_device *dev,
			     struct iw_request_info *info,
			     union iwreq_data *wrqu, char *extra)
{
	struct ndis_device *wnd = netdev_priv(dev);
	struct ndis_dot11_bssid_list bssid_list;
	NDIS_STATUS res;

	memset(&bssid_list, 0, sizeof(bssid_list));
	init_ndis_object_header(&bssid_list, NDIS_OBJECT_TYPE_DEFAULT,
				DOT11_BSSID_LIST_REVISION_1);
	bssid_list.num_entries = 1;
	bssid_list.num_total_entries = 1;
	memcpy(bssid_list.bssids[0], wrqu->ap_addr.sa_data,
	       sizeof(bssid_list.bssids[0]));
	TRACE2("ap: " MACSTRSEP, MAC2STR(bssid_list.bssids[0]));
	res = mp_set(wnd, OID_DOT11_DESIRED_BSSID_LIST,
		     &bssid_list, sizeof(bssid_list));
	if (res) {
		WARNING("setting bssid list failed: %08X", res);
		return -EINVAL;
	}
	EXIT2(return 0);
}

NDIS_STATUS set_auth_algo(struct ndis_device *wnd,
			  enum ndis_dot11_auth_algorithm algo_id)
{
	struct ndis_dot11_auth_algorithm_list auth_algos;
	NDIS_STATUS res;

	TRACE2("%d", algo_id);
	memset(&auth_algos, 0, sizeof(auth_algos));
	init_ndis_object_header(&auth_algos, NDIS_OBJECT_TYPE_DEFAULT,
				DOT11_AUTH_ALGORITHM_LIST_REVISION_1);
	auth_algos.num_entries = 1;
	auth_algos.num_total_entries = 1;
	auth_algos.algo_ids[0] = algo_id;
	res = mp_set(wnd, OID_DOT11_ENABLED_AUTHENTICATION_ALGORITHM,
		     &auth_algos, sizeof(auth_algos));
	if (res)
		WARNING("setting authentication mode to %d failed: %08X",
			algo_id, res);
	EXIT2(return res);
}

static enum ndis_dot11_auth_algorithm get_auth_algo(struct ndis_device *wnd)
{
	struct ndis_dot11_auth_algorithm_list auth_algos;
	NDIS_STATUS res;

	memset(&auth_algos, 0, sizeof(auth_algos));
	init_ndis_object_header(&auth_algos, NDIS_OBJECT_TYPE_DEFAULT,
				DOT11_AUTH_ALGORITHM_LIST_REVISION_1);
	auth_algos.num_entries = 1;
	auth_algos.num_total_entries = 1;
	res = mp_query(wnd, OID_DOT11_ENABLED_AUTHENTICATION_ALGORITHM,
		       &auth_algos, sizeof(auth_algos));
	if (res) {
		WARNING("getting authentication mode failed: %08X", res);
		return DOT11_AUTH_ALGO_80211_OPEN;
	}
	TRACE2("%d", auth_algos.algo_ids[0]);
	EXIT2(return auth_algos.algo_ids[0]);
}

NDIS_STATUS set_cipher_algo(struct ndis_device *wnd,
			    enum ndis_dot11_cipher_algorithm algo_id)
{
	struct ndis_dot11_cipher_algorithm_list cipher_algos;
	NDIS_STATUS res;

	TRACE2("%d", algo_id);
	memset(&cipher_algos, 0, sizeof(cipher_algos));
	init_ndis_object_header(&cipher_algos, NDIS_OBJECT_TYPE_DEFAULT,
				DOT11_CIPHER_ALGORITHM_LIST_REVISION_1);
	cipher_algos.num_entries = 1;
	cipher_algos.num_total_entries = 1;
	cipher_algos.algo_ids[0] = algo_id;
	res = mp_set(wnd, OID_DOT11_ENABLED_UNICAST_CIPHER_ALGORITHM,
		     &cipher_algos, sizeof(cipher_algos));
	if (res)
		WARNING("setting cipher algorithm to %d failed: %08X",
			algo_id, res);
#if 0
	else {
		BOOLEAN exclude_unencr;
		if (algo_id == DOT11_CIPHER_ALGO_NONE)
			exclude_unencr = FALSE;
		else
			exclude_unencr = TRUE;
		res = 0;
		res = mp_set(wnd, OID_DOT11_EXCLUDE_UNENCRYPTED,
			     &exclude_unencr, sizeof(ULONG));
		if (res)
			WARNING("setting cipher failed: %08X", res);
		else
			wnd->cipher_info.algo = algo_id;
	}
#endif
	EXIT2(return res);
}

static enum ndis_dot11_cipher_algorithm get_cipher_algo(struct ndis_device *wnd)
{
	struct ndis_dot11_cipher_algorithm_list cipher_algos;
	NDIS_STATUS res;

	memset(&cipher_algos, 0, sizeof(cipher_algos));
	init_ndis_object_header(&cipher_algos, NDIS_OBJECT_TYPE_DEFAULT,
				DOT11_CIPHER_ALGORITHM_LIST_REVISION_1);
	cipher_algos.num_entries = 1;
	cipher_algos.num_total_entries = 1;
#if 0
	res = mp_query(wnd, OID_DOT11_ENABLED_MULTICAST_CIPHER_ALGORITHM,
		       &cipher_algos, sizeof(cipher_algos));
	if (res)
		WARNING("getting cipher algorithm failed: %08X", res);
	TRACE2("%d, %d", cipher_algos.algo_ids[0], wnd->cipher_info.algo);
#endif
	res = mp_query(wnd, OID_DOT11_ENABLED_UNICAST_CIPHER_ALGORITHM,
		       &cipher_algos, sizeof(cipher_algos));
	if (res) {
		WARNING("getting cipher algorithm failed: %08X", res);
		return DOT11_CIPHER_ALGO_NONE;
	}
	TRACE2("%d, %d", cipher_algos.algo_ids[0], wnd->cipher_info.algo);
	if (cipher_algos.algo_ids[0] != wnd->cipher_info.algo)
		WARNING("%d != %d", cipher_algos.algo_ids[0],
			wnd->cipher_info.algo);
	wnd->cipher_info.algo = cipher_algos.algo_ids[0];
	EXIT2(return cipher_algos.algo_ids[0]);
}

static int iw_get_cipher(struct net_device *dev, struct iw_request_info *info,
			 union iwreq_data *wrqu, char *extra)
{
	struct ndis_device *wnd = netdev_priv(dev);
	int index, mode;
	struct cipher_info *cipher_info = &wnd->cipher_info;

	ENTER2("wnd = %p", wnd);
	wrqu->data.length = 0;
	extra[0] = 0;

	index = (wrqu->encoding.flags & IW_ENCODE_INDEX);
	TRACE2("index = %u", index);
	if (index > 0)
		index--;
	else
		index = cipher_info->tx_index;

	if (index < 0 || index >= MAX_CIPHER_KEYS) {
		WARNING("encryption index out of range (%u)", index);
		EXIT2(return -EINVAL);
	}

	if (index != cipher_info->tx_index) {
		if (cipher_info->keys[index].length > 0) {
			wrqu->data.flags |= IW_ENCODE_ENABLED;
			wrqu->data.length = cipher_info->keys[index].length;
			memcpy(extra, cipher_info->keys[index].key,
			       cipher_info->keys[index].length);
		} else
			wrqu->data.flags |= IW_ENCODE_DISABLED;
		EXIT2(return 0);
	}

	/* transmit key */
	mode = get_cipher_algo(wnd);
	if (mode < 0)
		EXIT2(return -EOPNOTSUPP);

	if (mode == DOT11_CIPHER_ALGO_NONE)
		wrqu->data.flags |= IW_ENCODE_DISABLED;
	else {
		wrqu->data.flags |= IW_ENCODE_ENABLED;
		wrqu->encoding.flags |= index + 1;
		wrqu->data.length = cipher_info->keys[index].length;
		memcpy(extra, cipher_info->keys[index].key,
		       cipher_info->keys[index].length);
		mode = get_auth_algo(wnd);
		if (mode < 0)
			EXIT2(return -EOPNOTSUPP);

		if (mode == DOT11_AUTH_ALGO_80211_OPEN)
			wrqu->data.flags |= IW_ENCODE_OPEN;
		else if (mode == DOT11_AUTH_ALGO_80211_SHARED_KEY)
			wrqu->data.flags |= IW_ENCODE_RESTRICTED;
		else // WPA / RSNA etc
			wrqu->data.flags |= IW_ENCODE_RESTRICTED;
	}

	EXIT2(return 0);
}

/* index must be 0 - N, as per NDIS  */
static int add_cipher_key(struct ndis_device *wnd, char *key, int key_len,
			  int index, enum ndis_dot11_cipher_algorithm algo,
			  mac_address mac)
{
	struct ndis_dot11_cipher_default_key_value *ndis_key;
	NDIS_STATUS res;

	ENTER2("key index: %d, length: %d", index, key_len);
	if (key_len <= 0 || key_len > NDIS_ENCODING_TOKEN_MAX) {
		WARNING("invalid key length (%d)", key_len);
		EXIT2(return -EINVAL);
	}
	if (index < 0 || index >= MAX_CIPHER_KEYS) {
		WARNING("invalid key index (%d)", index);
		EXIT2(return -EINVAL);
	}
#if 0
	if (wnd->cipher_info.algo != DOT11_CIPHER_ALGO_NONE &&
	    wnd->cipher_info.algo != algo) {
		WARNING("invalid algorithm: %d/%d", wnd->cipher_info.algo, algo);
		return -EINVAL;
	}
#endif
	ndis_key = kzalloc(sizeof(*ndis_key) + key_len - 1, GFP_KERNEL);
	if (!ndis_key)
		return -ENOMEM;

	init_ndis_object_header(ndis_key, NDIS_OBJECT_TYPE_DEFAULT,
				DOT11_CIPHER_DEFAULT_KEY_VALUE_REVISION_1);

	ndis_key->key_index = index;
	TRACE2("key %d/%d: " MACSTRSEP, index, key_len, MAC2STR(key));

	ndis_key->algo_id = algo;
	if (mac)
		memcpy(ndis_key->mac, mac, sizeof(ndis_key->mac));
	ndis_key->is_static = TRUE;
	ndis_key->key_length = key_len;
	memcpy(ndis_key->key, key, key_len);

	res = mp_set(wnd, OID_DOT11_CIPHER_DEFAULT_KEY, ndis_key,
		     sizeof(*ndis_key) + key_len - 1);
	if (res) {
		WARNING("adding key %d failed (%08X)", index + 1, res);
		kfree(ndis_key);
		EXIT2(return -EINVAL);
	}

	wnd->cipher_info.keys[index].length = key_len;
	memcpy(&wnd->cipher_info.keys[index].key, key, key_len);
	wnd->cipher_info.algo = algo;
	kfree(ndis_key);
	EXIT2(return 0);
}

static int delete_cipher_key(struct ndis_device *wnd, int index,
			     mac_address mac)
{
	struct ndis_dot11_cipher_default_key_value *ndis_key;
	char key_buf[sizeof(*ndis_key) + NDIS_ENCODING_TOKEN_MAX - 1];
	NDIS_STATUS res;

	ENTER2("key index: %d", index);
	if (wnd->cipher_info.keys[index].length == 0)
		EXIT2(return 0);

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

	res = mp_set(wnd, OID_DOT11_CIPHER_DEFAULT_KEY, ndis_key,
		     sizeof(*ndis_key));
	if (res) {
		WARNING("deleting key %d failed (%08X)", index + 1, res);
		EXIT2(return -EINVAL);
	}
	wnd->cipher_info.keys[index].length = 0;
	memset(&wnd->cipher_info.keys[index].key, 0,
	       sizeof(wnd->cipher_info.keys[index].length));
	EXIT2(return 0);
}

static int iw_set_wep(struct net_device *dev, struct iw_request_info *info,
		      union iwreq_data *wrqu, char *extra)
{
	struct ndis_device *wnd = netdev_priv(dev);
	NDIS_STATUS res;
	unsigned int index, key_len;
	struct cipher_info *cipher_info = &wnd->cipher_info;
	unsigned char *key;
	enum ndis_dot11_cipher_algorithm algo;

	ENTER2("");
	index = (wrqu->encoding.flags & IW_ENCODE_INDEX);
	TRACE2("index = %u", index);

	/* iwconfig gives index as 1 - N */
	if (index > 0)
		index--;
	else
		index = cipher_info->tx_index;

	if (index >= MAX_CIPHER_KEYS) {
		WARNING("encryption index out of range (%u)", index);
		EXIT2(return -EINVAL);
	}

	/* remove key if disabled */
	if (wrqu->data.flags & IW_ENCODE_DISABLED) {
		if (delete_cipher_key(wnd, index, NULL))
			EXIT2(return -EINVAL);
		if (index == cipher_info->tx_index) {
			res = set_cipher_algo(wnd, DOT11_CIPHER_ALGO_NONE);
			if (res)
				WARNING("couldn't disable encryption: %08X",
					res);
		}
		EXIT2(return 0);
	}

	/* global encryption state (for all keys) */
	if (wrqu->data.flags & IW_ENCODE_OPEN)
		res = set_auth_algo(wnd, DOT11_AUTH_ALGO_80211_OPEN);
	else // if (wrqu->data.flags & IW_ENCODE_RESTRICTED)
		res = set_auth_algo(wnd, DOT11_AUTH_ALGO_80211_SHARED_KEY);

	if (res) {
		WARNING("setting authentication mode failed (%08X)", res);
//		EXIT2(return -EINVAL);
	}

	TRACE2("key length: %d", wrqu->data.length);

	if (wrqu->data.length > 0) {
		key_len = wrqu->data.length;
		key = extra;
	} else { // must be set as tx key
		if (cipher_info->keys[index].length == 0) {
			WARNING("key %d is not set", index+1);
			EXIT2(return -EINVAL);
		}
		key_len = cipher_info->keys[index].length;
		key = cipher_info->keys[index].key;
		cipher_info->tx_index = index;
	}

	if (key_len == 5)
		algo = DOT11_CIPHER_ALGO_WEP40;
	else if (key_len == 13)
		algo = DOT11_CIPHER_ALGO_WEP104;
	else
		return -EINVAL;

	if (add_cipher_key(wnd, key, key_len, index, algo, NULL))
		EXIT2(return -EINVAL);

#if 0
	if (index == cipher_info->tx_index) {
		res = mp_set(wnd, OID_DOT11_CIPHER_DEFAULT_KEY_ID,
			     &index, sizeof(ULONG));
		if (res) {
			WARNING("couldn't set tx key to %d: %08X", index, res);
			return -EINVAL;
		} else {
			/* ndis drivers want essid to be set after
			 * setting encr */
//			set_essid(wnd, wnd->essid.essid, wnd->essid.length);
		}
	}
#endif
	set_cipher_algo(wnd, algo);
	EXIT2(return 0);
}

static int iw_set_nick(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct ndis_device *wnd = netdev_priv(dev);

	if (wrqu->data.length > IW_ESSID_MAX_SIZE || wrqu->data.length <= 0)
		return -EINVAL;
	memcpy(wnd->nick, extra, wrqu->data.length);
	wnd->nick[wrqu->data.length-1] = 0;
	return 0;
}

static int iw_get_nick(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct ndis_device *wnd = netdev_priv(dev);

	wrqu->data.length = strlen(wnd->nick);
	memcpy(extra, wnd->nick, wrqu->data.length);
	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27) && !defined(IW_REQUEST_FLAG_COMPAT)
#define	iwe_stream_add_event(a, b, c, d, e)	iwe_stream_add_event(b, c, d, e)
#define	iwe_stream_add_point(a, b, c, d, e)	iwe_stream_add_point(b, c, d, e)
#define	iwe_stream_add_value(a, b, c, d, e, f)	\
	iwe_stream_add_value(b, c, d, e, f)
#define	iwe_stream_lcp_len(a)			IW_EV_LCP_LEN
#endif

static char *ndis_translate_scan(struct net_device *dev,
				 struct iw_request_info *info, char *event,
				 char *end_buf, void *item)
{
	struct ndis_device *wnd = netdev_priv(dev);
	struct iw_event iwe;
	struct ndis_dot11_bss_entry *bss;
	struct ndis_dot11_info_element *ie;
	unsigned char buf[MAX_WPA_IE_LEN * 2 + 30];
	unsigned long i;
	char *cbuf;

	ENTER2("%p, %p", event, item);
	bss = item;

	TRACE2("0x%x, 0x%x, 0x%x", bss->phy_id, bss->bss_type,
		  bss->in_reg_domain);
	if (bss->phy_id > 2)
		return event;
	/* add mac address */
	memset(&iwe, 0, sizeof(iwe));
	iwe.cmd = SIOCGIWAP;
	iwe.u.ap_addr.sa_family = ARPHRD_ETHER;
	iwe.len = IW_EV_ADDR_LEN;
	memcpy(iwe.u.ap_addr.sa_data, bss->bss_id, ETH_ALEN);
	event = iwe_stream_add_event(info, event, end_buf, &iwe,
				     IW_EV_ADDR_LEN);

	/* add protocol name */
	TRACE2("0x%x", bss->phy_id);
	memset(&iwe, 0, sizeof(iwe));
	iwe.cmd = SIOCGIWNAME;
	strncpy(iwe.u.name,
		network_type_to_name(wnd->phy_types->phy_types[bss->phy_id]),
		IFNAMSIZ);
	event = iwe_stream_add_event(info, event, end_buf, &iwe,
				     IW_EV_CHAR_LEN);

	/* add mode */
	memset(&iwe, 0, sizeof(iwe));
	iwe.cmd = SIOCGIWMODE;
	if (bss->bss_type == ndis_dot11_bss_type_independent)
		iwe.u.mode = IW_MODE_ADHOC;
	else if (bss->bss_type == ndis_dot11_bss_type_infrastructure)
		iwe.u.mode = IW_MODE_INFRA;
	else // if (bss->bss_type == ndis_dot11_bss_type_any)
		iwe.u.mode = IW_MODE_AUTO;
	event = iwe_stream_add_event(info, event, end_buf, &iwe,
				     IW_EV_UINT_LEN);

	/* add qual */
	memset(&iwe, 0, sizeof(iwe));
	iwe.cmd = IWEVQUAL;
	iwe.u.qual.level = bss->rssi;
	iwe.u.qual.noise = WL_NOISE;
	iwe.u.qual.qual  = bss->link_quality;
	iwe.len = IW_EV_QUAL_LEN;
	event = iwe_stream_add_event(info, event, end_buf, &iwe,
				     IW_EV_QUAL_LEN);

	memset(&iwe, 0, sizeof(iwe));
	iwe.cmd = IWEVCUSTOM;
	sprintf(buf, "time=%llu", bss->time_stamp);
	iwe.u.data.length = strlen(buf);
	event = iwe_stream_add_point(info, event, end_buf, &iwe, buf);

	i = 0;
	ie = (typeof(ie))bss->buffer;
	while (i < bss->buffer_length) {
		char *current_val;
		TRACE2("0x%x, %u", ie->id, ie->length);
		if (ie->length <= 0)
			break;
		switch (ie->id) {
		case DOT11_IE_SSID:
			memset(&iwe, 0, sizeof(iwe));
			iwe.cmd = SIOCGIWESSID;
			iwe.u.data.length = ie->length;
			if (iwe.u.data.length > IW_ESSID_MAX_SIZE)
				iwe.u.data.length = IW_ESSID_MAX_SIZE;
			iwe.u.data.flags = 1;
			iwe.len = IW_EV_POINT_LEN + iwe.u.data.length;
			event = iwe_stream_add_point(info, event, end_buf, &iwe,
						     ((char *)ie) + sizeof(*ie));
			break;
		case DOT11_IE_SUPPORTED_RATES:
		case DOT11_IE_EXTD_SUPPORTED_RATES:
			memset(&iwe, 0, sizeof(iwe));
			current_val = event + IW_EV_LCP_LEN;
			iwe.cmd = SIOCGIWRATE;
			cbuf = (char *)ie + sizeof(*ie);
			for (i = 0 ; i < ie->length ; i++) {
				if (!(cbuf[i] & 0x7f))
					continue;
				iwe.u.bitrate.value =
					(cbuf[i] & 0x7f) * 500000;
				current_val =
					iwe_stream_add_value(info, event,
							     current_val,
							     end_buf, &iwe,
							     IW_EV_PARAM_LEN);
			}
			if ((current_val - event) > IW_EV_LCP_LEN)
				event = current_val;
			break;
		case DOT11_IE_ERP:
			break;
		case DOT11_IE_RSN:
			memset(&iwe, 0, sizeof(iwe));
			iwe.cmd = IWEVGENIE;
			iwe.u.data.length = ie->length;
			cbuf = (char *)ie + sizeof(*ie);
			event = iwe_stream_add_point(info, event, end_buf,
						     &iwe, cbuf);
			break;
		default:
			TRACE2("unknown element: 0x%x, %u", ie->id, ie->length);
			break;
		}
		TRACE2("%lu, %d", i, ie->length);
		i += ie->length;
		ie = (void *)ie + ie->length;
	}

	EXIT2(return event);
}

int set_scan(struct ndis_device *wnd)
{
	struct ndis_dot11_scan_request_v2 *scan_req;
	int len;
	NDIS_STATUS res;

	ENTER2("");
	len = sizeof(*scan_req) + sizeof(struct ndis_dot11_ssid) +
		sizeof(struct ndis_dot11_phy_type_info);
	len = sizeof(*scan_req) + sizeof(struct ndis_dot11_ssid);
	scan_req = kzalloc(len, GFP_KERNEL);
	if (!scan_req)
		return -ENOMEM;
	TRACE2("%zd, %d, %zd", sizeof(*scan_req), len,
		  sizeof(struct ndis_dot11_ssid));
	scan_req->bss_type = ndis_dot11_bss_type_any;
	memset(scan_req->bssid, 0xff, sizeof(scan_req->bssid));
	scan_req->ssids_offset = 0;
	scan_req->scan_type = ndis_dot11_scan_type_auto;
	scan_req->restricted_scan = FALSE;
	scan_req->num_ssids = 1;
	scan_req->num_phy_types = 0;
//	dump_bytes(__func__, (void *)scan_req, len);
	res = mp_set(wnd, OID_DOT11_SCAN_REQUEST, scan_req, len);
	kfree(scan_req);
	if (res) {
		WARNING("scanning failed (%08X)", res);
		EXIT2(return -EOPNOTSUPP);
	}
	wnd->scan_timestamp = jiffies;
	EXIT2(return 0);
}

static int iw_set_scan(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
//	struct ndis_device *wnd = netdev_priv(dev);
//	return set_scan(wnd);
	return 0;
}

static int iw_get_scan(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct ndis_device *wnd = netdev_priv(dev);
	unsigned int i, len;
	NDIS_STATUS res;
	char *event = extra;
	struct ndis_dot11_byte_array *byte_array;
	struct ndis_dot11_bss_entry *bss;

	ENTER2("");
#if 0
	if (time_before(jiffies, wnd->scan_timestamp + 3 * HZ))
		return -EAGAIN;
#endif
	/* try with space for a few scan items */
	len = sizeof(*byte_array) + sizeof(*bss) * 8;
	len = 1024;
	byte_array = kzalloc(len, GFP_KERNEL);
	if (!byte_array) {
		ERROR("couldn't allocate memory");
		return -ENOMEM;
	}
	TRACE2("%zd", sizeof(*byte_array));
	res = mp_request_method(wnd, OID_DOT11_ENUM_BSS_LIST,
				byte_array, len, &len, NULL);
	TRACE2("%d", len);
	if (res == NDIS_STATUS_INVALID_LENGTH ||
	    res == NDIS_STATUS_BUFFER_OVERFLOW ||
	    res == NDIS_STATUS_BUFFER_TOO_SHORT) {
		/* now try with required space */
		kfree(byte_array);
		byte_array = kzalloc(len, GFP_KERNEL);
		if (!byte_array) {
			ERROR("couldn't allocate memory");
			return -ENOMEM;
		}
		res = mp_request_method(wnd, OID_DOT11_ENUM_BSS_LIST,
					byte_array, len, NULL, NULL);
	}
	if (res) {
		WARNING("getting BSSID list failed (%08X)", res);
		kfree(byte_array);
		EXIT2(return -EOPNOTSUPP);
	}
	TRACE2("%d, %d", byte_array->num_bytes, byte_array->num_total_bytes);
//	dump_bytes(__func__, byte_array->buffer, byte_array->num_bytes);
	for (i = 0; i < byte_array->num_bytes;
	     i += sizeof(*bss) - 1 + bss->buffer_length) {
		bss = (typeof(bss))(&byte_array->buffer[i]);
		TRACE2("%d", bss->buffer_length);
		event = ndis_translate_scan(dev, info, event,
					    extra + IW_SCAN_MAX_DATA, bss);
	}
	wrqu->data.length = event - extra;
	wrqu->data.flags = 0;
	kfree(byte_array);
	EXIT2(return 0);
}

static int iw_set_power_mode(struct net_device *dev,
			     struct iw_request_info *info,
			     union iwreq_data *wrqu, char *extra)
{
	struct ndis_device *wnd = netdev_priv(dev);
	NDIS_STATUS res;
	ULONG power_mode;
	BOOLEAN hw_state;

	ENTER2("");
	if (wrqu->power.disabled == 1) {
		power_mode = DOT11_POWER_SAVING_NO_POWER_SAVING;
		hw_state = FALSE;
	} else {
		power_mode = DOT11_POWER_SAVING_FAST_PSP;
		hw_state = TRUE;
	}

	res = mp_set(wnd, OID_DOT11_HARDWARE_PHY_STATE,
		     &hw_state, sizeof(hw_state));
	TRACE2("%d, %08X", hw_state, res);

	res = mp_set(wnd, OID_DOT11_POWER_MGMT_REQUEST,
		     &power_mode, sizeof(power_mode));
	TRACE2("%d, %08X", power_mode, res);
	if (res)
		WARNING("setting power mode failed (%08X)", res);
	return 0;
}

static int iw_get_power_mode(struct net_device *dev,
			     struct iw_request_info *info,
			     union iwreq_data *wrqu, char *extra)
{
	struct ndis_device *wnd = netdev_priv(dev);
	NDIS_STATUS res;
	ULONG power_mode;
	BOOLEAN hw_state;

	ENTER2("");
	res = mp_query(wnd, OID_DOT11_POWER_MGMT_MODE,
		       &power_mode, sizeof(power_mode));
	TRACE2("%d, %08X", power_mode, res);

	res = mp_query(wnd, OID_DOT11_HARDWARE_PHY_STATE,
		       &hw_state, sizeof(hw_state));
	TRACE2("%d, %08X", hw_state, res);

	res = mp_query(wnd, OID_DOT11_POWER_MGMT_REQUEST,
		       &power_mode, sizeof(power_mode));
	TRACE2("%d, %08X", power_mode, res);
	if (res)
		return -ENOTSUPP;

	if (power_mode == DOT11_POWER_SAVING_NO_POWER_SAVING)
		wrqu->power.disabled = 1;
	else {
		wrqu->power.disabled = 0;
		wrqu->power.flags |= IW_POWER_ALL_R;
		wrqu->power.flags |= IW_POWER_TIMEOUT;
		wrqu->power.value = 0;

		if (power_mode == DOT11_POWER_SAVING_FAST_PSP)
			wrqu->power.flags |= IW_POWER_MIN;
		else if (power_mode == DOT11_POWER_SAVING_MAX_PSP ||
			 power_mode == DOT11_POWER_SAVING_MAXIMUM_LEVEL)
			wrqu->power.flags |= IW_POWER_MAX;
	}
	return 0;
}

static int iw_get_sensitivity(struct net_device *dev,
			      struct iw_request_info *info,
			      union iwreq_data *wrqu, char *extra)
{
	return -EOPNOTSUPP;
}

static int iw_set_sensitivity(struct net_device *dev,
			      struct iw_request_info *info,
			      union iwreq_data *wrqu, char *extra)
{
	return -EOPNOTSUPP;
}

static int iw_get_ndis_stats(struct net_device *dev,
			     struct iw_request_info *info,
			     union iwreq_data *wrqu, char *extra)
{
	struct ndis_device *wnd = netdev_priv(dev);
	struct iw_statistics *stats = &wnd->wireless_stats;
	memcpy(&wrqu->qual, &stats->qual, sizeof(stats->qual));
	return 0;
}

static int iw_get_range(struct net_device *dev, struct iw_request_info *info,
			union iwreq_data *wrqu, char *extra)
{
	struct iw_range *range = (struct iw_range *)extra;
	struct iw_point *data = &wrqu->data;
	struct ndis_device *wnd = netdev_priv(dev);
	unsigned int i;
	struct ndis_dot11_supported_data_rates_value_v2 *data_rates;
	struct ndis_dot11_supported_power_levels *power_levels;

	ENTER2("");
	data->length = sizeof(struct iw_range);
	memset(range, 0, sizeof(struct iw_range));

	range->txpower_capa = IW_TXPOW_MWATT;
	range->num_txpower = 0;
	power_levels = kzalloc(sizeof(*power_levels), GFP_KERNEL);
	if (power_levels &&
	    (mp_query(wnd, OID_DOT11_SUPPORTED_POWER_LEVELS,
		      power_levels, sizeof(*power_levels)) ==
	     NDIS_STATUS_SUCCESS)) {
		for (i = 0; i < power_levels->num_levels; i++) {
			range->txpower[range->num_txpower++] =
				power_levels->levels[i];
		}
	}
	kfree(power_levels);

	range->we_version_compiled = WIRELESS_EXT;
	range->we_version_source = 18;

	range->retry_capa = IW_RETRY_LIMIT;
	range->retry_flags = IW_RETRY_LIMIT;
	range->min_retry = 0;
	range->max_retry = 255;

	range->num_channels = 1;

	range->max_qual.qual = 100;
	range->max_qual.level = 154;
	range->max_qual.noise = 154;

	range->max_encoding_tokens = 4;
	range->num_encoding_sizes = 2;
	range->encoding_size[0] = 5;
	range->encoding_size[1] = 13;

	range->sensitivity = 0;
	range->num_bitrates = 0;
	data_rates = kzalloc(sizeof(*data_rates), GFP_KERNEL);
	if (data_rates &&
	    (mp_query(wnd, OID_DOT11_SUPPORTED_DATA_RATES_VALUE,
		      data_rates, sizeof(*data_rates)) ==
	     NDIS_STATUS_SUCCESS)) {
		for (i = 0; i < MAX_NUM_SUPPORTED_RATES_V2 &&
			     data_rates->tx_rates[i]; i++) {
			if (!(data_rates->tx_rates[i] & 0x7f))
				continue;
			range->bitrate[range->num_bitrates++] =
				(data_rates->tx_rates[i] & 0x7f) * 500000;
		}
	}
	kfree(data_rates);

	range->num_channels = (sizeof(freq_chan) / sizeof(freq_chan[0]));

	for (i = 0; i < (sizeof(freq_chan) / sizeof(freq_chan[0])) &&
		     i < IW_MAX_FREQUENCIES; i++) {
		range->freq[i].i = i + 1;
		range->freq[i].m = freq_chan[i] * 100000;
		range->freq[i].e = 1;
	}
	range->num_frequency = i;

	range->min_rts = 0;
	range->max_rts = 2347;
	range->min_frag = 256;
	range->max_frag = 2346;

	/* Event capability (kernel + driver) */
	range->event_capa[0] = (IW_EVENT_CAPA_K_0 |
				IW_EVENT_CAPA_MASK(SIOCGIWTHRSPY) |
				IW_EVENT_CAPA_MASK(SIOCGIWAP) |
				IW_EVENT_CAPA_MASK(SIOCGIWSCAN));
	range->event_capa[1] = IW_EVENT_CAPA_K_1;
	range->event_capa[4] = (IW_EVENT_CAPA_MASK(IWEVTXDROP) |
				IW_EVENT_CAPA_MASK(IWEVCUSTOM) |
				IW_EVENT_CAPA_MASK(IWEVREGISTERED) |
				IW_EVENT_CAPA_MASK(IWEVEXPIRED));

	range->enc_capa = 0;

	if (test_bit(DOT11_CIPHER_ALGO_TKIP, &wnd->capa.encr))
		range->enc_capa |= IW_ENC_CAPA_CIPHER_TKIP;
	if (test_bit(DOT11_CIPHER_ALGO_CCMP, &wnd->capa.encr))
		range->enc_capa |= IW_ENC_CAPA_CIPHER_CCMP;

	if (test_bit(DOT11_AUTH_ALGO_WPA, &wnd->capa.auth) ||
	    test_bit(DOT11_AUTH_ALGO_WPA_PSK, &wnd->capa.auth))
		range->enc_capa |= IW_ENC_CAPA_WPA;
	if (test_bit(DOT11_AUTH_ALGO_RSNA, &wnd->capa.auth) ||
	    test_bit(DOT11_AUTH_ALGO_RSNA_PSK, &wnd->capa.auth))
		range->enc_capa |= IW_ENC_CAPA_WPA2;

	return 0;
}

int set_priv_filter(struct ndis_device *wnd, int flags)
{
	EXIT2(return 0);
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

static int iw_get_auth(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct ndis_device *wnd = netdev_priv(dev);

	ENTER2("");

	if (wnd->cipher_info.algo == DOT11_CIPHER_ALGO_NONE)
		wrqu->data.flags |= IW_ENCODE_DISABLED;
	else {
		int mode;
		mode = get_auth_algo(wnd);
		if (mode < 0)
			EXIT2(return -EOPNOTSUPP);
		wrqu->data.flags |= IW_ENCODE_ENABLED;
		if (mode == DOT11_AUTH_ALGO_80211_OPEN)
			wrqu->data.flags |= IW_ENCODE_OPEN;
		else if (mode == DOT11_AUTH_ALGO_80211_SHARED_KEY)
			wrqu->data.flags |= IW_ENCODE_RESTRICTED;
		else // WPA / RSNA etc
			wrqu->data.flags |= IW_ENCODE_RESTRICTED;
	}
	return 0;
}

static int iw_set_auth(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct ndis_device *wnd = netdev_priv(dev);
	int res;

	if (wrqu->data.flags & IW_ENCODE_DISABLED) {
		res = set_cipher_algo(wnd, DOT11_CIPHER_ALGO_NONE);
		if (res)
			return res;
		res = set_auth_algo(wnd, DOT11_AUTH_ALGO_80211_OPEN);
		if (res)
			return res;
	} else if (wrqu->data.flags & IW_ENCODE_OPEN)
		res = set_auth_algo(wnd, DOT11_AUTH_ALGO_80211_OPEN);
	else // if (wrqu->data.flags & IW_ENCODE_RESTRICTED)
		res = set_auth_algo(wnd, DOT11_AUTH_ALGO_80211_SHARED_KEY);
	return 0;
}

static int iw_set_encodeext(struct net_device *dev,
			    struct iw_request_info *info,
			    union iwreq_data *wrqu, char *extra)
{
	return -EOPNOTSUPP;
}

static int iw_get_encodeext(struct net_device *dev,
			    struct iw_request_info *info,
			    union iwreq_data *wrqu, char *extra)
{
	/* TODO */
	ENTER2("");
	return -EOPNOTSUPP;
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
	struct ndis_device *wnd = netdev_priv(dev);
	struct ndis_dot11_reset_request reset_req;
	int res;

	ENTER2("");
	memset(reset_req.mac, 0xff, sizeof(reset_req.mac));
	if (wrqu->param.value == 0)
		res = mp_reset(netdev_priv(dev));
	else if (wrqu->param.value == 1) {
		reset_req.type = ndis_dot11_reset_type_phy;
		reset_req.set_default_mib = TRUE;
		res = mp_request_method(wnd, OID_DOT11_RESET_REQUEST,
					&reset_req, sizeof(reset_req),
					NULL, NULL);
	} else if (wrqu->param.value == 2) {
		reset_req.type = ndis_dot11_reset_type_phy_and_mac;
		reset_req.set_default_mib = TRUE;
		res = mp_request_method(wnd, OID_DOT11_RESET_REQUEST,
					&reset_req, sizeof(reset_req),
					NULL, NULL);
	} else {
		res = mp_set(wnd, OID_DOT11_DISCONNECT_REQUEST, NULL, 0);
	}
	if (res) {
		WARNING("reset failed: %08X", res);
		return -EOPNOTSUPP;
	}
	return 0;
}

static int priv_set_phy_id(struct net_device *dev, struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	struct ndis_device *wnd = netdev_priv(dev);
	ULONG id;
	int res;

	ENTER2("");
	res = mp_query(wnd, OID_DOT11_CURRENT_PHY_ID, &id, sizeof(id));
	TRACE2("%08X, %u", res, id);
	if (res)
		return -EINVAL;
	if (id != wnd->phy_id) {
		WARNING("%u != %u", id, wnd->phy_id);
		wnd->phy_id = id;
	}
	id = wrqu->param.value;
	TRACE2("%d, %d", id, wnd->phy_types->num_entries);
	if (id > wnd->phy_types->num_entries) {
		struct ndis_dot11_phy_id_list phy_id_list;
		memset(&phy_id_list, 0, sizeof(phy_id_list));
		init_ndis_object_header(&phy_id_list, NDIS_OBJECT_TYPE_DEFAULT,
					DOT11_PHY_ID_LIST_REVISION_1);
		phy_id_list.num_entries = 1;
		phy_id_list.num_total_entries = 1;
		phy_id_list.phy_ids[0] = DOT11_PHY_ID_ANY;
		res = mp_set(wnd, OID_DOT11_DESIRED_PHY_LIST,
			     &phy_id_list, sizeof(phy_id_list));
	} else {
		res = mp_set(wnd, OID_DOT11_CURRENT_PHY_ID, &id, sizeof(id));
		if (res == NDIS_STATUS_SUCCESS)
			wnd->phy_id = id;
	}
	if (res)
		return -EINVAL;
	else
		return 0;
}

static int priv_set_nic_power(struct net_device *dev,
			      struct iw_request_info *info,
			      union iwreq_data *wrqu, char *extra)
{
	struct ndis_device *wnd = netdev_priv(dev);
	BOOLEAN state;
	NDIS_STATUS res;

	res = mp_query(wnd, OID_DOT11_HARDWARE_PHY_STATE,
		       &state, sizeof(state));
	TRACE2("%08X, %d", res, state);
	res = mp_query(wnd, OID_DOT11_NIC_POWER_STATE, &state, sizeof(state));
	TRACE2("%08X, %d", res, state);
	if (wrqu->param.value)
		state = TRUE;
	else
		state = FALSE;
	res = mp_set(wnd, OID_DOT11_NIC_POWER_STATE, &state, sizeof(state));
	if (res)
		return -EOPNOTSUPP;
	else
		return 0;
}

static int priv_connect(struct net_device *dev, struct iw_request_info *info,
			union iwreq_data *wrqu, char *extra)
{
	struct ndis_device *wnd = netdev_priv(dev);
	NDIS_STATUS res;

	if (wrqu->param.value) {
		struct ndis_dot11_mac_address_list excl_mac;
		memset(&excl_mac, 0, sizeof(excl_mac));
		init_ndis_object_header(&excl_mac, NDIS_OBJECT_TYPE_DEFAULT,
					DOT11_MAC_ADDRESS_LIST_REVISION_1);
		res = mp_set(wnd, OID_DOT11_EXCLUDED_MAC_ADDRESS_LIST,
			     &excl_mac, sizeof(excl_mac));
		if (res)
			WARNING("excluding mac list failed: %08X", res);
		res = mp_set(wnd, OID_DOT11_CONNECT_REQUEST, NULL, 0);
	} else
		res = mp_set(wnd, OID_DOT11_DISCONNECT_REQUEST, NULL, 0);
	if (res)
		return -EOPNOTSUPP;
	else
		return 0;
}

static int priv_scan(struct net_device *dev, struct iw_request_info *info,
		     union iwreq_data *wrqu, char *extra)
{
	struct ndis_device *wnd = netdev_priv(dev);

	if (set_scan(wnd))
		return -EFAULT;
	return 0;
}

static const struct iw_priv_args priv_args[] = {
	{PRIV_RESET, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0,
	 "reset"},
	{PRIV_SET_PHY_ID, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0,
	 "set_phy_id"},
	{PRIV_SET_NIC_POWER, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0,
	 "nic_power"},
	{PRIV_CONNECT, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0,
	 "connect"},
	{PRIV_SCAN, 0, 0, "scan"},
};

#define WEPRIV(id) [id - SIOCIWFIRSTPRIV]

static const iw_handler priv_handler[] = {
	WEPRIV(PRIV_RESET)		= priv_reset,
	WEPRIV(PRIV_SET_PHY_ID)		= priv_set_phy_id,
	WEPRIV(PRIV_SET_NIC_POWER)	= priv_set_nic_power,
	WEPRIV(PRIV_CONNECT)		= priv_connect,
	WEPRIV(PRIV_SCAN)		= priv_scan,
};

const struct iw_handler_def ndis_handler_def = {
	.num_standard	= sizeof(ndis_handler) / sizeof(ndis_handler[0]),
	.num_private	= sizeof(priv_handler) / sizeof(priv_handler[0]),
	.num_private_args = sizeof(priv_args) / sizeof(priv_args[0]),

	.standard	= (iw_handler *)ndis_handler,
	.private	= (iw_handler *)priv_handler,
	.private_args	= (struct iw_priv_args *)priv_args,
	.get_wireless_stats = get_iw_stats,
};

#endif
