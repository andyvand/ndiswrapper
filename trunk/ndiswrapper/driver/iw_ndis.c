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
#include "wrapper.h"

static int freq_chan[] = { 2412, 2417, 2422, 2427, 2432, 2437, 2442,
			   2447, 2452, 2457, 2462, 2467, 2472, 2484 };


int set_essid(struct ndis_handle *handle, const char *ssid, int ssid_len)
{
	unsigned int res;
	struct ndis_essid req;

	memset(&req, 0, sizeof(req));
	
	if (ssid_len == 0)
		req.length = 0;
	else {
		if (ssid_len > (IW_ESSID_MAX_SIZE + 1))
			return -EINVAL;

		req.length = ssid_len;
		memcpy(&req.essid, ssid, req.length);
		req.essid[req.length] = 0;
		DBGTRACE("ssid = '%s'", req.essid);
	}
	
	res = miniport_set_info(handle, NDIS_OID_ESSID, (char*)&req,
				sizeof(req));
	if (res)
		WARNING("setting essid failed (%08X)", res); 

	memcpy(&handle->essid, &req, sizeof(req));
	TRACEEXIT1(return 0);
}

static int iw_set_essid(struct net_device *dev, struct iw_request_info *info,
			union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv;
	char ssid[IW_ESSID_MAX_SIZE];

	memset(ssid, 0, sizeof(ssid));
	/* iwconfig adds 1 to the actual length */
	if (wrqu->essid.flags)
		wrqu->essid.length--;

	if (wrqu->essid.length > IW_ESSID_MAX_SIZE)
		TRACEEXIT1(return -EINVAL);

	memcpy(ssid, extra, wrqu->essid.length);
	if (set_essid(handle, ssid, wrqu->essid.length))
		TRACEEXIT1(return -EINVAL);

	TRACEEXIT1(return 0);
}

static int iw_get_essid(struct net_device *dev, struct iw_request_info *info,
			union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv; 
	unsigned int res;
	struct ndis_essid req;

	TRACEENTER1("%s", "");
	memset(&req, 0, sizeof(req));
	res = miniport_query_info(handle, NDIS_OID_ESSID, (char*)&req,
				  sizeof(req));
	if (res)
		WARNING("getting essid failed (%08X)", res);

	memcpy(extra, req.essid, req.length);
	extra[req.length] = 0;
	if (req.length > 0)
		wrqu->essid.flags  = 1;
	else
		wrqu->essid.flags = 0;
	wrqu->essid.length = req.length;
	TRACEEXIT1(return 0);
}

int set_mode(struct ndis_handle *handle, enum op_mode mode)
{
	unsigned int res, i;

	TRACEENTER1("%s", "");

	res = miniport_set_int(handle, NDIS_OID_MODE, mode);
	if (res == NDIS_STATUS_INVALID_DATA) {
		WARNING("setting operating mode failed (%08X)", res); 
		TRACEEXIT1(return -EINVAL);
	}

	for (i = 0; i < MAX_ENCR_KEYS; i++)
		handle->encr_info.keys[i].length = 0;
	handle->op_mode = mode;
	TRACEEXIT1(return 0);
}

static int iw_set_mode(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv;
	enum op_mode ndis_mode;

	TRACEENTER1("%s", "");
	switch (wrqu->mode) {
	case IW_MODE_ADHOC:
		ndis_mode = NDIS_MODE_ADHOC;
		break;	
	case IW_MODE_INFRA:
		ndis_mode = NDIS_MODE_INFRA;
		break;	
	case IW_MODE_AUTO:
		ndis_mode = NDIS_MODE_AUTO;
		break;	
	default:
		TRACEEXIT1(return -EINVAL);
	}
	
	if (set_mode(handle, ndis_mode))
		TRACEEXIT1(return -EINVAL);

	TRACEEXIT1(return 0);
}

static int iw_get_mode(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv; 
	int ndis_mode, iw_mode;

	int res;

	TRACEENTER1("%s", "");
	res = miniport_query_int(handle, NDIS_OID_MODE, &ndis_mode);
	if (res) {
		WARNING("getting operating mode failed (%08X)", res);
		TRACEEXIT1(return -EOPNOTSUPP);
	}

	switch(ndis_mode) {
	case NDIS_MODE_ADHOC:
		iw_mode = IW_MODE_ADHOC;
		break;
	case NDIS_MODE_INFRA:
		iw_mode = IW_MODE_INFRA;
		break;
	case NDIS_MODE_AUTO:
		iw_mode = IW_MODE_AUTO;
		break;
	default:
		ERROR("invalid operating mode (%u)", ndis_mode);
		TRACEEXIT1(return -EINVAL);
	}
	wrqu->mode = iw_mode;
	TRACEEXIT1(return 0);
}

static const char *net_type_to_name(int net_type)
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

static int iw_get_name(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv;
	unsigned int network_type, res;
	
	res = miniport_query_int(handle, NDIS_OID_NETWORK_TYPE_IN_USE,
				 &network_type);
	if (res == NDIS_STATUS_INVALID_DATA)
		network_type = -1;

	strncpy(wrqu->name, net_type_to_name(network_type),
	        sizeof(wrqu->name) - 1);
	wrqu->name[sizeof(wrqu->name)-1] = 0;
	return 0;
}

static int iw_get_freq(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv;
	unsigned int res;
	struct ndis_configuration req;

	memset(&req, 0, sizeof(req));
	res = miniport_query_info(handle, NDIS_OID_CONFIGURATION, (char*)&req,
				  sizeof(req));
	if (res == NDIS_STATUS_INVALID_DATA) {
		WARNING("getting configuration failed (%08X)", res);
		TRACEEXIT(return -EOPNOTSUPP);
	}

	memset(&(wrqu->freq), 0, sizeof(struct iw_freq));

	/* see comment in wireless.h above the "struct iw_freq"
	   definition for an explanation of this if
	   NOTE: 1000000 is due to the kHz
	*/
	if (req.ds_config > 1000000) {
		wrqu->freq.m = req.ds_config / 10;
		wrqu->freq.e = 1;
	}
	else
		wrqu->freq.m = req.ds_config;

	/* convert from kHz to Hz */
	wrqu->freq.e += 3;

	return 0;
}

static int iw_set_freq(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv;
	unsigned int res;
	struct ndis_configuration req;

	memset(&req, 0, sizeof(req));
	res = miniport_query_info(handle, NDIS_OID_CONFIGURATION, (char*)&req,
				  sizeof(req));
	if (res == NDIS_STATUS_INVALID_DATA) {
		WARNING("getting configuration failed (%08X)", res);
		TRACEEXIT(return -EOPNOTSUPP);
	}

	if (wrqu->freq.m < 1000 && wrqu->freq.e == 0) {
		if (wrqu->freq.m >= 1 &&
		    wrqu->freq.m <= (sizeof(freq_chan)/sizeof(freq_chan[0])))
			req.ds_config = freq_chan[wrqu->freq.m - 1] * 1000;
		else
			return -EINVAL;
	} else {
		int i;
		for (req.ds_config = wrqu->freq.m, i = wrqu->freq.e ;
		     i > 0 ; i--)
			req.ds_config *= 10;
		req.ds_config /= 1000;
		
	}
	res = miniport_set_info(handle, NDIS_OID_CONFIGURATION, (char*)&req,
				sizeof(req));
	if (res == NDIS_STATUS_INVALID_DATA) {
		WARNING("setting configuration failed (%08X)", res);
		return -EINVAL;
	}
	return 0;
}

static int iw_get_tx_power(struct net_device *dev,
			   struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv; 
	unsigned long ndis_power;
	unsigned int res;

	res = miniport_query_info(handle, NDIS_OID_TX_POWER_LEVEL,
				  (char*)&ndis_power,
				  sizeof(ndis_power));
	/* Centrino driver returns NDIS_STATUS_INVALID_OID (why?) */
	if (res == NDIS_STATUS_NOT_SUPPORTED || res == NDIS_STATUS_INVALID_OID)
		return -EOPNOTSUPP;

	wrqu->txpower.flags = IW_TXPOW_MWATT;
	wrqu->txpower.disabled = 0;
	wrqu->txpower.fixed = 0;
	wrqu->txpower.value = ndis_power;
	return 0;
}

static int iw_set_tx_power(struct net_device *dev,
			   struct iw_request_info *info,
			   union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv; 
	unsigned long ndis_power;
	unsigned int res;

	if (wrqu->txpower.disabled) {
		ndis_power = 0;
		res = miniport_set_info(handle, NDIS_OID_TX_POWER_LEVEL,
					(char *)&ndis_power,
					sizeof(ndis_power));
		if (res == NDIS_STATUS_INVALID_DATA)
			return -EINVAL;
		res = miniport_set_int(handle, NDIS_OID_DISASSOCIATE, 0);
		if (res)
			return -EINVAL;
		return 0;
	} else {
		if (wrqu->txpower.flags == IW_TXPOW_MWATT)
			ndis_power = wrqu->txpower.value;
		else { // wrqu->txpower.flags == IW_TXPOW_DBM
			if (wrqu->txpower.value > 20)
				ndis_power = 128;
			else if (wrqu->txpower.value < -43)
				ndis_power = 127;
			else {
				signed char tmp;
				tmp = wrqu->txpower.value;
				tmp = -12 - tmp;
				tmp <<= 2;
				ndis_power = (unsigned char)tmp;
			}
		}
	}
	res = miniport_set_info(handle, NDIS_OID_TX_POWER_LEVEL,
				(char*)&ndis_power, sizeof(ndis_power));
	if (res)
		WARNING("setting tx_power failed (%08X)", res);
	if (res == NDIS_STATUS_NOT_SUPPORTED)
		return -EOPNOTSUPP;
	if (res == NDIS_STATUS_INVALID_DATA)
		return -EINVAL;

	return 0;
}

static int iw_get_bitrate(struct net_device *dev, struct iw_request_info *info,
			  union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv; 
	int ndis_rate;

	int res = miniport_query_int(handle, NDIS_OID_GEN_SPEED, &ndis_rate);
	if (res)
		WARNING("getting bitrate failed (%08X)", res);

	wrqu->bitrate.value = ndis_rate * 100;
	return 0;
}

static int iw_set_bitrate(struct net_device *dev, struct iw_request_info *info,
			  union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv; 
	int i, res;
	char rates[NDIS_MAX_RATES_EX];

	if (wrqu->bitrate.fixed == 0)
		TRACEEXIT1(return 0);

	res = miniport_query_info(handle, NDIS_OID_SUPPORTED_RATES,
				  (char *)&rates, sizeof(rates));
	if (res == NDIS_STATUS_NOT_SUPPORTED)
		TRACEEXIT1(return -EOPNOTSUPP);
	if (res == NDIS_STATUS_INVALID_DATA)
		TRACEEXIT1(return -EINVAL);
		
	for (i = 0 ; i < NDIS_MAX_RATES_EX ; i++) {
		if (rates[i] & 0x80)
			continue;
		if ((rates[i] & 0x7f) * 500000 > wrqu->bitrate.value) {
			DBGTRACE1("setting rate %d to 0",
				  (rates[i] & 0x7f) * 500000);
			rates[i] = 0;
		}
	}

	res = miniport_query_info(handle, NDIS_OID_DESIRED_RATES,
				  (char *)&rates, sizeof(rates));
	if (res == NDIS_STATUS_NOT_SUPPORTED)
		TRACEEXIT1(return -EOPNOTSUPP);
	if (res == NDIS_STATUS_INVALID_DATA)
		TRACEEXIT1(return -EINVAL);

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
	struct ndis_handle *handle = dev->priv;
	int ndis_rts_threshold;

	int res = miniport_query_int(handle, NDIS_OID_RTS_THRESH,
				     &ndis_rts_threshold);
	if (res == NDIS_STATUS_NOT_SUPPORTED)
		return -EOPNOTSUPP;

	wrqu->rts.value = ndis_rts_threshold;
	return 0;
}

static int iw_get_frag_threshold(struct net_device *dev,
				 struct iw_request_info *info,
				 union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv; 
	int ndis_frag_threshold;

	int res = miniport_query_int(handle, NDIS_OID_FRAG_THRESH,
				     &ndis_frag_threshold);
	if (res == NDIS_STATUS_NOT_SUPPORTED)
		return -EOPNOTSUPP;

	wrqu->frag.value = ndis_frag_threshold;
	return 0;
}

int get_ap_address(struct ndis_handle *handle, mac_address ap_addr)
{
	unsigned int res;

	TRACEENTER1("%s", "");

	res = miniport_query_info(handle, NDIS_OID_BSSID, ap_addr, ETH_ALEN);
	if (res == NDIS_STATUS_ADAPTER_NOT_READY)
		memset(ap_addr, 0, ETH_ALEN);

	DBGTRACE1(MACSTR, MAC2STR(ap_addr));
        TRACEEXIT1(return 0);
}

static int iw_get_ap_address(struct net_device *dev,
			     struct iw_request_info *info,
			     union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv;
	mac_address ap_addr;

	TRACEENTER1("%s", "");
	get_ap_address(handle, ap_addr);

	memcpy(wrqu->ap_addr.sa_data, ap_addr, ETH_ALEN);
	wrqu->ap_addr.sa_family = ARPHRD_ETHER;
	TRACEEXIT1(return 0);
}

static int iw_set_ap_address(struct net_device *dev,
			     struct iw_request_info *info,
			     union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv; 
	unsigned int res;
	mac_address ap_addr;

        memcpy(ap_addr, wrqu->ap_addr.sa_data, ETH_ALEN);
	DBGTRACE1(MACSTR, MAC2STR(ap_addr));
	res = miniport_set_info(handle, NDIS_OID_BSSID, (char*)&(ap_addr[0]),
				ETH_ALEN);

	if (res) {
		WARNING("setting AP mac address failed (%08X)", res);
		TRACEEXIT1(return -EINVAL);
	}

        TRACEEXIT1(return 0);
}

int set_auth_mode(struct ndis_handle *handle, int auth_mode)
{
	unsigned int res;
	res = miniport_set_int(handle, NDIS_OID_AUTH_MODE, auth_mode);
	if (res == NDIS_STATUS_INVALID_DATA) {
		WARNING("setting auth mode failed (%08X)", res);
		TRACEEXIT2(return -EINVAL);
	} else {
		handle->auth_mode = auth_mode;
		TRACEEXIT2(return 0);
	}
}

int set_encr_mode(struct ndis_handle *handle, int encr_mode)
{
	unsigned int res;
	res = miniport_set_int(handle, NDIS_OID_ENCR_STATUS, encr_mode);
	if (res == NDIS_STATUS_INVALID_DATA)
		TRACEEXIT2(return -EINVAL);
	else {
		handle->encr_mode = encr_mode;
		TRACEEXIT2(return 0);
	}
}

static int iw_get_encr(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv;
	int status, res, index;
	struct encr_info *encr_info = &handle->encr_info;

	TRACEENTER2("handle = %p", handle);
	wrqu->data.length = 0;
	extra[0] = 0;

	index = (wrqu->encoding.flags & IW_ENCODE_INDEX);
	DBGTRACE2("index = %u", index);
	if (index > 0)
		index--;
	else
		index = encr_info->active;

	if (index < 0 || index >= MAX_ENCR_KEYS) {
		WARNING("encryption index out of range (%u)", index);
		TRACEEXIT1(return -EINVAL);
	}

	if (index != encr_info->active) {
		if (encr_info->keys[index].length > 0) {
			wrqu->data.flags |= IW_ENCODE_ENABLED;
			wrqu->data.length = encr_info->keys[index].length;
			memcpy(extra, encr_info->keys[index].key,
			       encr_info->keys[index].length);
		}
		else
			wrqu->data.flags |= IW_ENCODE_DISABLED;

		TRACEEXIT1(return 0);
	}
	
	/* active key */
	res = miniport_query_int(handle, NDIS_OID_ENCR_STATUS, &status);
	if (res == NDIS_STATUS_NOT_SUPPORTED) {
		WARNING("getting encryption status failed (%08X)", res);
		TRACEEXIT1(return -EOPNOTSUPP);
	}

	if (status == ENCR_DISABLED || status == ENCR1_NO_SUPPORT)
		wrqu->data.flags |= IW_ENCODE_DISABLED;
	else {
		if (status == ENCR1_NOKEY || status == ENCR2_ABSENT ||
		    status == ENCR3_ABSENT)
			wrqu->data.flags |= IW_ENCODE_NOKEY;
		else {
			wrqu->data.flags |= IW_ENCODE_ENABLED;
			wrqu->encoding.flags |= index+1;
			wrqu->data.length = encr_info->keys[index].length;
			memcpy(extra, encr_info->keys[index].key,
			       encr_info->keys[index].length);
		}
	}
	res = miniport_query_int(handle, NDIS_OID_AUTH_MODE, &status);
	if (res == NDIS_STATUS_NOT_SUPPORTED) {
		WARNING("getting authentication mode failed (%08X)", res);
		TRACEEXIT1(return -EOPNOTSUPP);
	}

	if (status == AUTHMODE_OPEN)
		wrqu->data.flags |= IW_ENCODE_OPEN;
	else if (status == AUTHMODE_RESTRICTED)
		wrqu->data.flags |= IW_ENCODE_RESTRICTED;
	else if (status == AUTHMODE_AUTO)
		wrqu->data.flags |= IW_ENCODE_RESTRICTED;
	
	TRACEEXIT1(return 0);
}

/* index must be 0 - N, as per NDIS  */
int add_wep_key(struct ndis_handle *handle, char *key, int key_len,
		int index)
{
	struct ndis_encr_key ndis_key;
	unsigned int res;

	TRACEENTER2("handle = %p", handle);
	if (key_len <= 0 || key_len > NDIS_ENCODING_TOKEN_MAX) {
		WARNING("invalid key length (%d)", key_len);
		TRACEEXIT(return -EINVAL);
	}
	ndis_key.struct_size = sizeof(ndis_key);
	ndis_key.length = key_len;
	memcpy(&ndis_key.key, key, key_len);
	/* active/transmit key works only if index is 0 */
	if (index == handle->encr_info.active)
		ndis_key.index = 0 | (1 << 31);
	else
		ndis_key.index = index;

	res = miniport_set_info(handle, NDIS_OID_ADD_WEP, (char *)&ndis_key,
				sizeof(ndis_key));
	if (res == NDIS_STATUS_INVALID_DATA) {
		WARNING("adding encryption key %d failed (%08X)",
			index+1, res);
		TRACEEXIT1(return -EINVAL);
	}
		
	/* Atheros driver messes up ndis_key during ADD_WEP, so
	 * don't rely on that; instead use info in key and key_len */
	handle->encr_info.keys[index].length = key_len;
	memcpy(&handle->encr_info.keys[index].key, key, key_len);

	/* active/transmit key is always stored at index 0 */
	if (index == handle->encr_info.active) {
		handle->encr_info.keys[0].length = key_len;
		memcpy(&handle->encr_info.keys[0].key, key, key_len);
		res = set_encr_mode(handle, ENCR1_ENABLED);
		if (res)
			WARNING("changing encr status failed (%08X)", res);
	}
	TRACEEXIT1(return 0);
}

static int iw_set_encr(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv;
	unsigned int res, index;
	struct encr_info *encr_info = &handle->encr_info;
	unsigned char *key;
	int key_len;
	
	TRACEENTER1("%s", "");
	index = (wrqu->encoding.flags & IW_ENCODE_INDEX);
	DBGTRACE2("index = %u", index);

	/* iwconfig gives index as 1 - N */
	if (index > 0)
		index--;
	else
		index = encr_info->active;

	if (index < 0 || index >= MAX_ENCR_KEYS) {
		WARNING("encryption index out of range (%u)", index);
		TRACEEXIT1(return -EINVAL);
	}

	/* remove key if disabled */
	if (wrqu->data.flags & IW_ENCODE_DISABLED) {
		unsigned long keyindex = index;
		res = miniport_set_info(handle, NDIS_OID_REMOVE_WEP,
					(char *)&keyindex, sizeof(keyindex));
		if (res == NDIS_STATUS_INVALID_DATA) {
			WARNING("removing encryption key %d failed (%08X)",
				index, res);
			TRACEEXIT1(return -EINVAL);
		}
		encr_info->keys[index].length = 0;
		
		/* if it is active key, disable encryption */
		if (index == encr_info->active) {
			res = set_encr_mode(handle, ENCR_DISABLED);
			if (res)
				WARNING("changing encr status failed (%08X)",
					res);
		}
		TRACEEXIT1(return 0);
	}

	/* global encryption state (for all keys) */
	if (wrqu->data.flags & IW_ENCODE_OPEN)
		res = set_auth_mode(handle, AUTHMODE_OPEN);
	else // if (wrqu->data.flags & IW_ENCODE_RESTRICTED)
		res = set_auth_mode(handle, AUTHMODE_RESTRICTED);
	if (res) {
		WARNING("setting authentication mode failed (%08X)", res);
		TRACEEXIT1(return -EINVAL);
	}

	if (wrqu->data.length > 0) {
		key_len = wrqu->data.length;
		key = extra;
	} else { // must be set as tx key
		if (encr_info->keys[index].length == 0) {
			WARNING("key %d is not set", index+1);
			TRACEEXIT1(return -EINVAL);
		}
		key_len = encr_info->keys[index].length;
		key = encr_info->keys[index].key;
		encr_info->active = index;
	}

	if (add_wep_key(handle, key, key_len, index))
		TRACEEXIT(return -EINVAL);

	if (index == encr_info->active) {
		/* ndis drivers want essid to be set after setting encr */
		set_essid(handle, handle->essid.essid, handle->essid.length);
	}
	TRACEEXIT1(return 0);
}
	
static int iw_set_nick(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv;
	
	if (wrqu->data.length > IW_ESSID_MAX_SIZE)
		return -EINVAL;
	memcpy(handle->nick, extra, wrqu->data.length);
	handle->nick[IW_ESSID_MAX_SIZE] = 0;
	return 0;
}

static int iw_get_nick(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv;
	
	memcpy(extra, handle->nick, IW_ESSID_MAX_SIZE+1);
	wrqu->data.length = strlen(handle->nick);
	return 0;
}

static char *ndis_translate_scan(struct net_device *dev, char *event,
				 char *end_buf, struct ndis_ssid_item *item)
{
	struct iw_event iwe;
	char *current_val;
	int i, nrates;
	unsigned char buf[MAX_WPA_IE_LEN * 2 + 30];

	TRACEENTER1("%s", "");
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
	iwe.u.data.length = item->ssid.length;
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
	if (item->config.ds_config > 1000000) {
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
	if (item->length > sizeof(struct ndis_ssid_item))
		nrates = NDIS_MAX_RATES_EX;
	else
		nrates = NDIS_MAX_RATES;
	for (i = 0 ; i < nrates ; i++) {
		if (item->rates[i] & 0x7f) {
			iwe.u.bitrate.value = ((item->rates[i] & 0x7f) *
					       500000);
			current_val = iwe_stream_add_value(event, current_val,
							   end_buf, &iwe,
							   IW_EV_PARAM_LEN);
		}
	}

	if ((current_val - event) > IW_EV_LCP_LEN)
		event = current_val;

	memset(&iwe, 0, sizeof(iwe));
	iwe.cmd = IWEVCUSTOM;
	sprintf(buf, "bcn_int=%d", item->config.beacon_period);
	iwe.u.data.length = strlen(buf);
	event = iwe_stream_add_point(event, end_buf, &iwe, buf);
	
	DBGTRACE2("%s: adding atim", __FUNCTION__);
	memset(&iwe, 0, sizeof(iwe));
	iwe.cmd = IWEVCUSTOM;
	sprintf(buf, "atim=%u", item->config.atim_window);
	iwe.u.data.length = strlen(buf);
	event = iwe_stream_add_point(event, end_buf, &iwe, buf);

	if (item->length > sizeof(*item)) {
		unsigned char *iep = (unsigned char *)item->ies +
			sizeof(struct ndis_fixed_ies);
		unsigned char *end = iep + item->ie_length;

		while (iep + 1 < end && iep + 2 + iep[1] <= end) {
			unsigned char ielen = 2 + iep[1];

			if (ielen > SSID_MAX_WPA_IE_LEN) {
				iep += ielen;
				continue;
			}

			if (iep[0] == WLAN_EID_GENERIC && iep[1] >= 4 &&
			    memcmp(iep + 2, "\x00\x50\xf2\x01", 4) == 0) {
				unsigned char *p = buf;

				p += sprintf(p, "wpa_ie=");
				for (i = 0; i < ielen; i++)
					p += sprintf(p, "%02x", iep[i]);
				
				DBGTRACE2("adding wpa_ie :%d", strlen(buf));
				memset(&iwe, 0, sizeof(iwe));
				iwe.cmd = IWEVCUSTOM;
				iwe.u.data.length = strlen(buf);
				event = iwe_stream_add_point(event, end_buf,
							     &iwe, buf);
			} else if (iep[0] == WLAN_EID_RSN) {
				unsigned char *p = buf;
				for (i = 0; i < ielen; i++)
					p += sprintf(p, "%02x", iep[i]);

				DBGTRACE2("adding rsn_ie :%d\n", strlen(buf));
				memset(&iwe, 0, sizeof(iwe));
				iwe.cmd = IWEVCUSTOM;
				iwe.u.data.length = strlen(buf);
				event = iwe_stream_add_point(event, end_buf,
							     &iwe, buf);
			}

			iep += ielen;
		}
	}

	DBGTRACE2("event = %p, current_val = %p", event, current_val);

	TRACEEXIT1(return event);
}

static int iw_set_scan(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv;
	unsigned int res = 0;

	TRACEENTER1("%s", "");
	res = miniport_set_int(handle, NDIS_OID_BSSID_LIST_SCAN, 0);
	if (res == NDIS_STATUS_NOT_SUPPORTED ||
	    res == NDIS_STATUS_INVALID_DATA) {
		WARNING("scanning failed (%08X)", res);
		handle->scan_timestamp = 0;
		TRACEEXIT1(return -EOPNOTSUPP);
	} else {
		handle->scan_timestamp = jiffies;
		TRACEEXIT1(return 0);
	}
}

static int iw_get_scan(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
 	struct ndis_handle *handle = dev->priv;
	unsigned int i, res, list_len, needed;
	struct ndis_bssid_list *bssid_list;
	char *event = extra;
	struct ndis_ssid_item *cur_item ;

	TRACEENTER1("%s", "");
	if (!handle->scan_timestamp)
		TRACEEXIT1(return -EOPNOTSUPP);

	if (time_before(jiffies, handle->scan_timestamp + 3 * HZ))
		return -EAGAIN;
	
	/* Try with space for 15 scan items */
	list_len = sizeof(unsigned long) + sizeof(struct ndis_ssid_item) * 15;
	bssid_list = kmalloc(list_len, GFP_KERNEL);

	res = miniport_query_info_needed(handle, NDIS_OID_BSSID_LIST,
					 (char *)bssid_list, list_len,
					 &needed);
	if (res == NDIS_STATUS_INVALID_LENGTH) {
		/* 15 items not enough; allocate required space */
		kfree(bssid_list);
		list_len = needed;
		bssid_list = kmalloc(list_len, GFP_KERNEL);
	
		res = miniport_query_info(handle, NDIS_OID_BSSID_LIST,
					  (char*)bssid_list, list_len);
	}

	if (res == NDIS_STATUS_INVALID_DATA) {
		WARNING("getting BSSID list failed (%08X)", res);
		kfree(bssid_list);
		TRACEEXIT1(return -EOPNOTSUPP);
	}

	for (i = 0, cur_item = &bssid_list->items[0] ;
	     i < bssid_list->num_items ; i++) {
		event = ndis_translate_scan(dev, event,
					    extra + IW_SCAN_MAX_DATA,
					    cur_item);
		cur_item = (struct ndis_ssid_item *)((char *)cur_item +
						cur_item->length);
	}
	wrqu->data.length = event - extra;
	wrqu->data.flags = 0;

	kfree(bssid_list);
	TRACEEXIT1(return 0);
}

static int iw_set_power_mode(struct net_device *dev,
			     struct iw_request_info *info,
			     union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv;
	int res, power_mode;

	if (wrqu->power.disabled == 1)
		power_mode = NDIS_POWER_OFF;
	else if (wrqu->power.flags & IW_POWER_MIN)
		power_mode = NDIS_POWER_MIN;
	else // if (wrqu->power.flags & IW_POWER_MAX)
		power_mode = NDIS_POWER_MAX;

	res = miniport_set_int(handle, NDIS_OID_POWER_MODE, power_mode);
	if (res == NDIS_STATUS_INVALID_DATA) {
		WARNING("setting power mode failed (%08X)", res);
		return -EINVAL;
	}

	return 0;
}

static int iw_get_power_mode(struct net_device *dev,
			     struct iw_request_info *info,
			     union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv;
	int res, power_mode;

	res = miniport_query_int(handle, NDIS_OID_POWER_MODE, &power_mode);
	if (res == NDIS_STATUS_NOT_SUPPORTED)
		return -EOPNOTSUPP;

	if (power_mode == NDIS_POWER_OFF)
		wrqu->power.disabled = 1;
	else {
		if (wrqu->power.flags != 0)
			return 0;
		wrqu->power.flags |= IW_POWER_ALL_R;
		wrqu->power.flags |= IW_POWER_TIMEOUT;
		wrqu->power.value = 0;
		wrqu->power.disabled = 0;

		if (power_mode == NDIS_POWER_MIN)
			wrqu->power.flags |= IW_POWER_MIN;
		else // if (power_mode == NDIS_POWER_MAX)
			wrqu->power.flags |= IW_POWER_MAX;
	}
	return 0;
}

static int iw_get_sensitivity(struct net_device *dev,
			      struct iw_request_info *info,
			      union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv;
	unsigned int res;
	unsigned long rssi_trigger;

	res = miniport_query_info(handle, NDIS_OID_RSSI_TRIGGER,
				  (char *)&rssi_trigger, sizeof(rssi_trigger));
	if (res)
		return -EOPNOTSUPP;
	wrqu->param.value = rssi_trigger;
	wrqu->param.disabled = (rssi_trigger == 0);
	wrqu->param.fixed = 1;
	return 0;
}

static int iw_set_sensitivity(struct net_device *dev,
			      struct iw_request_info *info,
			      union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv;
	unsigned int res;
	unsigned long rssi_trigger;

	if (wrqu->param.disabled)
		rssi_trigger = 0;
	else
		rssi_trigger = wrqu->param.value;
	res = miniport_set_info(handle, NDIS_OID_RSSI_TRIGGER,
				(char *)&rssi_trigger, sizeof(rssi_trigger));
	if (res)
		return -EINVAL;
	return 0;
}

static int iw_get_ndis_stats(struct net_device *dev,
			     struct iw_request_info *info,
			     union iwreq_data *wrqu, char *extra)

{
	struct ndis_handle *handle = dev->priv;
	struct iw_statistics *stats = &handle->wireless_stats;
	memcpy(&wrqu->qual, &stats->qual, sizeof(stats->qual));
	return 0;
}

static int iw_get_range(struct net_device *dev, struct iw_request_info *info,
			union iwreq_data *wrqu, char *extra)
{
	struct iw_range *range = (struct iw_range *)extra;
	struct iw_point *data = &wrqu->data;
	struct ndis_handle *handle = (struct ndis_handle *)dev->priv;
	unsigned int i, res;
	unsigned char rates[NDIS_MAX_RATES_EX];
	unsigned long tx_power;

	data->length = sizeof(struct iw_range);
	memset(range, 0, sizeof(struct iw_range));
	
	range->txpower_capa = IW_TXPOW_MWATT;
	range->num_txpower = 0;

	res = miniport_query_info(handle, NDIS_OID_TX_POWER_LEVEL,
				 (char*)&tx_power, sizeof(tx_power));
	if (!res) {
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
	res = miniport_query_info(handle, NDIS_OID_SUPPORTED_RATES,
				  (char *)&rates, sizeof(rates));
	if (res)
		WARNING("getting bit rates failed: %08X", res);
	else {
		for (i = 0 ; i < NDIS_MAX_RATES_EX &&
			     range->num_bitrates < IW_MAX_BITRATES ; i++)
			if (rates[i] & 0x80)
				continue;
			else if (rates[i] & 0x7f) {
				range->bitrate[range->num_bitrates] =
					(rates[i] & 0x7f) * 500000;
				range->num_bitrates++;
			}
	}

	range->num_channels = (sizeof(freq_chan)/sizeof(freq_chan[0]));

	for (i = 0; i < (sizeof(freq_chan)/sizeof(freq_chan[0])) &&
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

	return 0;
}

static const iw_handler	ndis_handler[] = {
	[SIOCGIWNAME	- SIOCIWFIRST] = iw_get_name,
	[SIOCSIWESSID	- SIOCIWFIRST] = iw_set_essid,
	[SIOCGIWESSID	- SIOCIWFIRST] = iw_get_essid,
	[SIOCSIWMODE	- SIOCIWFIRST] = iw_set_mode,
	[SIOCGIWMODE	- SIOCIWFIRST] = iw_get_mode,
	[SIOCGIWFREQ	- SIOCIWFIRST] = iw_get_freq,
	[SIOCSIWFREQ	- SIOCIWFIRST] = iw_set_freq,
	[SIOCGIWTXPOW	- SIOCIWFIRST] = iw_get_tx_power,
	[SIOCSIWTXPOW	- SIOCIWFIRST] = iw_set_tx_power,
	[SIOCGIWRATE	- SIOCIWFIRST] = iw_get_bitrate,
	[SIOCSIWRATE	- SIOCIWFIRST] = iw_set_bitrate,
	[SIOCGIWRTS	- SIOCIWFIRST] = iw_get_rts_threshold,
	[SIOCGIWFRAG	- SIOCIWFIRST] = iw_get_frag_threshold,
	[SIOCGIWAP	- SIOCIWFIRST] = iw_get_ap_address,
	[SIOCSIWAP	- SIOCIWFIRST] = iw_set_ap_address,
	[SIOCSIWENCODE	- SIOCIWFIRST] = iw_set_encr,
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
};

/* private ioctl's */

static int priv_reset(struct net_device *dev, struct iw_request_info *info,
		      union iwreq_data *wrqu, char *extra)
{
	int res;
	res = miniport_reset(dev->priv);
	if (res) {
		WARNING("reset returns %08X", res);
		return -EOPNOTSUPP;
	}
	return 0;
}

static int priv_power_profile(struct net_device *dev,
			      struct iw_request_info *info,
			      union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = dev->priv;
	struct miniport_char *miniport = &handle->driver->miniport_char;
	unsigned long profile_inf;

	miniport = &handle->driver->miniport_char;
	if (!miniport->pnp_event_notify)
		TRACEEXIT(return -EOPNOTSUPP);

	/* 1 for AC and 0 for Battery */
	if (wrqu->param.value)
		profile_inf = NDIS_POWER_PROFILE_AC;
	else
		profile_inf = NDIS_POWER_PROFILE_BATTERY;
	
	miniport->pnp_event_notify(handle->adapter_ctx,
				   NDIS_PNP_PROFILE_CHANGED,
				   &profile_inf, sizeof(profile_inf));
	TRACEEXIT(return 0);
}

/* WPA support */

static int wpa_set_wpa(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = (struct ndis_handle *)dev->priv;
	
	TRACEENTER("%s", "");
	DBGTRACE("flags = %d,  handle->capa = %ld",
		 wrqu->data.flags, handle->capa);
	
	if (set_mode(handle, NDIS_MODE_INFRA))
		TRACEEXIT(return -1);

	if (test_bit(CAPA_WPA, &handle->capa))
		TRACEEXIT(return 0);
	else {
		WARNING("%s", "driver is not WPA capable");
		TRACEEXIT(return -1);
	}
}

static int wpa_set_key(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = (struct ndis_handle *)dev->priv;
	struct ndis_wpa_key ndis_key;
	struct wpa_key wpa_key;
	int i, res;
	u8 addr[ETH_ALEN];
	u8 seq[IW_ENCODING_TOKEN_MAX];
	u8 key[IW_ENCODING_TOKEN_MAX];

	if (copy_from_user(&wpa_key, wrqu->data.pointer, sizeof(wpa_key)))
		TRACEEXIT1(return -1);
	if (wpa_key.addr && copy_from_user(&addr, wpa_key.addr, ETH_ALEN))
		TRACEEXIT1(return -1);

	if (wpa_key.seq &&
	    copy_from_user(&seq, wpa_key.seq, IW_ENCODING_TOKEN_MAX))
		TRACEEXIT1(return -1);

	if (wpa_key.key &&
	    copy_from_user(&key, wpa_key.key, IW_ENCODING_TOKEN_MAX))
		TRACEEXIT1(return -1);
	
	TRACEENTER2("alg = %d, key_index = %d",
		    wpa_key.alg, wpa_key.key_index);
	
	if (wpa_key.alg == WPA_ALG_WEP) {
		if (test_bit(CAPA_ENCR_NONE, &handle->capa))
			TRACEEXIT2(return -1);

		if (wpa_key.set_tx)
			handle->encr_info.active = wpa_key.key_index;

		if (add_wep_key(handle, key, wpa_key.key_len,
				wpa_key.key_index))
			TRACEEXIT(return -1);
		else
			TRACEEXIT(return 0);
	}

	/* alg is either WPA_ALG_TKIP or WPA_ALG_CCMP */
	if (!test_bit(CAPA_WPA, &handle->capa))
		TRACEEXIT2(return -1);

	if (wpa_key.key_len > sizeof(ndis_key.key)) {
		DBGTRACE2("incorrect key length (%d)", wpa_key.key_len);
		TRACEEXIT2(return -1);
	}
	
	if (wpa_key.seq_len > IW_ENCODING_TOKEN_MAX) {
		DBGTRACE2("incorrect seq? length = (%d)", wpa_key.seq_len);
		TRACEEXIT2(return -1);
	}

	DBGTRACE2("setting key %d, %d", wpa_key.key_index, wpa_key.key_len);
	memset(&ndis_key, 0, sizeof(ndis_key));

	ndis_key.struct_size = sizeof(ndis_key);
	ndis_key.length = wpa_key.key_len;
	ndis_key.index = wpa_key.key_index;

	if (wpa_key.seq && wpa_key.seq_len > 0) {
		for (i = 0, ndis_key.rsc = 0 ; i < wpa_key.seq_len ; i++)
			ndis_key.rsc |= (seq[i] << (i * 8));

		ndis_key.index |= 1 << 29;
	}

	if (wpa_key.addr == NULL || memcmp(addr, "\xff\xff\xff\xff\xff\xff",
				   ETH_ALEN) == 0) {
		/* group key */
		get_ap_address(handle, ndis_key.bssid);
	} else {
		/* pairwise key */
		ndis_key.index |= (1 << 30);
		memcpy(&ndis_key.bssid, addr, ETH_ALEN);
	}
		
	DBGTRACE2("bssid " MACSTR, MAC2STR(ndis_key.bssid));

	if (wpa_key.set_tx)
		ndis_key.index |= (1 << 31);

	if (wpa_key.alg == WPA_ALG_TKIP && wpa_key.key_len == 32) {
		/* wpa_supplicant gives us the Michael MIC RX/TX keys in
		 * different order than NDIS spec, so swap the order here. */
		memcpy(ndis_key.key, key, 16);
		memcpy(ndis_key.key + 16, key + 24, 8);
		memcpy(ndis_key.key + 24, key + 16, 8);
	} else
		memcpy(ndis_key.key, key, wpa_key.key_len);

	if (wpa_key.alg == WPA_ALG_NONE || wpa_key.key_len == 0) {
		/* TI driver crashes kernel if NDIS_OID_REMOVE_KEY is
		 * called; other drivers seem to not require it, so
		 * for now, don't remove the key from drvier */
		handle->encr_info.keys[wpa_key.key_index].length = 0;
		memset(&handle->encr_info.keys[wpa_key.key_index].key, 0,
		       wpa_key.key_len);
		DBGTRACE2("key %d removed", wpa_key.key_index);
	} else {
		res = miniport_set_info(handle, NDIS_OID_ADD_KEY,
					(char *)&ndis_key, sizeof(ndis_key));
		if (res == NDIS_STATUS_INVALID_DATA) {
			DBGTRACE2("adding key failed (%08X), %u",
				  res, ndis_key.struct_size);
			TRACEEXIT2(return -1);
		}
		handle->encr_info.keys[wpa_key.key_index].length = 
			wpa_key.key_len;
		memcpy(&handle->encr_info.keys[wpa_key.key_index].key,
		       &ndis_key.key, wpa_key.key_len);
		DBGTRACE2("key %d added", wpa_key.key_index);
	}

	TRACEEXIT2(return 0);
}

static int wpa_disassociate(struct net_device *dev,
			    struct iw_request_info *info,
			    union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = (struct ndis_handle *)dev->priv;
	mac_address ap_addr;
	unsigned char buf[NDIS_ESSID_MAX_SIZE];
	int i;
	
	TRACEENTER("%s", "");
	get_random_bytes(buf, sizeof(buf));
	for (i = 0; i < sizeof(buf); i++)
		buf[i] = 'a' + (buf[i] % ('z' - 'a'));
	set_essid(handle, buf, sizeof(buf));
	get_ap_address(handle, ap_addr);
	if (memcmp(ap_addr, "\x00\x00\x00\x00\x00\x00", ETH_ALEN))
		TRACEEXIT(return -1);
	else
		TRACEEXIT(return 0);
}

static int wpa_associate(struct net_device *dev,
			 struct iw_request_info *info,
			 union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = (struct ndis_handle *)dev->priv;
	struct wpa_assoc_info wpa_assoc_info;
	char ssid[NDIS_ESSID_MAX_SIZE], ie;
	int auth_mode, encr_mode, wpa2 = 0;
	
	TRACEENTER("%s", "");
	if (copy_from_user(&wpa_assoc_info, wrqu->data.pointer,
			   sizeof(wpa_assoc_info)) ||
	    copy_from_user(&ssid, wpa_assoc_info.ssid, NDIS_ESSID_MAX_SIZE))
		TRACEEXIT1(return -1);

	if (wpa_assoc_info.wpa_ie_len > 0 &&
	    copy_from_user(&ie, wpa_assoc_info.wpa_ie, 1) == 0 &&
	    ie == WLAN_EID_RSN) {
		wpa2 = 1;
	}
	
	DBGTRACE("key_mgmt_suite = %d, pairwise_suite = %d, group_suite= %d",
		 wpa_assoc_info.key_mgmt_suite,
		 wpa_assoc_info.pairwise_suite, wpa_assoc_info.group_suite);
	if (wpa_assoc_info.key_mgmt_suite != KEY_MGMT_PSK &&
	    wpa_assoc_info.key_mgmt_suite != KEY_MGMT_802_1X &&
	    wpa_assoc_info.key_mgmt_suite != KEY_MGMT_NONE)
		TRACEEXIT(return -1);

	switch (wpa_assoc_info.pairwise_suite) {
	case CIPHER_CCMP:
		if (!test_bit(CAPA_AES, &handle->capa))
			TRACEEXIT(return -1);
		encr_mode = ENCR3_ENABLED;
		break;
	case CIPHER_TKIP:
		if (!test_bit(CAPA_TKIP, &handle->capa))
			TRACEEXIT(return -1);
		encr_mode =  ENCR2_ENABLED;
		break;
	case CIPHER_WEP104:
	case CIPHER_WEP40:
		if (test_bit(CAPA_ENCR_NONE, &handle->capa))
			TRACEEXIT(return -1);
		encr_mode = ENCR1_ENABLED;
		break;
	default:
		TRACEEXIT(return -1);
	}

	switch (wpa_assoc_info.key_mgmt_suite) {
	case KEY_MGMT_PSK:
		if (!test_bit(CAPA_WPA, &handle->capa))
			TRACEEXIT(return -1);
		auth_mode = wpa2 ? AUTHMODE_WPA2PSK : AUTHMODE_WPAPSK;
		break;
	case KEY_MGMT_802_1X:
		if (!test_bit(CAPA_WPA, &handle->capa))
			TRACEEXIT(return -1);
		auth_mode = wpa2 ? AUTHMODE_WPA2 : AUTHMODE_WPA;
		break;
	case KEY_MGMT_NONE:
		if (wpa_assoc_info.group_suite != CIPHER_WEP104 &&
		    wpa_assoc_info.group_suite != CIPHER_WEP40)
			TRACEEXIT(return -1);
		auth_mode = handle->auth_mode;
#if 0
		if (wpa_assoc_info.auth_alg & AUTH_ALG_SHARED_KEY)
			auth_mode = AUTHMODE_RESTRICTED;
		else
			auth_mode = AUTHMODE_OPEN;
#endif
		break;
	default:
		TRACEEXIT(return -1);
	}

	if (set_auth_mode(handle, auth_mode))
		TRACEEXIT(return -1);
	if (set_encr_mode(handle, encr_mode))
		TRACEEXIT(return -1);

#if 0
	/* set channel */
	for (i = 0; i < (sizeof(freq_chan)/sizeof(freq_chan[0])); i++) {
		if (wpa_assoc_info.freq == freq_chan[i]) {
			union iwreq_data freq_req;

			memset(&freq_req, 0, sizeof(freq_req));
			freq_req.freq.m = i;
			if (iw_set_freq(dev, NULL, &freq_req, NULL))
				TRACEEXIT(return -1);
		}
	}
#endif

	/* set ssid */
	if (set_essid(handle, ssid, wpa_assoc_info.ssid_len))
		TRACEEXIT(return -1);

	TRACEEXIT(return 0);
}

static int wpa_set_countermeasures(struct net_device *dev,
				   struct iw_request_info *info,
				   union iwreq_data *wrqu, char *extra)
{
	TRACEENTER("%s", "");
	return 0;
}

static int wpa_deauthenticate(struct net_device *dev,
			      struct iw_request_info *info,
			      union iwreq_data *wrqu, char *extra)
{
	int ret;
	
	TRACEENTER("%s", "");
	ret = wpa_disassociate(dev, info, wrqu, extra);
	TRACEEXIT(return ret);
}

int set_privacy_filter(struct ndis_handle *handle, int flags)
{
	int res;

	TRACEENTER("filter: %d", flags);
	res = miniport_set_int(handle, NDIS_OID_PRIVACY_FILTER, flags);
	if (res == NDIS_STATUS_INVALID_DATA) {
		WARNING("setting privacy filter to %d failed (%08X)",
			flags, res);
		TRACEEXIT(return -EINVAL);
	}
	TRACEEXIT(return 0);
}

static int wpa_set_privacy_filter(struct net_device *dev,
				  struct iw_request_info *info,
				  union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = (struct ndis_handle *)dev->priv;
	int flags;

	TRACEENTER("filter: %d", wrqu->param.value);
	if (wrqu->param.value)
		flags = NDIS_PRIV_WEP;
	else
		flags = NDIS_PRIV_ACCEPT_ALL;
	if (set_privacy_filter(handle, flags))
		TRACEEXIT(return -1);
	TRACEEXIT(return 0);
}

static int wpa_set_auth_alg(struct net_device *dev,
			    struct iw_request_info *info,
			    union iwreq_data *wrqu, char *extra)
{
	struct ndis_handle *handle = (struct ndis_handle *)dev->priv;
	int mode;
	
	if (wrqu->param.value & AUTH_ALG_SHARED_KEY)
		mode = AUTHMODE_RESTRICTED;
	else if (wrqu->param.value & AUTH_ALG_OPEN_SYSTEM)
		mode = AUTHMODE_OPEN;
	else
		TRACEEXIT(return -1);

	DBGTRACE2("%d", mode);

	if (set_auth_mode(handle, mode))
		TRACEEXIT(return -1);
	TRACEEXIT(return 0);
}

static const struct iw_priv_args priv_args[] = {
	{WPA_SET_WPA, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "setwpa"},
	{WPA_SET_KEY, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "setkey"},
	{WPA_ASSOCIATE, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0,
	 "associate"},
	{WPA_DISASSOCIATE, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0,
	 "disassociate"},
	{WPA_DROP_UNENCRYPTED, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0,
	 "drop_unencrypted"},
	{WPA_SET_COUNTERMEASURES, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0,
	 "countermeaures"},
	{WPA_DEAUTHENTICATE, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0,
	 "deauthenticate"},
	{WPA_SET_AUTH_ALG, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0,
	 "auth_alg"},

	{PRIV_RESET, 0, 0, "ndis_reset"},
	{PRIV_POWER_PROFILE, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0,
	 "power_profile"},
};

static const iw_handler priv_handler[] = {
	[WPA_SET_WPA 		- SIOCIWFIRSTPRIV] = wpa_set_wpa,
	[WPA_SET_KEY 		- SIOCIWFIRSTPRIV] = wpa_set_key,
	[WPA_ASSOCIATE 		- SIOCIWFIRSTPRIV] = wpa_associate,
	[WPA_DISASSOCIATE 	- SIOCIWFIRSTPRIV] = wpa_disassociate,
	[WPA_DROP_UNENCRYPTED 	- SIOCIWFIRSTPRIV] = wpa_set_privacy_filter,
	[WPA_SET_COUNTERMEASURES- SIOCIWFIRSTPRIV] = wpa_set_countermeasures,
	[WPA_DEAUTHENTICATE 	- SIOCIWFIRSTPRIV] = wpa_deauthenticate,
	[WPA_SET_AUTH_ALG 	- SIOCIWFIRSTPRIV] = wpa_set_auth_alg,

	[PRIV_RESET 		- SIOCIWFIRSTPRIV] = priv_reset,
	[PRIV_POWER_PROFILE 	- SIOCIWFIRSTPRIV] = priv_power_profile,
};

const struct iw_handler_def ndis_handler_def = {
	.num_standard	= sizeof(ndis_handler) / sizeof(ndis_handler[0]),
	.num_private	= sizeof(priv_handler) / sizeof(priv_handler[0]),
	.num_private_args = sizeof(priv_args) / sizeof(priv_args[0]),

	.standard	= (iw_handler *)ndis_handler,
	.private	= (iw_handler *)priv_handler,
	.private_args	= (struct iw_priv_args *)priv_args,
};
