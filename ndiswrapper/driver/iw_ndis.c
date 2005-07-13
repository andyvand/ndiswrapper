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

static const char *network_names[] = {"IEEE 802.11FH", "IEEE 802.11b",
				      "IEEE 802.11a", "IEEE 802.11g", "Auto"};

int set_essid(struct wrapper_dev *wd, const char *ssid, int ssid_len)
{
	NDIS_STATUS res;
	struct ndis_essid req;

	memset(&req, 0, sizeof(req));
	
	if (ssid_len == 0)
		req.length = 1;
	else {
		if (ssid_len > NDIS_ESSID_MAX_SIZE)
			return -EINVAL;

		req.length = ssid_len;
		memcpy(&req.essid, ssid, req.length);
		DBGTRACE1("ssid = '%s'", req.essid);
	}
	
	res = miniport_set_info(wd, OID_802_11_SSID, &req, sizeof(req));
	if (res)
		WARNING("setting essid failed (%08X)", res); 

	memcpy(&wd->essid, &req, sizeof(req));
	TRACEEXIT1(return 0);
}

static int set_assoc_params(struct wrapper_dev *wd)
{
#if WIRELESS_EXT > 17
	int auth_mode, encr_mode, priv_mode;

	priv_mode = Ndis802_11PrivFilterAcceptAll;

	DBGTRACE2("wpa_version=0x%x auth_alg=0x%x key_mgmt=0x%x "
		  "cipher_pairwise=0x%x cipher_group=0x%x",
		  wd->iw_auth_wpa_version, wd->iw_auth_80211_auth_alg,
		  wd->iw_auth_key_mgmt, wd->iw_auth_cipher_pairwise,
		  wd->iw_auth_cipher_group);
	if (wd->iw_auth_wpa_version & IW_AUTH_WPA_VERSION_WPA2) {
		priv_mode = Ndis802_11PrivFilter8021xWEP;
		if (wd->iw_auth_key_mgmt & IW_AUTH_KEY_MGMT_802_1X)
			auth_mode = Ndis802_11AuthModeWPA2;
		else
			auth_mode = Ndis802_11AuthModeWPA2PSK;
	} else if (wd->iw_auth_wpa_version & IW_AUTH_WPA_VERSION_WPA) {
		priv_mode = Ndis802_11PrivFilter8021xWEP;
		if (wd->iw_auth_key_mgmt & IW_AUTH_KEY_MGMT_802_1X)
			auth_mode = Ndis802_11AuthModeWPA;
		else if (wd->iw_auth_key_mgmt & IW_AUTH_KEY_MGMT_PSK)
			auth_mode = Ndis802_11AuthModeWPAPSK;
		else
			auth_mode = Ndis802_11AuthModeWPANone;
	} else if (wd->iw_auth_80211_auth_alg & IW_AUTH_ALG_SHARED_KEY) {
		if (wd->iw_auth_80211_auth_alg &
		    IW_AUTH_ALG_OPEN_SYSTEM)
			auth_mode = Ndis802_11AuthModeAutoSwitch;
		else
			auth_mode = Ndis802_11AuthModeShared;
	} else
		auth_mode = Ndis802_11AuthModeOpen;

	if (wd->iw_auth_cipher_pairwise & IW_AUTH_CIPHER_CCMP)
		encr_mode = Ndis802_11Encryption3Enabled;
	else if (wd->iw_auth_cipher_pairwise & IW_AUTH_CIPHER_TKIP)
		encr_mode = Ndis802_11Encryption2Enabled;
	else if (wd->iw_auth_cipher_pairwise &
		 (IW_AUTH_CIPHER_WEP40 | IW_AUTH_CIPHER_WEP104))
		encr_mode = Ndis802_11Encryption1Enabled;
	else if (wd->iw_auth_cipher_group & IW_AUTH_CIPHER_CCMP)
		encr_mode = Ndis802_11Encryption3Enabled;
	else if (wd->iw_auth_cipher_group & IW_AUTH_CIPHER_TKIP)
		encr_mode = Ndis802_11Encryption2Enabled;
	else
		encr_mode = Ndis802_11EncryptionDisabled;

	DBGTRACE2("priv_mode=%d auth_mode=%d encr_mode=%d",
		  priv_mode, auth_mode, encr_mode);

	set_privacy_filter(wd, priv_mode);
	set_auth_mode(wd, auth_mode);
	set_encr_mode(wd, encr_mode);
#endif
	return 0;
}


static int iw_set_essid(struct net_device *dev, struct iw_request_info *info,
			union iwreq_data *wrqu, char *extra)
{
	struct wrapper_dev *wd = dev->priv;
	char ssid[IW_ESSID_MAX_SIZE];

	memset(ssid, 0, sizeof(ssid));
	/* iwconfig adds 1 to the actual length */
	/* there is no way to turn off essid other than to set to
	 * random bytes; instead, we use off to mean any */
	if (wrqu->essid.flags)
		wrqu->essid.length--;
	else
		wrqu->essid.length = 0;

	if (wrqu->essid.length > IW_ESSID_MAX_SIZE)
		TRACEEXIT1(return -EINVAL);

	if (wd->iw_auth_set) {
		int ret = set_assoc_params(wd);
		wd->iw_auth_set = 0;
		if (ret < 0)
			TRACEEXIT1(return ret);
	}

	memcpy(ssid, extra, wrqu->essid.length);
	if (set_essid(wd, ssid, wrqu->essid.length))
		TRACEEXIT1(return -EINVAL);

	TRACEEXIT1(return 0);
}

static int iw_get_essid(struct net_device *dev, struct iw_request_info *info,
			union iwreq_data *wrqu, char *extra)
{
	struct wrapper_dev *wd = dev->priv; 
	NDIS_STATUS res;
	struct ndis_essid req;

	TRACEENTER1("%s", "");
	memset(&req, 0, sizeof(req));
	res = miniport_query_info(wd, OID_802_11_SSID, &req, sizeof(req));
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

int set_infra_mode(struct wrapper_dev *wd,
		   enum network_infrastructure mode)
{
	NDIS_STATUS res;
	unsigned int i;

	TRACEENTER1("%s", "");

	res = miniport_set_int(wd, OID_802_11_INFRASTRUCTURE_MODE, mode);
	if (res == NDIS_STATUS_INVALID_DATA) {
		WARNING("setting operating mode failed (%08X)", res); 
		TRACEEXIT1(return -EINVAL);
	}

	for (i = 0; i < MAX_ENCR_KEYS; i++)
		wd->encr_info.keys[i].length = 0;
	wd->infrastructure_mode = mode;
	TRACEEXIT1(return 0);
}

static int iw_set_infra_mode(struct net_device *dev,
			     struct iw_request_info *info,
			     union iwreq_data *wrqu, char *extra)
{
	struct wrapper_dev *wd = dev->priv;
	enum network_infrastructure ndis_mode;

	TRACEENTER1("%s", "");
	switch (wrqu->mode) {
	case IW_MODE_ADHOC:
		ndis_mode = Ndis802_11IBSS;
		break;	
	case IW_MODE_INFRA:
		ndis_mode = Ndis802_11Infrastructure;
		break;	
	case IW_MODE_AUTO:
		ndis_mode = Ndis802_11AutoUnknown;
		break;	
	default:
		TRACEEXIT1(return -EINVAL);
	}
	
	if (set_infra_mode(wd, ndis_mode))
		TRACEEXIT1(return -EINVAL);

	TRACEEXIT1(return 0);
}

static int iw_get_infra_mode(struct net_device *dev,
			     struct iw_request_info *info,
			     union iwreq_data *wrqu, char *extra)
{
	struct wrapper_dev *wd = dev->priv; 
	int ndis_mode, iw_mode;
	NDIS_STATUS res;

	TRACEENTER1("%s", "");
	res = miniport_query_int(wd, OID_802_11_INFRASTRUCTURE_MODE,
				 &ndis_mode);
	if (res) {
		WARNING("getting operating mode failed (%08X)", res);
		TRACEEXIT1(return -EOPNOTSUPP);
	}

	switch(ndis_mode) {
	case Ndis802_11IBSS:
		iw_mode = IW_MODE_ADHOC;
		break;
	case Ndis802_11Infrastructure:
		iw_mode = IW_MODE_INFRA;
		break;
	case Ndis802_11AutoUnknown:
		iw_mode = IW_MODE_AUTO;
		break;
	default:
		ERROR("invalid operating mode (%u)", ndis_mode);
		TRACEEXIT1(return -EINVAL);
	}
	wrqu->mode = iw_mode;
	TRACEEXIT1(return 0);
}

static const char *network_type_to_name(int net_type)
{
	if (net_type >= 0 &&
	    net_type < (sizeof(network_names)/sizeof(network_names[0])))
		return network_names[net_type];
	else
		return network_names[sizeof(network_names) / 
				     sizeof(network_names[0]) - 1];
}

static int iw_get_network_type(struct net_device *dev,
			       struct iw_request_info *info,
			       union iwreq_data *wrqu, char *extra)
{
	struct wrapper_dev *wd = dev->priv;
	unsigned int network_type;
	NDIS_STATUS res;
	
	res = miniport_query_int(wd, OID_802_11_NETWORK_TYPE_IN_USE,
				 &network_type);
	if (res == NDIS_STATUS_INVALID_DATA)
		network_type = -1;

	strncpy(wrqu->name, network_type_to_name(network_type),
	        sizeof(wrqu->name) - 1);
	wrqu->name[sizeof(wrqu->name)-1] = 0;
	return 0;
}

static int iw_get_freq(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct wrapper_dev *wd = dev->priv;
	NDIS_STATUS res;
	struct ndis_configuration req;

	memset(&req, 0, sizeof(req));
	res = miniport_query_info(wd, OID_802_11_CONFIGURATION,
				  &req, sizeof(req));
	if (res == NDIS_STATUS_INVALID_DATA) {
		WARNING("getting configuration failed (%08X)", res);
		TRACEEXIT2(return -EOPNOTSUPP);
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
	struct wrapper_dev *wd = dev->priv;
	NDIS_STATUS res;
	struct ndis_configuration req;

	memset(&req, 0, sizeof(req));
	res = miniport_query_info(wd, OID_802_11_CONFIGURATION,
				  &req, sizeof(req));
	if (res == NDIS_STATUS_INVALID_DATA) {
		WARNING("getting configuration failed (%08X)", res);
		TRACEEXIT2(return -EOPNOTSUPP);
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
	res = miniport_set_info(wd, OID_802_11_CONFIGURATION, &req,
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
	struct wrapper_dev *wd = dev->priv; 
	ndis_tx_power_level ndis_power;
	NDIS_STATUS res;

	res = miniport_query_info(wd, OID_802_11_TX_POWER_LEVEL,
				  &ndis_power, sizeof(ndis_power));
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
	struct wrapper_dev *wd = dev->priv; 
	ndis_tx_power_level ndis_power;
	NDIS_STATUS res;

	if (wrqu->txpower.disabled) {
		ndis_power = 0;
		res = miniport_set_info(wd, OID_802_11_TX_POWER_LEVEL,
					&ndis_power, sizeof(ndis_power));
		if (res == NDIS_STATUS_INVALID_DATA)
			return -EINVAL;
		res = miniport_set_int(wd, OID_802_11_DISASSOCIATE, 0);
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
	res = miniport_set_info(wd, OID_802_11_TX_POWER_LEVEL,
				&ndis_power, sizeof(ndis_power));
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
	struct wrapper_dev *wd = dev->priv; 
	ULONG ndis_rate;

	int res = miniport_query_info(wd, OID_GEN_LINK_SPEED,
				      &ndis_rate, sizeof(ndis_rate));
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
	struct wrapper_dev *wd = dev->priv; 
	int i;
	NDIS_STATUS res;
	ndis_rates rates;

	if (wrqu->bitrate.fixed == 0)
		TRACEEXIT1(return 0);

	res = miniport_query_info(wd, OID_802_11_SUPPORTED_RATES,
				  &rates, sizeof(rates));
	if (res == NDIS_STATUS_NOT_SUPPORTED ||
	    res == NDIS_STATUS_INVALID_DATA) {
		WARNING("getting bit rate failed (%08X)", res);
		TRACEEXIT1(return 0);
	}
		
	for (i = 0 ; i < NDIS_MAX_RATES_EX ; i++) {
		if (rates[i] & 0x80)
			continue;
		if ((rates[i] & 0x7f) * 500000 > wrqu->bitrate.value) {
			DBGTRACE1("setting rate %d to 0",
				  (rates[i] & 0x7f) * 500000);
			rates[i] = 0;
		}
	}

	res = miniport_query_info(wd, OID_802_11_DESIRED_RATES,
				  &rates, sizeof(rates));
	if (res == NDIS_STATUS_NOT_SUPPORTED ||
	    res == NDIS_STATUS_INVALID_DATA) {
		WARNING("setting bit rate failed (%08X)", res);
		TRACEEXIT1(return 0);
	}

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
	struct wrapper_dev *wd = dev->priv;
	ndis_rts_threshold rts_threshold;
	NDIS_STATUS res;

	res = miniport_query_info(wd, OID_802_11_RTS_THRESHOLD,
				  &rts_threshold, sizeof(rts_threshold));
	if (res == NDIS_STATUS_NOT_SUPPORTED)
		return -EOPNOTSUPP;

	wrqu->rts.value = rts_threshold;
	return 0;
}

static int iw_get_frag_threshold(struct net_device *dev,
				 struct iw_request_info *info,
				 union iwreq_data *wrqu, char *extra)
{
	struct wrapper_dev *wd = dev->priv; 
	ndis_fragmentation_threshold frag_threshold;
	NDIS_STATUS res;

	res = miniport_query_info(wd, OID_802_11_FRAGMENTATION_THRESHOLD,
				  &frag_threshold, sizeof(frag_threshold));
	if (res == NDIS_STATUS_NOT_SUPPORTED)
		return -EOPNOTSUPP;

	wrqu->frag.value = frag_threshold;
	return 0;
}

int get_ap_address(struct wrapper_dev *wd, mac_address ap_addr)
{
	NDIS_STATUS res;

	TRACEENTER1("%s", "");

	res = miniport_query_info(wd, OID_802_11_BSSID, ap_addr, ETH_ALEN);
	if (res == NDIS_STATUS_ADAPTER_NOT_READY)
		memset(ap_addr, 0, ETH_ALEN);

	DBGTRACE1(MACSTR, MAC2STR(ap_addr));
        TRACEEXIT1(return 0);
}

static int iw_get_ap_address(struct net_device *dev,
			     struct iw_request_info *info,
			     union iwreq_data *wrqu, char *extra)
{
	struct wrapper_dev *wd = dev->priv;
	mac_address ap_addr;

	TRACEENTER1("%s", "");
	get_ap_address(wd, ap_addr);

	memcpy(wrqu->ap_addr.sa_data, ap_addr, ETH_ALEN);
	wrqu->ap_addr.sa_family = ARPHRD_ETHER;
	TRACEEXIT1(return 0);
}

static int iw_set_ap_address(struct net_device *dev,
			     struct iw_request_info *info,
			     union iwreq_data *wrqu, char *extra)
{
	struct wrapper_dev *wd = dev->priv; 
	NDIS_STATUS res;
	mac_address ap_addr;

        memcpy(ap_addr, wrqu->ap_addr.sa_data, ETH_ALEN);
	DBGTRACE1(MACSTR, MAC2STR(ap_addr));
	res = miniport_set_info(wd, OID_802_11_BSSID, ap_addr, ETH_ALEN);

	if (res) {
		WARNING("setting AP mac address failed (%08X)", res);
		TRACEEXIT1(return -EINVAL);
	}

        TRACEEXIT1(return 0);
}

int set_auth_mode(struct wrapper_dev *wd, int auth_mode)
{
	NDIS_STATUS res;

	res = miniport_set_int(wd, OID_802_11_AUTHENTICATION_MODE,
			       auth_mode);
	if (res == NDIS_STATUS_INVALID_DATA) {
		WARNING("setting auth mode failed (%08X)", res);
		TRACEEXIT2(return -EINVAL);
	} else {
		wd->auth_mode = auth_mode;
		TRACEEXIT2(return 0);
	}
}

int get_auth_mode(struct wrapper_dev *wd)
{
	int i;

	if (miniport_query_int(wd, OID_802_11_AUTHENTICATION_MODE, &i))
		TRACEEXIT2(return -EINVAL);
	else
		TRACEEXIT2(return i);
}

int set_encr_mode(struct wrapper_dev *wd, int encr_mode)
{
	NDIS_STATUS res;

	res = miniport_set_int(wd, OID_802_11_ENCRYPTION_STATUS,
			       encr_mode);
	if (res == NDIS_STATUS_INVALID_DATA)
		TRACEEXIT2(return -EINVAL);
	else {
		wd->encr_mode = encr_mode;
		TRACEEXIT2(return 0);
	}
}

int get_encr_mode(struct wrapper_dev *wd)
{
	int i;

	if (miniport_query_int(wd, OID_802_11_ENCRYPTION_STATUS, &i))
		TRACEEXIT2(return -EINVAL);
	else
		TRACEEXIT2(return i);
}

static int iw_get_encr(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct wrapper_dev *wd = dev->priv;
	NDIS_STATUS res;
	int index, status;
	struct encr_info *encr_info = &wd->encr_info;

	TRACEENTER2("wd = %p", wd);
	wrqu->data.length = 0;
	extra[0] = 0;

	index = (wrqu->encoding.flags & IW_ENCODE_INDEX);
	DBGTRACE2("index = %u", index);
	if (index > 0)
		index--;
	else
		index = encr_info->tx_key_index;

	if (index < 0 || index >= MAX_ENCR_KEYS) {
		WARNING("encryption index out of range (%u)", index);
		TRACEEXIT1(return -EINVAL);
	}

	if (index != encr_info->tx_key_index) {
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
	
	/* transmit key */
	res = miniport_query_int(wd, OID_802_11_ENCRYPTION_STATUS,
				 &status);
	if (res == NDIS_STATUS_NOT_SUPPORTED) {
		WARNING("getting encryption status failed (%08X)", res);
		TRACEEXIT1(return -EOPNOTSUPP);
	}

	if (status == Ndis802_11EncryptionDisabled ||
	    status == Ndis802_11EncryptionNotSupported)
		wrqu->data.flags |= IW_ENCODE_DISABLED;
	else {
		if (status == Ndis802_11Encryption1KeyAbsent ||
		    status == Ndis802_11Encryption2KeyAbsent ||
		    status == Ndis802_11Encryption3KeyAbsent)
			wrqu->data.flags |= IW_ENCODE_NOKEY;
		else {
			wrqu->data.flags |= IW_ENCODE_ENABLED;
			wrqu->encoding.flags |= index+1;
			wrqu->data.length = encr_info->keys[index].length;
			memcpy(extra, encr_info->keys[index].key,
			       encr_info->keys[index].length);
		}
	}
	res = miniport_query_int(wd, OID_802_11_AUTHENTICATION_MODE,
				 &status);
	if (res == NDIS_STATUS_NOT_SUPPORTED) {
		WARNING("getting authentication mode failed (%08X)", res);
		TRACEEXIT1(return -EOPNOTSUPP);
	}

	if (status == Ndis802_11AuthModeOpen)
		wrqu->data.flags |= IW_ENCODE_OPEN;
	else if (status == Ndis802_11AuthModeShared)
		wrqu->data.flags |= IW_ENCODE_RESTRICTED;
	else if (status == Ndis802_11AuthModeAutoSwitch)
		wrqu->data.flags |= IW_ENCODE_RESTRICTED;
	
	TRACEEXIT1(return 0);
}

/* index must be 0 - N, as per NDIS  */
int add_wep_key(struct wrapper_dev *wd, char *key, int key_len,
		int index)
{
	struct ndis_encr_key ndis_key;
	NDIS_STATUS res;

	TRACEENTER2("key index: %d", index);
	if (key_len <= 0 || key_len > NDIS_ENCODING_TOKEN_MAX) {
		WARNING("invalid key length (%d)", key_len);
		TRACEEXIT2(return -EINVAL);
	}
	if (index < 0 || index >= MAX_ENCR_KEYS) {
		WARNING("invalid key index (%d)", index);
		TRACEEXIT2(return -EINVAL);
	}
	ndis_key.struct_size = sizeof(ndis_key);
	ndis_key.length = key_len;
	memcpy(&ndis_key.key, key, key_len);
	ndis_key.index = index;
	if (index == wd->encr_info.tx_key_index)
		ndis_key.index |= (1 << 31);

	res = miniport_set_info(wd, OID_802_11_ADD_WEP, &ndis_key,
				sizeof(ndis_key));
	if (res == NDIS_STATUS_INVALID_DATA) {
		WARNING("adding encryption key %d failed (%08X)",
			index+1, res);
		TRACEEXIT1(return -EINVAL);
	}
		
	/* Atheros driver messes up ndis_key during ADD_WEP, so
	 * don't rely on that; instead use info in key and key_len */
	wd->encr_info.keys[index].length = key_len;
	memcpy(&wd->encr_info.keys[index].key, key, key_len);

	if (index == wd->encr_info.tx_key_index) {
		res = set_encr_mode(wd, Ndis802_11Encryption1Enabled);
		if (res)
			WARNING("encryption couldn't be enabled (%08X)", res);
	}
	TRACEEXIT1(return 0);
}

static int iw_set_encr(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct wrapper_dev *wd = dev->priv;
	NDIS_STATUS res;
	unsigned int index, key_len;
	struct encr_info *encr_info = &wd->encr_info;
	unsigned char *key;
	
	TRACEENTER1("%s", "");
	index = (wrqu->encoding.flags & IW_ENCODE_INDEX);
	DBGTRACE2("index = %u", index);

	/* iwconfig gives index as 1 - N */
	if (index > 0)
		index--;
	else
		index = encr_info->tx_key_index;

	if (index < 0 || index >= MAX_ENCR_KEYS) {
		WARNING("encryption index out of range (%u)", index);
		TRACEEXIT1(return -EINVAL);
	}

	/* remove key if disabled */
	if (wrqu->data.flags & IW_ENCODE_DISABLED) {
		ndis_key_index keyindex = index;
		res = miniport_set_info(wd, OID_802_11_REMOVE_WEP,
					&keyindex, sizeof(keyindex));
		if (res == NDIS_STATUS_INVALID_DATA) {
			WARNING("removing encryption key %d failed (%08X)",
				index, res);
			TRACEEXIT1(return -EINVAL);
		}
		encr_info->keys[index].length = 0;
		
		/* if it is transmit key, disable encryption */
		if (index == encr_info->tx_key_index) {
			res = set_encr_mode(wd, Ndis802_11EncryptionDisabled);
			if (res)
				WARNING("changing encr status failed (%08X)",
					res);
		}
		TRACEEXIT1(return 0);
	}

	/* global encryption state (for all keys) */
	if (wrqu->data.flags & IW_ENCODE_OPEN)
		res = set_auth_mode(wd, Ndis802_11AuthModeOpen);
	else // if (wrqu->data.flags & IW_ENCODE_RESTRICTED)
		res = set_auth_mode(wd, Ndis802_11AuthModeShared);
	if (res) {
		WARNING("setting authentication mode failed (%08X)", res);
		TRACEEXIT1(return -EINVAL);
	}

	DBGTRACE2("key length: %d", wrqu->data.length);

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
		encr_info->tx_key_index = index;
	}

	if (add_wep_key(wd, key, key_len, index))
		TRACEEXIT2(return -EINVAL);

	if (index == encr_info->tx_key_index) {
		/* if transmit key is at index other than 0, some
		 * drivers, at least Atheros and TI, want another
		 * (global) non-transmit key to be set; don't know why */
		if (index != 0) {
			int i;
			for (i = 0; i < MAX_ENCR_KEYS; i++)
				if (i != index &&
				    encr_info->keys[i].length != 0)
					break;
			if (i == MAX_ENCR_KEYS) {
				if (index == 0)
					i = index + 1;
				else
					i = index - 1;
				if (add_wep_key(wd, key, key_len, i))
					WARNING("couldn't add broadcast key"
						" at %d", i);
			}
		}
		/* ndis drivers want essid to be set after setting encr */
		set_essid(wd, wd->essid.essid, wd->essid.length);
	}
	TRACEEXIT1(return 0);
}
	
static int iw_set_nick(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct wrapper_dev *wd = dev->priv;
	
	if (wrqu->data.length > IW_ESSID_MAX_SIZE)
		return -EINVAL;
	memcpy(wd->nick, extra, wrqu->data.length);
	wd->nick[IW_ESSID_MAX_SIZE] = 0;
	return 0;
}

static int iw_get_nick(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct wrapper_dev *wd = dev->priv;
	
	memcpy(extra, wd->nick, IW_ESSID_MAX_SIZE+1);
	wrqu->data.length = strlen(wd->nick);
	return 0;
}

static char *ndis_translate_scan(struct net_device *dev, char *event,
				 char *end_buf, struct ndis_ssid_item *item)
{
	struct iw_event iwe;
	char *current_val;
	int i, nrates;
	unsigned char buf[MAX_WPA_IE_LEN * 2 + 30];

	TRACEENTER1("%p, %p", event, item);
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
	strncpy(iwe.u.name, network_type_to_name(item->net_type), IFNAMSIZ);
	event = iwe_stream_add_event(event, end_buf, &iwe, IW_EV_CHAR_LEN);

	/* add mode */
	memset(&iwe, 0, sizeof(iwe));
	iwe.cmd = SIOCGIWMODE;
	if (item->mode == Ndis802_11IBSS)
		iwe.u.mode = IW_MODE_ADHOC;
	else if (item->mode == Ndis802_11Infrastructure)
		iwe.u.mode = IW_MODE_INFRA;
	else // if (item->mode == Ndis802_11AutoUnknown)
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
	if (item->privacy == Ndis802_11PrivFilterAcceptAll)
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
	
	memset(&iwe, 0, sizeof(iwe));
	iwe.cmd = IWEVCUSTOM;
	sprintf(buf, "atim=%u", item->config.atim_window);
	iwe.u.data.length = strlen(buf);
	event = iwe_stream_add_point(event, end_buf, &iwe, buf);

	if (item->length > sizeof(*item)) {
		unsigned char *iep = (unsigned char *)item->ies +
			sizeof(struct ndis_fixed_ies);
	/*
	 * TODO: backwards compatibility would require that IWEVCUSTOM
	 * is send even if WIRELESS_EXT > 17. This version does not do
	 * this in order to allow wpa_supplicant to be tested with
	 * WE-18.
	 */
#if WIRELESS_EXT > 17
		memset(&iwe, 0, sizeof(iwe));
		iwe.cmd = IWEVGENIE;
		iwe.u.data.length = item->ie_length;
		event = iwe_stream_add_point(event, end_buf, &iwe, iep);
#else
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
				
				DBGTRACE2("adding wpa_ie :%lu",
					  (unsigned long)strlen(buf));

				memset(&iwe, 0, sizeof(iwe));
				iwe.cmd = IWEVCUSTOM;
				iwe.u.data.length = strlen(buf);
				event = iwe_stream_add_point(event, end_buf,
							     &iwe, buf);
			} else if (iep[0] == RSN_INFO_ELEM) {
				unsigned char *p = buf;

				p += sprintf(p, "rsn_ie=");
				for (i = 0; i < ielen; i++)
					p += sprintf(p, "%02x", iep[i]);

				DBGTRACE2("adding rsn_ie :%lu",
					  (unsigned long)strlen(buf));
				memset(&iwe, 0, sizeof(iwe));
				iwe.cmd = IWEVCUSTOM;
				iwe.u.data.length = strlen(buf);
				event = iwe_stream_add_point(event, end_buf,
							     &iwe, buf);
			}

			iep += ielen;
		}
#endif
	}

	DBGTRACE2("event = %p, current_val = %p", event, current_val);

	TRACEEXIT1(return event);
}

int set_scan(struct wrapper_dev *wd)
{
	NDIS_STATUS res;

	TRACEENTER1("%s", "");
	res = miniport_set_int(wd, OID_802_11_BSSID_LIST_SCAN, 0);
	wd->scan_timestamp = jiffies;
	if (res == NDIS_STATUS_NOT_SUPPORTED ||
	    res == NDIS_STATUS_INVALID_DATA) {
		WARNING("scanning failed (%08X)", res);
		TRACEEXIT1(return -EOPNOTSUPP);
	} else
		TRACEEXIT1(return 0);
}

static int iw_set_scan(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct wrapper_dev *wd = dev->priv;
	
	return set_scan(wd);
}

static int iw_get_scan(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
 	struct wrapper_dev *wd = dev->priv;
	unsigned int i, list_len, needed;
	NDIS_STATUS res;
	struct ndis_bssid_list *bssid_list;
	char *event = extra;
	struct ndis_ssid_item *cur_item ;

	TRACEENTER1("%s", "");

	if (time_before(jiffies, wd->scan_timestamp + 3 * HZ))
		return -EAGAIN;
	
	/* try with space for a few scan items */
	list_len = sizeof(ULONG) + sizeof(struct ndis_ssid_item) * 8;
	bssid_list = kmalloc(list_len, GFP_KERNEL);
	/* some drivers don't set bssid_list->num_items to 0 if
	   OID_802_11_BSSID_LIST returns no items (prism54 driver, e.g.,) */
	memset(bssid_list, 0, list_len);

	res = miniport_query_info_needed(wd, OID_802_11_BSSID_LIST,
					 bssid_list, list_len, &needed);
	if (needed > 0 || res == NDIS_STATUS_INVALID_LENGTH) {
		/* now try with required space */
		kfree(bssid_list);
		list_len = needed;
		bssid_list = kmalloc(list_len, GFP_KERNEL);
		memset(bssid_list, 0, list_len);

		res = miniport_query_info(wd, OID_802_11_BSSID_LIST,
					  bssid_list, list_len);
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
	struct wrapper_dev *wd = dev->priv;
	NDIS_STATUS res;
	ULONG power_mode;

	if (wrqu->power.disabled == 1)
		power_mode = NDIS_POWER_OFF;
	else if (wrqu->power.flags & IW_POWER_MIN)
		power_mode = NDIS_POWER_MIN;
	else // if (wrqu->power.flags & IW_POWER_MAX)
		power_mode = NDIS_POWER_MAX;

	res = miniport_set_info(wd, OID_802_11_POWER_MODE,
				&power_mode, sizeof(power_mode));
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
	struct wrapper_dev *wd = dev->priv;
	NDIS_STATUS res;
	ULONG power_mode;

	res = miniport_query_info(wd, OID_802_11_POWER_MODE,
				  &power_mode, sizeof(power_mode));
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
	struct wrapper_dev *wd = dev->priv;
	NDIS_STATUS res;
	ndis_rssi rssi_trigger;

	res = miniport_query_info(wd, OID_802_11_RSSI_TRIGGER,
				  &rssi_trigger, sizeof(rssi_trigger));
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
	struct wrapper_dev *wd = dev->priv;
	NDIS_STATUS res;
	ndis_rssi rssi_trigger;

	if (wrqu->param.disabled)
		rssi_trigger = 0;
	else
		rssi_trigger = wrqu->param.value;
	res = miniport_set_info(wd, OID_802_11_RSSI_TRIGGER,
				&rssi_trigger, sizeof(rssi_trigger));
	if (res)
		return -EINVAL;
	return 0;
}

static int iw_get_ndis_stats(struct net_device *dev,
			     struct iw_request_info *info,
			     union iwreq_data *wrqu, char *extra)
{
	struct wrapper_dev *wd = dev->priv;
	struct iw_statistics *stats = &wd->wireless_stats;
	memcpy(&wrqu->qual, &stats->qual, sizeof(stats->qual));
	return 0;
}

static int iw_get_range(struct net_device *dev, struct iw_request_info *info,
			union iwreq_data *wrqu, char *extra)
{
	struct iw_range *range = (struct iw_range *)extra;
	struct iw_point *data = &wrqu->data;
	struct wrapper_dev *wd = dev->priv;
	unsigned int i;
	NDIS_STATUS res;
	ndis_rates rates;
	ndis_tx_power_level tx_power;

	data->length = sizeof(struct iw_range);
	memset(range, 0, sizeof(struct iw_range));
	
	range->txpower_capa = IW_TXPOW_MWATT;
	range->num_txpower = 0;

	res = miniport_query_info(wd, OID_802_11_TX_POWER_LEVEL,
				 &tx_power, sizeof(tx_power));
	if (!res) {
		range->num_txpower = 1;
		range->txpower[0] = tx_power;
	}

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
	range->sensitivity = 3;

	range->max_encoding_tokens = 4;
	range->num_encoding_sizes = 2;
	range->encoding_size[0] = 5;
	range->encoding_size[1] = 13;

	range->num_bitrates = 0;
	res = miniport_query_info(wd, OID_802_11_SUPPORTED_RATES,
				  &rates, sizeof(rates));
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

#if WIRELESS_EXT > 16
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
#endif /* WIRELESS_EXT > 16 */

#if WIRELESS_EXT > 17
	/* TODO: should determine WPA/WPA2 support in check_capa(). */
	range->enc_capa = IW_ENC_CAPA_WPA | IW_ENC_CAPA_WPA2;
	if (test_bit(Ndis802_11Encryption2Enabled, &wd->capa.encr))
		range->enc_capa |= IW_ENC_CAPA_CIPHER_TKIP;
	if (test_bit(Ndis802_11Encryption3Enabled, &wd->capa.encr))
		range->enc_capa |= IW_ENC_CAPA_CIPHER_CCMP;
#endif /* WIRELESS_EXT > 17 */

	return 0;
}

#if WIRELESS_EXT > 17
static int wpa_disassociate(struct net_device *dev,
			    struct iw_request_info *info,
			    union iwreq_data *wrqu, char *extra);

static int iw_set_mlme(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct iw_mlme *mlme = (struct iw_mlme *)extra;

	switch (mlme->cmd) {
	case IW_MLME_DEAUTH:
	case IW_MLME_DISASSOC:
		DBGTRACE2("cmd=%d reason_code=%d",
			  mlme->cmd, mlme->reason_code);
		return wpa_disassociate(dev, info, wrqu, extra);
	default:
		return -EOPNOTSUPP;
	}

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
	struct wrapper_dev *wd = dev->priv;
	DBGTRACE2("index=%d value=%d", wrqu->param.flags & IW_AUTH_INDEX,
		  wrqu->param.value);
	wd->iw_auth_set = 1;
	switch (wrqu->param.flags & IW_AUTH_INDEX) {
	case IW_AUTH_WPA_VERSION:
		wd->iw_auth_wpa_version = wrqu->param.value;
		break;
	case IW_AUTH_CIPHER_PAIRWISE:
		wd->iw_auth_cipher_pairwise = wrqu->param.value;
		break;
	case IW_AUTH_CIPHER_GROUP:
		wd->iw_auth_cipher_group = wrqu->param.value;
		break;
	case IW_AUTH_KEY_MGMT:
		wd->iw_auth_key_mgmt = wrqu->param.value;
		break;
	case IW_AUTH_80211_AUTH_ALG:
		wd->iw_auth_80211_auth_alg = wrqu->param.value;
		break;
	case IW_AUTH_TKIP_COUNTERMEASURES:
	case IW_AUTH_DROP_UNENCRYPTED:
	case IW_AUTH_WPA_ENABLED:
	case IW_AUTH_RX_UNENCRYPTED_EAPOL:
	case IW_AUTH_PRIVACY_INVOKED:
		/* TODO */
		break;
	default:
		return -EOPNOTSUPP;
	}
	return 0;
}

static int iw_get_auth(struct net_device *dev,
		       struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct wrapper_dev *wd = dev->priv;

	TRACEENTER2("index=%d", wrqu->param.flags & IW_AUTH_INDEX);
	switch (wrqu->param.flags & IW_AUTH_INDEX) {
	case IW_AUTH_WPA_VERSION:
		wrqu->param.value = wd->iw_auth_wpa_version;
		break;
	case IW_AUTH_CIPHER_PAIRWISE:
		wrqu->param.value = wd->iw_auth_cipher_pairwise;
		break;
	case IW_AUTH_CIPHER_GROUP:
		wrqu->param.value = wd->iw_auth_cipher_group;
		break;
	case IW_AUTH_KEY_MGMT:
		wrqu->param.value = wd->iw_auth_key_mgmt;
		break;
	case IW_AUTH_80211_AUTH_ALG:
		wrqu->param.value = wd->iw_auth_80211_auth_alg;
		break;
	default:
		return -EOPNOTSUPP;
	}
	return 0;
}

static int iw_set_encodeext(struct net_device *dev,
			    struct iw_request_info *info,
			    union iwreq_data *wrqu, char *extra)
{
	struct iw_encode_ext *ext = (struct iw_encode_ext *) extra;
	struct wrapper_dev *wd = dev->priv;
	struct ndis_add_key ndis_key;
	int i, keyidx;
	NDIS_STATUS res;
	u8 *addr;

	TRACEENTER2("");
	keyidx = wrqu->encoding.flags & IW_ENCODE_INDEX;
	if (keyidx > 0)
		keyidx--;
	else
		keyidx = wd->encr_info.tx_key_index;

	if (keyidx < 0 || keyidx >= MAX_ENCR_KEYS)
		return -EINVAL;

	if (ext->alg == IW_ENCODE_ALG_WEP) {
		if (test_bit(Ndis802_11EncryptionDisabled, &wd->capa.encr))
			TRACEEXIT2(return -1);

		if (ext->ext_flags & IW_ENCODE_EXT_SET_TX_KEY)
			wd->encr_info.tx_key_index = keyidx;

		if (add_wep_key(wd, ext->key, ext->key_len, keyidx))
			TRACEEXIT2(return -1);
		else
			TRACEEXIT2(return 0);
	}

	if (ext->key_len > sizeof(ndis_key.key)) {
		DBGTRACE2("incorrect key length (%u)", ext->key_len);
		TRACEEXIT2(return -1);
	}
	
	memset(&ndis_key, 0, sizeof(ndis_key));

	ndis_key.struct_size = sizeof(ndis_key);
	ndis_key.length = ext->key_len;
	ndis_key.index = keyidx;

	if (ext->ext_flags & IW_ENCODE_EXT_RX_SEQ_VALID) {
		for (i = 0, ndis_key.rsc = 0 ; i < 6 ; i++)
			ndis_key.rsc |= (ext->rx_seq[i] << (i * 8));

		ndis_key.index |= 1 << 29;
	}

	addr = ext->addr.sa_data;
	DBGTRACE2("infra_mode = %d, addr = " MACSTR,
		  wd->infrastructure_mode, MAC2STR(addr));

	if (memcmp(addr, "\xff\xff\xff\xff\xff\xff", ETH_ALEN) == 0) {
		/* group key */
		if (wd->infrastructure_mode == Ndis802_11IBSS)
			memset(ndis_key.bssid, 0xff, ETH_ALEN);
		else
			get_ap_address(wd, ndis_key.bssid);
	} else {
		/* pairwise key */
		ndis_key.index |= (1 << 30);
		memcpy(&ndis_key.bssid, addr, ETH_ALEN);
	}
		
	DBGTRACE2("bssid " MACSTR, MAC2STR(ndis_key.bssid));

	if (ext->ext_flags & IW_ENCODE_EXT_SET_TX_KEY)
		ndis_key.index |= (1 << 31);

	if (ext->alg == IW_ENCODE_ALG_TKIP && ext->key_len == 32) {
		/* wpa_supplicant gives us the Michael MIC RX/TX keys in
		 * different order than NDIS spec, so swap the order here. */
		memcpy(ndis_key.key, ext->key, 16);
		memcpy(ndis_key.key + 16, ext->key + 24, 8);
		memcpy(ndis_key.key + 24, ext->key + 16, 8);
	} else
		memcpy(ndis_key.key, ext->key, ext->key_len);

	if ((wrqu->encoding.flags & IW_ENCODE_DISABLED) ||
	    ext->alg == IW_ENCODE_ALG_NONE || ext->key_len == 0) {
		/* TI driver crashes kernel if OID_802_11_REMOVE_KEY is
		 * called; other drivers seem to not require it, so
		 * for now, don't remove the key from driver */
		wd->encr_info.keys[keyidx].length = 0;
		memset(&wd->encr_info.keys[keyidx].key, 0, ext->key_len);
		DBGTRACE2("key %d removed", keyidx);
	} else {
		res = miniport_set_info(wd, OID_802_11_ADD_KEY,
					&ndis_key, sizeof(ndis_key));
		if (res == NDIS_STATUS_INVALID_DATA) {
			DBGTRACE2("adding key failed (%08X), %u",
				  res, ndis_key.struct_size);
			TRACEEXIT2(return -1);
		}
		wd->encr_info.keys[keyidx].length = ext->key_len;
		memcpy(&wd->encr_info.keys[keyidx].key,
		       &ndis_key.key, ext->key_len);
		if (ext->ext_flags & IW_ENCODE_EXT_SET_TX_KEY)
			wd->encr_info.tx_key_index = keyidx;
		DBGTRACE2("key %d added", keyidx);
	}

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

static int iw_set_pmksa(struct net_device *dev,
			struct iw_request_info *info,
			union iwreq_data *wrqu, char *extra)
{
	struct iw_pmksa *pmksa = (struct iw_pmksa *) extra;
	struct ndis_pmkid pmkid;
	NDIS_STATUS res;
	struct wrapper_dev *wd = dev->priv;

	/* TODO: must keep local list of PMKIDs since NDIS drivers
	 * expect that all PMKID entries are included whenever a new
	 * one is added. */

	TRACEENTER2("");
	memset(&pmkid, 0, sizeof(pmkid));
	if (pmksa->cmd == IW_PMKSA_ADD) {
		pmkid.bssid_info_count = 1;
		memcpy(pmkid.bssid_info[0].bssid, pmksa->bssid.sa_data,
		       ETH_ALEN);
		memcpy(pmkid.bssid_info[0].pmkid, pmksa->pmkid, IW_PMKID_LEN);
	}
	pmkid.length = 8 + pmkid.bssid_info_count *
		sizeof(struct ndis_bssid_info);

	res = miniport_set_info(wd, OID_802_11_PMKID, &pmkid,
				sizeof(pmkid));
	DBGTRACE2("OID_802_11_PMKID -> %d", res);
	if (res)
		return -EINVAL;

	return 0;
}
#endif /* WIRELESS_EXT > 17 */

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
#if WIRELESS_EXT > 17
	[SIOCSIWMLME	- SIOCIWFIRST] = iw_set_mlme,
	[SIOCSIWGENIE	- SIOCIWFIRST] = iw_set_genie,
	[SIOCSIWAUTH	- SIOCIWFIRST] = iw_set_auth,
	[SIOCGIWAUTH	- SIOCIWFIRST] = iw_get_auth,
	[SIOCSIWENCODEEXT - SIOCIWFIRST] = iw_set_encodeext,
	[SIOCGIWENCODEEXT - SIOCIWFIRST] = iw_get_encodeext,
	[SIOCSIWPMKSA	- SIOCIWFIRST] = iw_set_pmksa,
#endif /* WIRELESS_EXT > 17 */
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
	struct wrapper_dev *wd = dev->priv;
	struct miniport_char *miniport;
	ULONG profile_inf;

	miniport = &wd->driver->miniport;
	if (!miniport->pnp_event_notify)
		TRACEEXIT2(return -EOPNOTSUPP);

	/* 1 for AC and 0 for Battery */
	if (wrqu->param.value)
		profile_inf = NdisPowerProfileAcOnLine;
	else
		profile_inf = NdisPowerProfileBattery;
	
	miniport->pnp_event_notify(wd->nmb->adapter_ctx,
				   NdisDevicePnPEventPowerProfileChanged,
				   &profile_inf, sizeof(profile_inf));
	TRACEEXIT2(return 0);
}

static int priv_network_type(struct net_device *dev,
			     struct iw_request_info *info,
			     union iwreq_data *wrqu, char *extra)
{
	struct wrapper_dev *wd = dev->priv;
	enum network_type network_type;
	NDIS_STATUS res;
	char type;

	type = wrqu->param.value;
	if (type == 'f')
		network_type = Ndis802_11FH;
	else if (type == 'b')
		network_type = Ndis802_11DS;
	else if (type == 'a')
		network_type = Ndis802_11OFDM5;
	else if (type == 'g')
		network_type = Ndis802_11OFDM24;
	else
		network_type = Ndis802_11Automode;

	res = miniport_set_int(wd, OID_802_11_NETWORK_TYPE_IN_USE,
			       network_type);
	if (res == NDIS_STATUS_INVALID_DATA) {
		WARNING("setting network type to %d failed (%08X)",
			network_type, res);
		TRACEEXIT2(return -EINVAL);
	}

	TRACEEXIT2(return 0);
}

/* WPA support */

static int wpa_init(struct net_device *dev, struct iw_request_info *info,
		    union iwreq_data *wrqu, char *extra)
{
	struct wrapper_dev *wd = dev->priv;

	TRACEENTER2("");

	if (test_bit(Ndis802_11Encryption2Enabled, &wd->capa.encr) ||
	    test_bit(Ndis802_11Encryption3Enabled, &wd->capa.encr)) {
		if (set_infra_mode(wd, Ndis802_11Infrastructure))
			WARNING("couldn't enable infrastructure/managed mode");
		TRACEEXIT2(return 0);
	} else {
		WARNING("driver is not WPA capable");
		TRACEEXIT2(return -1);
	}
}

static int wpa_deinit(struct net_device *dev, struct iw_request_info *info,
		      union iwreq_data *wrqu, char *extra)
{
	TRACEENTER2("");
	TRACEEXIT2(return 0);
}

static int wpa_set_wpa(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct wrapper_dev *wd = dev->priv;
	
	TRACEENTER2("");
	DBGTRACE1("flags = %d,  wd->capa.encr = %ld",
		  wrqu->data.flags, wd->capa.encr);

	if (wrqu->data.flags) {
		if (test_bit(Ndis802_11Encryption2Enabled, &wd->capa.encr) ||
		    test_bit(Ndis802_11Encryption3Enabled, &wd->capa.encr))
			TRACEEXIT2(return 0);
		else {
			WARNING("driver is not WPA capable");
			TRACEEXIT2(return -1);
		}
	} else
		TRACEEXIT2(return 0);
}

static int wpa_set_key(struct net_device *dev, struct iw_request_info *info,
		       union iwreq_data *wrqu, char *extra)
{
	struct wrapper_dev *wd = dev->priv;
	struct ndis_add_key ndis_key;
	struct wpa_key wpa_key;
	int i, size;
	NDIS_STATUS res;
	mac_address addr;
	u8 seq[IW_ENCODING_TOKEN_MAX];
	u8 key[IW_ENCODING_TOKEN_MAX];

	if (wrqu->data.length)
		size = wrqu->data.length;
	else
		size = sizeof(wpa_key);
	if (copy_from_user(&wpa_key, wrqu->data.pointer, size))
		TRACEEXIT1(return -1);
	if (wpa_key.addr && copy_from_user(&addr, wpa_key.addr, ETH_ALEN))
		TRACEEXIT1(return -1);

	if (wpa_key.seq &&
	    copy_from_user(&seq, wpa_key.seq, wpa_key.seq_len))
		TRACEEXIT1(return -1);

	if (wpa_key.key &&
	    copy_from_user(&key, wpa_key.key, wpa_key.key_len))
		TRACEEXIT1(return -1);
	
	TRACEENTER2("alg = %d, key_index = %d",
		    wpa_key.alg, wpa_key.key_index);
	
	if (wpa_key.alg == WPA_ALG_WEP) {
		if (test_bit(Ndis802_11EncryptionDisabled, &wd->capa.encr))
			TRACEEXIT2(return -1);

		if (wpa_key.set_tx)
			wd->encr_info.tx_key_index = wpa_key.key_index;

		if (add_wep_key(wd, key, wpa_key.key_len,
				wpa_key.key_index))
			TRACEEXIT2(return -1);
		else
			TRACEEXIT2(return 0);
	}

	if (wpa_key.key_len > sizeof(ndis_key.key)) {
		DBGTRACE2("incorrect key length (%u)", (u32)wpa_key.key_len);
		TRACEEXIT2(return -1);
	}
	
	if (wpa_key.seq_len > IW_ENCODING_TOKEN_MAX) {
		DBGTRACE2("incorrect seq? length = (%u)",
			  (u32)wpa_key.seq_len);
		TRACEEXIT2(return -1);
	}

	DBGTRACE2("setting key %d, %u", wpa_key.key_index,
		  (u32)wpa_key.key_len);
	memset(&ndis_key, 0, sizeof(ndis_key));

	ndis_key.struct_size = sizeof(ndis_key);
	ndis_key.length = wpa_key.key_len;
	ndis_key.index = wpa_key.key_index;

	if (wpa_key.seq && wpa_key.seq_len > 0) {
		for (i = 0, ndis_key.rsc = 0 ; i < wpa_key.seq_len ; i++)
			ndis_key.rsc |= (seq[i] << (i * 8));

		ndis_key.index |= 1 << 29;
	}

	DBGTRACE1("infra_mode = %d, key.addr = %p, addr = " MACSTR,
		  wd->infrastructure_mode, wpa_key.addr, MAC2STR(addr));

	if (wpa_key.addr == NULL ||
	    memcmp(addr, "\xff\xff\xff\xff\xff\xff", ETH_ALEN) == 0) {
		/* group key */
		if (wd->infrastructure_mode == Ndis802_11IBSS)
			memset(ndis_key.bssid, 0xff, ETH_ALEN);
		else
			get_ap_address(wd, ndis_key.bssid);
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
		/* TI driver crashes kernel if OID_802_11_REMOVE_KEY is
		 * called; other drivers seem to not require it, so
		 * for now, don't remove the key from drvier */
		wd->encr_info.keys[wpa_key.key_index].length = 0;
		memset(&wd->encr_info.keys[wpa_key.key_index].key, 0,
		       wpa_key.key_len);
		DBGTRACE2("key %d removed", wpa_key.key_index);
	} else {
		res = miniport_set_info(wd, OID_802_11_ADD_KEY,
					&ndis_key, sizeof(ndis_key));
		if (res == NDIS_STATUS_INVALID_DATA) {
			DBGTRACE2("adding key failed (%08X), %u",
				  res, ndis_key.struct_size);
			TRACEEXIT2(return -1);
		}
		wd->encr_info.keys[wpa_key.key_index].length = 
			wpa_key.key_len;
		memcpy(&wd->encr_info.keys[wpa_key.key_index].key,
		       &ndis_key.key, wpa_key.key_len);
		if (wpa_key.set_tx)
			wd->encr_info.tx_key_index = wpa_key.key_index;
		DBGTRACE2("key %d added", wpa_key.key_index);
	}

	TRACEEXIT2(return 0);
}

static int wpa_disassociate(struct net_device *dev,
			    struct iw_request_info *info,
			    union iwreq_data *wrqu, char *extra)
{
	struct wrapper_dev *wd = dev->priv;
	unsigned char buf[NDIS_ESSID_MAX_SIZE];
	int i;
	
	TRACEENTER2("%s", "");
	get_random_bytes(buf, sizeof(buf));
	for (i = 0; i < sizeof(buf); i++)
		buf[i] = 'a' + (buf[i] % ('z' - 'a'));
	set_essid(wd, buf, sizeof(buf));
	TRACEEXIT2(return 0);
}

static int wpa_associate(struct net_device *dev, struct iw_request_info *info,
			 union iwreq_data *wrqu, char *extra)
{
	struct wrapper_dev *wd = dev->priv;
	struct wpa_assoc_info wpa_assoc_info;
	char ssid[NDIS_ESSID_MAX_SIZE];
	int auth_mode, encr_mode, priv_mode, size;
	
	TRACEENTER2("%s", "");

	if (wrqu->data.length == 0)
		size = (void *)&wpa_assoc_info.key_mgmt_suite - 
			(void *)&wpa_assoc_info.bssid;
	else {
		if (wrqu->data.length > sizeof(wpa_assoc_info))
			size = sizeof(wpa_assoc_info);
		else
			size = wrqu->data.length;
	}

	memset(&wpa_assoc_info, 0, sizeof(wpa_assoc_info));

	if (copy_from_user(&wpa_assoc_info, wrqu->data.pointer, size))
		TRACEEXIT1(return -1);
	if (copy_from_user(&ssid, wpa_assoc_info.ssid,
			   wpa_assoc_info.ssid_len))
		TRACEEXIT1(return -1);

	/* setting the mode here clears the keys set earlier, so
	 * ignore this request */
	/*
	if (wpa_assoc_info.mode == IEEE80211_MODE_IBSS)
		set_infra_mode(wd, Ndis802_11IBSS);
	else
		set_infra_mode(wd, Ndis802_11Infrastructure);
	*/

	DBGTRACE1("key_mgmt_suite = %d, pairwise_suite = %d, group_suite= %d",
		  wpa_assoc_info.key_mgmt_suite,
		  wpa_assoc_info.pairwise_suite, wpa_assoc_info.group_suite);

	if (wpa_assoc_info.wpa_ie == NULL || wpa_assoc_info.wpa_ie_len == 0) {
		if (wpa_assoc_info.auth_alg & AUTH_ALG_SHARED_KEY) {
			if (wpa_assoc_info.auth_alg & AUTH_ALG_OPEN_SYSTEM)
				auth_mode = Ndis802_11AuthModeAutoSwitch;
			else
				auth_mode = Ndis802_11AuthModeShared;
		} else
			auth_mode = Ndis802_11AuthModeOpen;
		priv_mode = Ndis802_11PrivFilterAcceptAll;
	} else if (wpa_assoc_info.wpa_ie[0] == RSN_INFO_ELEM) {
		priv_mode = Ndis802_11PrivFilter8021xWEP;
		if (wpa_assoc_info.key_mgmt_suite == KEY_MGMT_PSK)
			auth_mode = Ndis802_11AuthModeWPA2PSK;
		else
			auth_mode = Ndis802_11AuthModeWPA2;
	} else {
		priv_mode = Ndis802_11PrivFilter8021xWEP;
		if (wpa_assoc_info.key_mgmt_suite == KEY_MGMT_WPA_NONE ||
		    wpa_assoc_info.key_mgmt_suite == KEY_MGMT_802_1X_NO_WPA)
			auth_mode = Ndis802_11AuthModeWPANone;
		else if (wpa_assoc_info.key_mgmt_suite == KEY_MGMT_PSK)
			auth_mode = Ndis802_11AuthModeWPAPSK;
		else
			auth_mode = Ndis802_11AuthModeWPA;
	}

	switch (wpa_assoc_info.pairwise_suite) {
	case CIPHER_CCMP:
		encr_mode = Ndis802_11Encryption3Enabled;
		break;
	case CIPHER_TKIP:
		encr_mode = Ndis802_11Encryption2Enabled;
		break;
	case CIPHER_WEP40:
	case CIPHER_WEP104:
		encr_mode = Ndis802_11Encryption1Enabled;
		break;
	case CIPHER_NONE:
		if (wpa_assoc_info.group_suite == CIPHER_CCMP)
			encr_mode = Ndis802_11Encryption3Enabled;
		else
			encr_mode = Ndis802_11Encryption2Enabled;
		break;
	default:
		encr_mode = Ndis802_11EncryptionDisabled;
	};

	set_privacy_filter(wd, priv_mode);
	set_auth_mode(wd, auth_mode);
	set_encr_mode(wd, encr_mode);

#if 0
	/* set channel */
	for (i = 0; i < (sizeof(freq_chan)/sizeof(freq_chan[0])); i++) {
		if (wpa_assoc_info.freq == freq_chan[i]) {
			union iwreq_data freq_req;

			memset(&freq_req, 0, sizeof(freq_req));
			freq_req.freq.m = i;
			if (iw_set_freq(dev, NULL, &freq_req, NULL))
				TRACEEXIT2(return -1);
		}
	}
#endif
	/* set ssid */
	if (set_essid(wd, ssid, wpa_assoc_info.ssid_len))
		TRACEEXIT2(return -1);

	TRACEEXIT2(return 0);
}

static int wpa_set_countermeasures(struct net_device *dev,
				   struct iw_request_info *info,
				   union iwreq_data *wrqu, char *extra)
{
	TRACEENTER2("%s", "");
	return 0;
}

static int wpa_deauthenticate(struct net_device *dev,
			      struct iw_request_info *info,
			      union iwreq_data *wrqu, char *extra)
{
	int ret;
	
	TRACEENTER2("%s", "");
	ret = wpa_disassociate(dev, info, wrqu, extra);
	TRACEEXIT2(return ret);
}

int set_privacy_filter(struct wrapper_dev *wd, int flags)
{
	NDIS_STATUS res;

	TRACEENTER2("filter: %d", flags);
	res = miniport_set_int(wd, OID_802_11_PRIVACY_FILTER, flags);
	if (res == NDIS_STATUS_INVALID_DATA) {
		WARNING("setting privacy filter to %d failed (%08X)",
			flags, res);
		TRACEEXIT2(return -EINVAL);
	}
	TRACEEXIT2(return 0);
}

static int wpa_set_privacy_filter(struct net_device *dev,
				  struct iw_request_info *info,
				  union iwreq_data *wrqu, char *extra)
{
	struct wrapper_dev *wd = dev->priv;
	int flags;

	TRACEENTER2("filter: %d", wrqu->param.value);
	if (wrqu->param.value)
		flags = Ndis802_11PrivFilter8021xWEP;
	else
		flags = Ndis802_11PrivFilterAcceptAll;
	if (set_privacy_filter(wd, flags))
		TRACEEXIT2(return -1);
	TRACEEXIT2(return 0);
}

static int wpa_set_auth_alg(struct net_device *dev,
			    struct iw_request_info *info,
			    union iwreq_data *wrqu, char *extra)
{
	struct wrapper_dev *wd = dev->priv;
	int mode;
	
	if (wrqu->param.value & AUTH_ALG_SHARED_KEY)
		mode = Ndis802_11AuthModeShared;
	else if (wrqu->param.value & AUTH_ALG_OPEN_SYSTEM)
		mode = Ndis802_11AuthModeOpen;
	else
		TRACEEXIT2(return -1);

	DBGTRACE2("%d", mode);

	if (set_auth_mode(wd, mode))
		TRACEEXIT2(return -1);
	TRACEEXIT2(return 0);
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
	 "countermeasures"},
	{WPA_DEAUTHENTICATE, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0,
	 "deauthenticate"},
	{WPA_SET_AUTH_ALG, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0,
	 "auth_alg"},

	{PRIV_RESET, 0, 0, "ndis_reset"},
	{PRIV_POWER_PROFILE, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0,
	 "power_profile"},
	{PRIV_NETWORK_TYPE, IW_PRIV_TYPE_CHAR | IW_PRIV_SIZE_FIXED | 1, 0,
	 "network_type"},
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
	[WPA_INIT 		- SIOCIWFIRSTPRIV] = wpa_init,
	[WPA_DEINIT 		- SIOCIWFIRSTPRIV] = wpa_deinit,

	[PRIV_RESET 		- SIOCIWFIRSTPRIV] = priv_reset,
	[PRIV_POWER_PROFILE 	- SIOCIWFIRSTPRIV] = priv_power_profile,
	[PRIV_NETWORK_TYPE 	- SIOCIWFIRSTPRIV] = priv_network_type,
};

const struct iw_handler_def ndis_handler_def = {
	.num_standard	= sizeof(ndis_handler) / sizeof(ndis_handler[0]),
	.num_private	= sizeof(priv_handler) / sizeof(priv_handler[0]),
	.num_private_args = sizeof(priv_args) / sizeof(priv_args[0]),

	.standard	= (iw_handler *)ndis_handler,
	.private	= (iw_handler *)priv_handler,
	.private_args	= (struct iw_priv_args *)priv_args,
};
