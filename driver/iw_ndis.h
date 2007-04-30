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

#ifndef _IW_NDIS_H_
#define _IW_NDIS_H_

#include "ndis.h"

#define	WL_NOISE	-96	/* typical noise level in dBm */
#define	WL_SIGMAX	-32	/* typical maximum signal level in dBm */

struct ndis_encr_key {
	ULONG struct_size;
	ULONG index;
	ULONG length;
	UCHAR key[NDIS_ENCODING_TOKEN_MAX];
};

struct ndis_add_key {
	ULONG struct_size;
	ndis_key_index index;
	ULONG length;
	mac_address bssid;
	UCHAR pad[6];
	ndis_key_rsc rsc;
	UCHAR key[NDIS_ENCODING_TOKEN_MAX];
};

struct ndis_remove_key {
	ULONG struct_size;
	ndis_key_index index;
	mac_address bssid;
};

struct ndis_fixed_ies {
	UCHAR time_stamp[8];
	USHORT beacon_interval;
	USHORT capa;
};

struct ndis_variable_ies {
	ULONG elem_id;
	UCHAR length;
	UCHAR data[1];
};

enum ndis_reload_defaults { Ndis802_11ReloadWEPKeys };

struct ndis_assoc_info {
	ULONG length;
	USHORT req_ies;
	struct req_ie {
		USHORT capa;
		USHORT listen_interval;
		mac_address cur_ap_address;
	} req_ie;
	ULONG req_ie_length;
	ULONG offset_req_ies;
	USHORT resp_ies;
	struct resp_ie {
		USHORT capa;
		USHORT status_code;
		USHORT assoc_id;
	} resp_ie;
	ULONG resp_ie_length;
	ULONG offset_resp_ies;
};

struct ndis_configuration_fh {
	ULONG length;
	ULONG hop_pattern;
	ULONG hop_set;
	ULONG dwell_time;
};

struct ndis_configuration {
	ULONG length;
	ULONG beacon_period;
	ULONG atim_window;
	ULONG ds_config;
	struct ndis_configuration_fh fh_config;
};

struct ndis_wlan_bssid {
	ULONG length;
	mac_address mac;
	UCHAR reserved[2];
	struct ndis_essid ssid;
	ULONG privacy;
	ndis_rssi rssi;
	UINT net_type;
	struct ndis_configuration config;
	UINT mode;
	ndis_rates rates;
};

struct ndis_wlan_bssid_ex {
	ULONG length;
	mac_address mac;
	UCHAR reserved[2];
	struct ndis_essid ssid;
	ULONG privacy;
	ndis_rssi rssi;
	UINT net_type;
	struct ndis_configuration config;
	UINT mode;
	ndis_rates_ex rates_ex;
	ULONG ie_length;
	UCHAR ies[1];
};

/* we use bssid_list as bssid_list_ex also */
struct ndis_bssid_list {
	ULONG num_items;
	struct ndis_wlan_bssid bssid[1];
};

enum ndis_priv_filter {
	Ndis802_11PrivFilterAcceptAll, Ndis802_11PrivFilter8021xWEP
};

enum network_type {
	Ndis802_11FH, Ndis802_11DS, Ndis802_11OFDM5, Ndis802_11OFDM24,
	/* MSDN site uses Ndis802_11Automode, which is not mentioned
	 * in DDK, so add one and assign it to
	 * Ndis802_11NetworkTypeMax */
	Ndis802_11Automode, Ndis802_11NetworkTypeMax = Ndis802_11Automode
};

struct network_type_list {
	ULONG num;
	enum network_type types[1];
};

enum ndis_power {
	NDIS_POWER_OFF = 0, NDIS_POWER_MAX, NDIS_POWER_MIN,
};

struct ndis_auth_req {
	ULONG length;
	mac_address bssid;
	ULONG flags;
};

struct ndis_bssid_info {
	mac_address bssid;
	UCHAR pmkid[16];
};

struct ndis_pmkid {
	ULONG length;
	ULONG bssid_info_count;
	struct ndis_bssid_info bssid_info[1];
};

int add_wep_key(struct wrap_ndis_device *wnd, char *key, int key_len,
		int index);
int set_essid(struct wrap_ndis_device *wnd, const char *ssid, int ssid_len);
int set_infra_mode(struct wrap_ndis_device *wnd,
		   enum network_infrastructure mode);
int get_ap_address(struct wrap_ndis_device *wnd, mac_address mac);
int set_auth_mode(struct wrap_ndis_device *wnd, ULONG auth_mode);
int set_encr_mode(struct wrap_ndis_device *wnd, ULONG encr_mode);
int get_auth_mode(struct wrap_ndis_device *wnd);
int get_encr_mode(struct wrap_ndis_device *wnd);
int set_priv_filter(struct wrap_ndis_device *wnd, int flags);
int set_scan(struct wrap_ndis_device *wnd);
NDIS_STATUS disassociate(struct wrap_ndis_device *wnd, int reset_ssid);

#define PRIV_RESET	 		SIOCIWFIRSTPRIV+16
#define PRIV_POWER_PROFILE	 	SIOCIWFIRSTPRIV+17
#define PRIV_NETWORK_TYPE	 	SIOCIWFIRSTPRIV+18
#define PRIV_USB_RESET	 		SIOCIWFIRSTPRIV+19
#define PRIV_MEDIA_STREAM_MODE 		SIOCIWFIRSTPRIV+20
#define PRIV_SET_ENCR_MODE		SIOCIWFIRSTPRIV+21
#define PRIV_SET_AUTH_MODE		SIOCIWFIRSTPRIV+22
#define PRIV_RELOAD_DEFAULTS		SIOCIWFIRSTPRIV+23

#define RSN_INFO_ELEM		0x30

/* these have to match what is in wpa_supplicant */

typedef enum { WPA_ALG_NONE, WPA_ALG_WEP, WPA_ALG_TKIP, WPA_ALG_CCMP } wpa_alg;
typedef enum { CIPHER_NONE, CIPHER_WEP40, CIPHER_TKIP, CIPHER_CCMP,
	       CIPHER_WEP104 } wpa_cipher;
typedef enum { KEY_MGMT_802_1X, KEY_MGMT_PSK, KEY_MGMT_NONE,
	       KEY_MGMT_802_1X_NO_WPA, KEY_MGMT_WPA_NONE } wpa_key_mgmt;

#if WIRELESS_EXT <= 17
/* WPA support through 'ndiswrapper' driver interface */

#define AUTH_ALG_OPEN_SYSTEM	0x01
#define AUTH_ALG_SHARED_KEY	0x02
#define AUTH_ALG_LEAP		0x04

#define IEEE80211_MODE_INFRA	0
#define IEEE80211_MODE_IBSS	1

struct wpa_key {
	wpa_alg alg;
	u8 *addr;
	int key_index;
	int set_tx;
	u8 *seq;
	size_t seq_len;
	u8 *key;
	size_t key_len;
};

struct wpa_assoc_info {
	const u8 *bssid;
	const u8 *ssid;
	size_t ssid_len;
	int freq;
	const u8 *wpa_ie;
	size_t wpa_ie_len;
	wpa_cipher pairwise_suite;
	wpa_cipher group_suite;
	wpa_key_mgmt key_mgmt_suite;
	int auth_alg;
	int mode;
};

struct wpa_driver_capa {
#define WPA_DRIVER_CAPA_KEY_MGMT_WPA        0x00000001
#define WPA_DRIVER_CAPA_KEY_MGMT_WPA2       0x00000002
#define WPA_DRIVER_CAPA_KEY_MGMT_WPA_PSK    0x00000004
#define WPA_DRIVER_CAPA_KEY_MGMT_WPA2_PSK   0x00000008
#define WPA_DRIVER_CAPA_KEY_MGMT_WPA_NONE   0x00000010
	unsigned int key_mgmt;

#define WPA_DRIVER_CAPA_ENC_WEP40   0x00000001
#define WPA_DRIVER_CAPA_ENC_WEP104  0x00000002
#define WPA_DRIVER_CAPA_ENC_TKIP    0x00000004
#define WPA_DRIVER_CAPA_ENC_CCMP    0x00000008
	unsigned int enc;

#define WPA_DRIVER_AUTH_OPEN        0x00000001
#define WPA_DRIVER_AUTH_SHARED      0x00000002
#define WPA_DRIVER_AUTH_LEAP        0x00000004
	unsigned int auth;

/* Driver generated WPA/RSN IE */
#define WPA_DRIVER_FLAGS_DRIVER_IE  0x00000001
#define WPA_DRIVER_FLAGS_SET_KEYS_AFTER_ASSOC 0x00000002
	unsigned int flags;
};

#define WPA_SET_WPA 			SIOCIWFIRSTPRIV+1
#define WPA_SET_KEY 			SIOCIWFIRSTPRIV+2
#define WPA_ASSOCIATE		 	SIOCIWFIRSTPRIV+3
#define WPA_DISASSOCIATE 		SIOCIWFIRSTPRIV+4
#define WPA_DROP_UNENCRYPTED 		SIOCIWFIRSTPRIV+5
#define WPA_SET_COUNTERMEASURES 	SIOCIWFIRSTPRIV+6
#define WPA_DEAUTHENTICATE	 	SIOCIWFIRSTPRIV+7
#define WPA_SET_AUTH_ALG	 	SIOCIWFIRSTPRIV+8
#define WPA_INIT			SIOCIWFIRSTPRIV+9
#define WPA_DEINIT			SIOCIWFIRSTPRIV+10
#define WPA_GET_CAPA			SIOCIWFIRSTPRIV+11

#endif

#endif // IW_NDIS_H
