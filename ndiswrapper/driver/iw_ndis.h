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
#ifndef IW_NDIS_H
#define IW_NDIS_H

#include "ndis.h"

struct ndis_wpa_key {
	ULONG struct_size;
	ULONG index;
	ULONG length;
	mac_address bssid;
	UCHAR pad[6];
	ULONGLONG rsc;
	UCHAR key[NDIS_ENCODING_TOKEN_MAX];
};

struct ndis_remove_key {
	ULONG struct_size;
	ULONG index;
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

struct packed ndis_configuration {
	ULONG length;
	ULONG beacon_period;
	ULONG atim_window;
	ULONG ds_config;
	struct ndis_configuration_fh {
		ULONG length;
		ULONG hop_pattern;
		ULONG hop_set;
		ULONG dwell_time;
	} fh_config;
};

struct ndis_ssid_item {
	ULONG length;
	mac_address mac;
	UCHAR reserved[2];
	struct ndis_essid ssid;
	ULONG privacy;
	LONG rssi;
	UINT net_type;
	struct ndis_configuration config;
	UINT mode;
	UCHAR rates[NDIS_MAX_RATES_EX];
	ULONG ie_length;
	UCHAR ies[1];
};

struct ndis_bssid_list {
	ULONG num_items;
	struct ndis_ssid_item items[1];
};

enum ndis_priv_filter {
	NDIS_PRIV_ACCEPT_ALL,
	NDIS_PRIV_WEP,
};

enum ndis_power {
	NDIS_POWER_OFF = 0,
	NDIS_POWER_MAX,
	NDIS_POWER_MIN,
};

enum ndis_power_profile {
	NDIS_POWER_PROFILE_BATTERY,
	NDIS_POWER_PROFILE_AC,
};

enum ndis_status_type {
	NDIS_STATUS_AUTHENTICATION,
	NDIS_STATUS_MAX,
};

struct ndis_status_indication
{
	enum ndis_status_type status_type;
};

struct ndis_auth_req {
	ULONG length;
	mac_address bssid;
	ULONG flags;
};

int add_wep_key(struct ndis_handle *handle, char *key, int key_len, int index);
extern const struct iw_handler_def ndis_handler_def;

int set_essid(struct ndis_handle *handle, const char *ssid, int ssid_len);
int set_mode(struct ndis_handle *handle, enum op_mode mode);
int get_ap_address(struct ndis_handle *handle, mac_address mac);
int set_auth_mode(struct ndis_handle *handle, int auth_mode);
int set_encr_mode(struct ndis_handle *handle, int encr_mode);
int set_privacy_filter(struct ndis_handle *handle, int flags);


/* WPA support */

enum capa_list {
	CAPA_ENCR1 = ENCR1_ENABLED,
	CAPA_WEP = ENCR1_ENABLED,
	CAPA_ENCR_NONE = ENCR_DISABLED,
	CAPA_TKIP = ENCR2_ENABLED,
	CAPA_AES = ENCR3_ENABLED,
	CAPA_WPA,
};

#define PRIV_RESET	 		SIOCIWFIRSTPRIV+16
#define PRIV_POWER_PROFILE	 	SIOCIWFIRSTPRIV+17

/* these have to match what is in wpa_supplicant */
typedef enum { WPA_ALG_NONE, WPA_ALG_WEP, WPA_ALG_TKIP, WPA_ALG_CCMP } wpa_alg;
typedef enum { CIPHER_NONE, CIPHER_WEP40, CIPHER_TKIP, CIPHER_CCMP,
	       CIPHER_WEP104 } wpa_cipher;
typedef enum { KEY_MGMT_802_1X, KEY_MGMT_PSK, KEY_MGMT_NONE } wpa_key_mgmt;

#define AUTH_ALG_OPEN_SYSTEM	0x01
#define AUTH_ALG_SHARED_KEY	0x02
#define AUTH_ALG_LEAP		0x04

struct wpa_key
{
	wpa_alg alg;
	u8 *addr;
	int key_index;
	int set_tx;
	u8 *seq;
	size_t seq_len;
	u8 *key;
	size_t key_len;
};

struct wpa_assoc_info
{
	const char *bssid;
	const char *ssid;
	size_t ssid_len;
	int freq;
	const char *wpa_ie;
	size_t wpa_ie_len;
	wpa_cipher pairwise_suite;
	wpa_cipher group_suite;
	wpa_key_mgmt key_mgmt_suite;
	int auth_alg;
};

#define WPA_SET_WPA 			SIOCIWFIRSTPRIV+1
#define WPA_SET_KEY 			SIOCIWFIRSTPRIV+2
#define WPA_ASSOCIATE		 	SIOCIWFIRSTPRIV+3
#define WPA_DISASSOCIATE 		SIOCIWFIRSTPRIV+4
#define WPA_DROP_UNENCRYPTED 		SIOCIWFIRSTPRIV+5
#define WPA_SET_COUNTERMEASURES 	SIOCIWFIRSTPRIV+6
#define WPA_DEAUTHENTICATE	 	SIOCIWFIRSTPRIV+7
#define WPA_SET_AUTH_ALG	 	SIOCIWFIRSTPRIV+8

#endif // IW_NDIS_H
