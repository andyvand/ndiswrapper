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

struct ndis_wpa_key
{
	unsigned long struct_size;
	unsigned long index;
	unsigned long length;
	mac_address bssid;
	unsigned char pad[6];
	unsigned long long rsc;
	unsigned char key[NDIS_ENCODING_TOKEN_MAX];
};

struct ndis_remove_key
{
	unsigned long struct_size;
	unsigned long index;
	mac_address bssid;
};

struct ndis_fixed_ies
{
	unsigned char time_stamp[8];
	unsigned short beacon_interval;
	unsigned short capa;
};

struct ndis_variable_ies
{
	unsigned char elem_id;
	unsigned char length;
	unsigned char data[1];
};

struct ndis_assoc_info
{
	unsigned long length;
	unsigned short req_ies;
	struct req_ie {
		unsigned short capa;
		unsigned short listen_interval;
		mac_address cur_ap_address;
	} req_ie;
	unsigned long req_ie_length;
	unsigned long offset_req_ies;
	unsigned short resp_ies;
	struct resp_ie {
		unsigned short capa;
		unsigned short status_code;
		unsigned short assoc_id;
	} resp_ie;
	unsigned long resp_ie_length;
	unsigned long offset_resp_ies;
};

struct packed ndis_configuration
{
	__u32 length;
	__u32 beacon_period;
	__u32 atim_window;
	__u32 ds_config;
	struct ndis_configuration_fh
	{
		__u32 length;
		__u32 hop_pattern;
		__u32 hop_set;
		__u32 dwell_time;
	} fh_config;
};

struct ndis_ssid_item
{
	unsigned long length;
	mac_address mac;
	unsigned char reserved[2];
	struct ndis_essid ssid;
	unsigned long privacy;
	long rssi;
	unsigned int net_type;
	struct ndis_configuration config;
	unsigned int mode;
	unsigned char rates[NDIS_MAX_RATES_EX];
	unsigned long ie_length;
	unsigned char ies[1];
};

struct ndis_bssid_list
{
	unsigned long num_items;
	struct ndis_ssid_item items[1];
};

enum ndis_priv_filter
{
	NDIS_PRIV_ACCEPT_ALL,
	NDIS_PRIV_WEP,
};

enum ndis_power
{
	NDIS_POWER_OFF = 0,
	NDIS_POWER_MAX,
	NDIS_POWER_MIN,
};

enum ndis_power_profile
{
	NDIS_POWER_PROFILE_BATTERY,
	NDIS_POWER_PROFILE_AC,
};

enum ndis_status_type
{
	NDIS_STATUS_AUTHENTICATION,
	NDIS_STATUS_MAX,
};

struct ndis_status_indication
{
	enum ndis_status_type status_type;
};

struct ndis_auth_req
{
	unsigned long length;
	mac_address bssid;
	unsigned long flags;
};

int add_wep_key(struct ndis_handle *handle, char *key, int key_len, int index);
extern const struct iw_handler_def ndis_handler_def;

int set_essid(struct ndis_handle *handle, const char *ssid, int ssid_len);
int set_mode(struct ndis_handle *handle, enum op_mode mode);
struct iw_statistics *get_wireless_stats(struct net_device *dev);
int get_ap_address(struct ndis_handle *handle, mac_address mac);
int set_auth_mode(struct ndis_handle *handle, int auth_mode);
int set_encr_mode(struct ndis_handle *handle, int encr_mode);
int set_privacy_filter(struct ndis_handle *handle, int flags);


/* WPA support */

enum capa_list
{
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
