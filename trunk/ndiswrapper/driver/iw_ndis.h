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

#define NDIS_OID_STAT_TX_OK         0x00020101
#define NDIS_OID_STAT_RX_OK         0x00020102
#define NDIS_OID_STAT_TX_ERROR      0x00020103
#define NDIS_OID_STAT_RX_ERROR      0x00020104

#define OID_802_3_MULTICAST_LIST    0x01010103
#define OID_802_3_MAXIMUM_LIST_SIZE 0x01010104

#define NDIS_OID_ESSID              0x0D010102
#define NDIS_OID_BSSID              0x0D010101
#define NDIS_OID_MODE               0x0D010108
#define NDIS_OID_RSSI               0x0D010206
#define NDIS_OID_RSSI_TRIGGER       0x0D010207
#define NDIS_OID_CONFIGURATION      0x0D010211
#define NDIS_OID_TX_POWER_LEVEL     0x0D010205
#define NDIS_OID_RTS_THRESH         0x0D01020A
#define NDIS_OID_FRAG_THRESH        0x0D010209
#define NDIS_OID_PACKET_FILTER      0x0001010E
#define NDIS_OID_ADD_WEP            0x0D010113
#define NDIS_OID_REMOVE_WEP         0x0D010114
#define NDIS_OID_ENCR_STATUS        0x0D01011B
#define NDIS_OID_AUTH_MODE          0x0D010118
#define NDIS_OID_PRIVACY_FILTER     0x0D010119
#define NDIS_OID_NETWORK_TYPE_IN_USE 0x0D010204
#define NDIS_OID_BSSID_LIST_SCAN    0x0D01011A
#define NDIS_OID_BSSID_LIST         0x0D010217
#define NDIS_OID_POWER_MODE         0x0D010216
#define NDIS_OID_DISASSOCIATE       0x0D010115
#define NDIS_OID_STATISTICS         0x0D020212
#define NDIS_OID_SUPPORTED_RATES    0x0D01020E
#define NDIS_OID_DESIRED_RATES      0x0D010210
#define NDIS_OID_ADD_KEY            0x0D01011D
#define NDIS_OID_REMOVE_KEY         0x0D01011E
#define NDIS_OID_ASSOC_INFO         0x0D01011F
#define NDIS_OID_TEST               0x0D010120

#define NDIS_OID_NUM_ANTENNA        0x0D01020B
#define NDIS_OID_RX_ANTENNA         0x0D01020C
#define NDIS_OID_TX_ANTENNA         0x0D01020D

/* general OIDs */
#define NDIS_OID_GEN_SPEED          0x00010107
#define OID_GEN_PHYSICAL_MEDIUM     0x00010202
#define OID_GEN_MEDIA_SUPPORTED                 0x00010103
#define OID_GEN_MEDIA_IN_USE                    0x00010104
#define OID_802_3_CURRENT_ADDRESS		0x01010102

#define NDIS_OID_PNP_SET_POWER      0xFD010101
#define NDIS_OID_PNP_QUERY_POWER    0xFD010102
#define NDIS_OID_CURRENT_MAC_ADDRESS 0x01010102

#define NDIS_STATUS_SUCCESS		0
#define NDIS_STATUS_PENDING		0x00000103
#define NDIS_STATUS_NOT_RECOGNIZED	0x00010001
#define NDIS_STATUS_NOT_COPIED		0x00010002
#define NDIS_STATUS_NOT_ACCEPTED	0x00010003
#define NDIS_STATUS_CALL_ACTIVE		0x00010007
#define NDIS_STATUS_ONLINE		0x40010003
#define NDIS_STATUS_RESET_START		0x40010004
#define NDIS_STATUS_RESET_END		0x40010005
#define NDIS_STATUS_RING_STATUS		0x40010006
#define NDIS_STATUS_CLOSED		0x40010007
#define NDIS_STATUS_WAN_LINE_UP		0x40010008
#define NDIS_STATUS_WAN_LINE_DOWN	0x40010009
#define NDIS_STATUS_WAN_FRAGMENT	0x4001000A
#define NDIS_STATUS_MEDIA_CONNECT	0x4001000B
#define NDIS_STATUS_MEDIA_DISCONNECT	0x4001000C
#define NDIS_STATUS_HARDWARE_LINE_UP	0x4001000D
#define NDIS_STATUS_HARDWARE_LINE_DOWN	0x4001000E
#define NDIS_STATUS_INTERFACE_UP	0x4001000F
#define NDIS_STATUS_INTERFACE_DOWN	0x40010010
#define NDIS_STATUS_MEDIA_BUSY		0x40010011
#define NDIS_STATUS_MEDIA_SPECIFIC_INDICATION	0x40010012
#define NDIS_STATUS_WW_INDICATION NDIS_STATUS_MEDIA_SPECIFIC_INDICATION
#define NDIS_STATUS_LINK_SPEED_CHANGE	0x40010013
#define NDIS_STATUS_WAN_GET_STATS	0x40010014
#define NDIS_STATUS_WAN_CO_FRAGMENT	0x40010015
#define NDIS_STATUS_WAN_CO_LINKPARAMS	0x40010016
#define NDIS_STATUS_NOT_RESETTABLE	0x80010001
#define NDIS_STATUS_SOFT_ERRORS		0x80010003
#define NDIS_STATUS_HARD_ERRORS		0x80010004
#define NDIS_STATUS_BUFFER_OVERFLOW	0x80000005
#define NDIS_STATUS_FAILURE		0xC0000001
#define NDIS_STATUS_INVALID_PARAMETER 0xC000000D
#define NDIS_STATUS_RESOURCES		0xC000009A
#define NDIS_STATUS_CLOSING		0xC0010002
#define NDIS_STATUS_BAD_VERSION		0xC0010004
#define NDIS_STATUS_BAD_CHARACTERISTICS	0xC0010005
#define NDIS_STATUS_ADAPTER_NOT_FOUND	0xC0010006
#define NDIS_STATUS_OPEN_FAILED		0xC0010007
#define NDIS_STATUS_DEVICE_FAILED	0xC0010008
#define NDIS_STATUS_MULTICAST_FULL	0xC0010009
#define NDIS_STATUS_MULTICAST_EXISTS	0xC001000A
#define NDIS_STATUS_MULTICAST_NOT_FOUND	0xC001000B
#define NDIS_STATUS_REQUEST_ABORTED	0xC001000C
#define NDIS_STATUS_RESET_IN_PROGRESS	0xC001000D
#define NDIS_STATUS_CLOSING_INDICATING	0xC001000E
#define NDIS_STATUS_BAD_VERSION		0xC0010004
#define NDIS_STATUS_NOT_SUPPORTED	0xC00000BB
#define NDIS_STATUS_INVALID_PACKET	0xC001000F
#define NDIS_STATUS_OPEN_LIST_FULL	0xC0010010
#define NDIS_STATUS_ADAPTER_NOT_READY	0xC0010011
#define NDIS_STATUS_ADAPTER_NOT_OPEN	0xC0010012
#define NDIS_STATUS_NOT_INDICATING	0xC0010013
#define NDIS_STATUS_INVALID_LENGTH	0xC0010014
#define NDIS_STATUS_INVALID_DATA	0xC0010015
#define NDIS_STATUS_BUFFER_TOO_SHORT	0xC0010016
#define NDIS_STATUS_INVALID_OID		0xC0010017
#define NDIS_STATUS_ADAPTER_REMOVED	0xC0010018
#define NDIS_STATUS_UNSUPPORTED_MEDIA	0xC0010019
#define NDIS_STATUS_GROUP_ADDRESS_IN_USE	0xC001001A
#define NDIS_STATUS_FILE_NOT_FOUND	0xC001001B
#define NDIS_STATUS_ERROR_READING_FILE	0xC001001C
#define NDIS_STATUS_ALREADY_MAPPED	0xC001001D
#define NDIS_STATUS_RESOURCE_CONFLICT	0xC001001E
#define NDIS_STATUS_NO_CABLE		0xC001001F
#define NDIS_STATUS_INVALID_SAP		0xC0010020
#define NDIS_STATUS_SAP_IN_USE		0xC0010021
#define NDIS_STATUS_INVALID_ADDRESS	0xC0010022
#define NDIS_STATUS_VC_NOT_ACTIVATED	0xC0010023
#define NDIS_STATUS_DEST_OUT_OF_ORDER	0xC0010024
#define NDIS_STATUS_VC_NOT_AVAILABLE	0xC0010025
#define NDIS_STATUS_CELLRATE_NOT_AVAILABLE	0xC0010026
#define NDIS_STATUS_INCOMPATABLE_QOS	0xC0010027
#define NDIS_STATUS_AAL_PARAMS_UNSUPPORTED	0xC0010028
#define NDIS_STATUS_NO_ROUTE_TO_DESTINATION	0xC0010029
#define NDIS_STATUS_TOKEN_RING_OPEN_ERROR	0xC0011000
#define NDIS_STATUS_INVALID_DEVICE_REQUEST	0xC0000010
#define NDIS_STATUS_NETWORK_UNREACHABLE         0xC000023C

/* Event codes */

#define EVENT_NDIS_RESOURCE_CONFLICT	0xC0001388
#define EVENT_NDIS_OUT_OF_RESOURCE	0xC0001389
#define EVENT_NDIS_HARDWARE_FAILURE	0xC000138A
#define EVENT_NDIS_ADAPTER_NOT_FOUND	0xC000138B
#define EVENT_NDIS_INTERRUPT_CONNECT	0xC000138C
#define EVENT_NDIS_DRIVER_FAILURE	0xC000138D
#define EVENT_NDIS_BAD_VERSION		0xC000138E
#define EVENT_NDIS_TIMEOUT		0x8000138F
#define EVENT_NDIS_NETWORK_ADDRESS	0xC0001390
#define EVENT_NDIS_UNSUPPORTED_CONFIGURATION	0xC0001391
#define EVENT_NDIS_INVALID_VALUE_FROM_ADAPTER	0xC0001392
#define EVENT_NDIS_MISSING_CONFIGURATION_PARAMETER	0xC0001393
#define EVENT_NDIS_BAD_IO_BASE_ADDRESS	0xC0001394
#define EVENT_NDIS_RECEIVE_SPACE_SMALL	0x40001395
#define EVENT_NDIS_ADAPTER_DISABLED	0x80001396
#define EVENT_NDIS_IO_PORT_CONFLICT	0x80001397
#define EVENT_NDIS_PORT_OR_DMA_CONFLICT	0x80001398
#define EVENT_NDIS_MEMORY_CONFLICT	0x80001399
#define EVENT_NDIS_INTERRUPT_CONFLICT	0x8000139A
#define EVENT_NDIS_DMA_CONFLICT		0x8000139B
#define EVENT_NDIS_INVALID_DOWNLOAD_FILE_ERROR	0xC000139C
#define EVENT_NDIS_MAXRECEIVES_ERROR	0x8000139D
#define EVENT_NDIS_MAXTRANSMITS_ERROR	0x8000139E
#define EVENT_NDIS_MAXFRAMESIZE_ERROR	0x8000139F
#define EVENT_NDIS_MAXINTERNALBUFS_ERROR	0x800013A0
#define EVENT_NDIS_MAXMULTICAST_ERROR	0x800013A1
#define EVENT_NDIS_PRODUCTID_ERROR	0x800013A2
#define EVENT_NDIS_LOBE_FAILUE_ERROR	0x800013A3
#define EVENT_NDIS_SIGNAL_LOSS_ERROR	0x800013A4
#define EVENT_NDIS_REMOVE_RECEIVED_ERROR	0x800013A5
#define EVENT_NDIS_TOKEN_RING_CORRECTION	0x400013A6
#define EVENT_NDIS_ADAPTER_CHECK_ERROR	0xC00013A7
#define EVENT_NDIS_RESET_FAILURE_ERROR	0x800013A8
#define EVENT_NDIS_CABLE_DISCONNECTED_ERROR	0x800013A9
#define EVENT_NDIS_RESET_FAILURE_CORRECTION	0x800013AA

/* packet filter bits used by NDIS_OID_PACKET_FILTER */
#define NDIS_PACKET_TYPE_DIRECTED               0x00000001
#define NDIS_PACKET_TYPE_MULTICAST              0x00000002
#define NDIS_PACKET_TYPE_ALL_MULTICAST          0x00000004
#define NDIS_PACKET_TYPE_BROADCAST              0x00000008
#define NDIS_PACKET_TYPE_SOURCE_ROUTING         0x00000010
#define NDIS_PACKET_TYPE_PROMISCUOUS            0x00000020
#define NDIS_PACKET_TYPE_SMT                    0x00000040
#define NDIS_PACKET_TYPE_ALL_LOCAL              0x00000080
#define NDIS_PACKET_TYPE_GROUP                  0x00001000
#define NDIS_PACKET_TYPE_ALL_FUNCTIONAL         0x00002000
#define NDIS_PACKET_TYPE_FUNCTIONAL             0x00004000
#define NDIS_PACKET_TYPE_MAC_FRAME              0x00008000

/* memory allocation flags */
#define NDIS_MEMORY_CONTIGUOUS			0x00000001
#define NDIS_MEMORY_NONCACHED			0x00000002

/* Atrribute flags to NdisMSetAtrributesEx */
#define NDIS_ATTRIBUTE_IGNORE_PACKET_TIMEOUT    0x00000001
#define NDIS_ATTRIBUTE_IGNORE_REQUEST_TIMEOUT   0x00000002
#define NDIS_ATTRIBUTE_IGNORE_TOKEN_RING_ERRORS 0x00000004
#define NDIS_ATTRIBUTE_BUS_MASTER               0x00000008
#define NDIS_ATTRIBUTE_INTERMEDIATE_DRIVER      0x00000010
#define NDIS_ATTRIBUTE_DESERIALIZE              0x00000020
#define NDIS_ATTRIBUTE_NO_HALT_ON_SUSPEND       0x00000040
#define NDIS_ATTRIBUTE_SURPRISE_REMOVE_OK       0x00000080
#define NDIS_ATTRIBUTE_NOT_CO_NDIS              0x00000100
#define NDIS_ATTRIBUTE_USES_SAFE_BUFFER_APIS    0x00000200


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
