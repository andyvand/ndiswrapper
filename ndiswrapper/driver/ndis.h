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
#ifndef NDIS_H
#define NDIS_H

#include "ntoskernel.h"
#include "wrapper.h"

struct packed ndis_scatterentry
{
	unsigned int physlo;
	unsigned int physhi;
	unsigned int len;
	unsigned int reserved;
};

struct packed ndis_scatterlist
{
	unsigned int len;
	unsigned int reserved;
	struct ndis_scatterentry entry;
};

struct packed ndis_phy_address
{
	__u32 low;
	__u32 high;
};

struct ndis_phy_addr_unit {
    struct ndis_phy_address phy_addr;
    unsigned int length;
};

struct ndis_buffer
{
	struct ndis_buffer *next;
	unsigned int len;
	unsigned int offset;
	unsigned char *data;
};


struct packed ndis_packet
{
	unsigned int nr_pages;

	/* 4: Packet length */
	unsigned int len;

	struct ndis_buffer *buffer_head;
	struct ndis_buffer *buffer_tail;
	void *pool;

	/* 14 Number of buffers */
	unsigned int count;

	unsigned int flags;

	/* 1 If buffer count is valid? */
	__u8 valid_counts;
	__u8 packet_flags;
	__u16 oob_offset;

	/* For use by miniport */
	unsigned char private_1 [6*sizeof(void*)];
	unsigned char private_2[4];

	/* OOB data */
	__u32 timesent1;
	__u32 timesent2;
	__u32 timerec1;
	__u32 timerec2;
	unsigned int header_size;
	unsigned int mediaspecific_size;
	void *mediaspecific;
	unsigned int status;

	void *ext1;
	void *ext2;
	void *ext3;
	void *ext4;
	void *ext5;
	struct ndis_scatterlist *scatter_gather_ext;
	void *ext7;
	void *ext8;
	void *ext9;
	void *ext10;
	void *ext11;
	void *ext12;

	struct ndis_scatterlist scatterlist;
	dma_addr_t dataphys;
	struct list_head recycle_list;
	unsigned char header[ETH_HLEN];
	unsigned char *look_ahead;
	unsigned int look_ahead_size;
};

enum ndis_pnp_event
{
	NDIS_PNP_QUERY_REMOVED,
	NDIS_PNP_REMOVED,
	NDIS_PNP_SURPRISE_REMOVED,
	NDIS_PNP_QUERY_STOPPED,
	NDIS_PNP_STOPPED,
	NDIS_PNP_PROFILE_CHANGED,
	NDIS_PNP_MAXIMUM,
};

struct miniport_char
{
	/* NDIS 3.0 */
	unsigned char majorVersion;
	unsigned char minorVersion;
	unsigned int reserved;

	char (*hangcheck)(void *ctx) STDCALL;
	void (*disable_interrupts)(void *ctx) STDCALL;
	void (*enable_interrupts)(void *ctx) STDCALL;

	/* Stop miniport */
	void (*halt)(void *ctx) STDCALL;

	/* Interrupt BH */
	void (*handle_interrupt)(void *ctx) STDCALL;

	/* Start miniport driver */
	unsigned int (*init)(unsigned int *OpenErrorStatus,
			     unsigned int *SelectedmediumIndex,
			     unsigned int *MediumArray,
			     unsigned int MediumArraySize, void *ndis_handle,
			     void *conf_handle) STDCALL;

	/* Interrupt TH */
	void (*isr)(unsigned int *taken, unsigned int *callme,
		    void *ctx) STDCALL;

	/* Query parameters */
	unsigned int (*query)(void *ctx, unsigned int oid,
			      char *buffer, unsigned int buflen,
			      unsigned int *written,
			      unsigned int *needed) STDCALL;

	void * ReconfigureHandler;
	int (*reset)(int *needs_set, void *ctx) STDCALL;

	/* Send one packet */
	unsigned int (*send)(void *ctx, struct ndis_packet *packet,
			     unsigned int flags) STDCALL;

	/* Set parameters */
	unsigned int (*setinfo)(void *ctx, unsigned int oid, char *buffer,
				unsigned int buflen, unsigned int *written,
				unsigned int *needed) STDCALL;

	/* transfer data from received packet */
	unsigned int (*tx_data)(struct ndis_packet *ndis_packet,
				unsigned int *bytes_txed,
				void *adapter_ctx, void *rx_ctx,
				unsigned int offset,
				unsigned int bytes_to_tx) STDCALL;

	/* NDIS 4.0 extensions */
	/* upper layer is done with RX packet */
	void (*return_packet)(void *ctx, void *packet) STDCALL;

	/* Send packets */
	unsigned int (*send_packets)(void *ctx, struct ndis_packet **packets,
				     int nr_of_packets) STDCALL;

	void (*alloc_complete)(void *handle, void *virt,
			       struct ndis_phy_address *phys,
			       unsigned long size, void *ctx) STDCALL;

	/* NDIS 5.0 extensions */
	void *co_create_vc;
	void *co_delete_vc;
	void *co_activate_vc;
	void *co_deactivate_vc;
	void *co_send_packets;
	void *co_request;

	/* NDIS 5.1 extensions */
	void *cancel_send_packets;
	void (*pnp_event_notify)(void *ctx, enum ndis_pnp_event, void *inf_buf,
				 unsigned long inf_buf_len) STDCALL;
	void (*adapter_shutdown)(void *ctx) STDCALL;
	void *reserved1;
	void *reserved2;
	void *reserved3;
	void *reserved4;

};

struct handle_ctx_entry
{
	struct list_head list;
	void *handle;
	void *ctx;
};

struct ndis_sched_work_item
{
	void *ctx;
	void (*func)(struct ndis_sched_work_item *, void *) STDCALL;
	unsigned char reserved[8 * sizeof(void *)];
};

struct ndis_alloc_mem
{
	struct ndis_handle *handle;
	unsigned long size;
	char cached;
	void *ctx;
};

struct ndis_free_mem
{
	void *addr;
	unsigned int length;
	unsigned int flags;
};

enum ndis_work_entry_type
{
	_NDIS_SCHED_WORK,
	_NDIS_ALLOC_MEM,
	_NDIS_FREE_MEM,
};

struct ndis_work_entry
{
	struct list_head list;
	enum ndis_work_entry_type type;
	union
	{
		struct ndis_sched_work_item *sched_work_item;
		struct ndis_alloc_mem alloc_mem;
		struct ndis_free_mem free_mem;
	} entry;
};

struct kevent
{
	struct dispatch_header header;
};

struct ndis_irq
{
	/* void *intr_obj is used for irq */
	int irq;
	/* KSPIN_LOCK lock (pointer to unsigned long) is used for spinlock */
	/* Taken by ISR, DisableInterrupt and SynchronizeWithInterrupt */
	spinlock_t *spinlock;
	void *id;
	void *isr;
	void *dpc;

	struct kdpc intr_dpc;
	struct ndis_handle *handle;
	unsigned char dpc_count;
	/* unsigned char filler1 is used for enabled */
	unsigned char enabled;
	struct kevent completed_event;
	unsigned char shared;
	unsigned char req_isr;
};

struct ndis_spin_lock
{
	struct wrap_spinlock *wrap_spinlock;
	KIRQL kirql;
};

struct packed ustring
{
	__u16 len;
	__u16 buflen;
	char *buf;
};

struct ndis_binary_data {
	__u16 len;
	void *buf;
};

enum ndis_setting_type {
	NDIS_SETTING_INT,
	NDIS_SETTING_HEXINT,
	NDIS_SETTING_STRING,
	NDIS_SETTING_MULTISTRING,
	NDIS_SETTING_BINARY,
	NDIS_SETTING_NONE,
};

struct ndis_setting_val
{
	enum ndis_setting_type type;
	union
	{
		unsigned long intval;
		struct ustring ustring;
//		struct ndis_binary_data binary_data;
	} data;
};

struct ndis_setting
{
	struct list_head list;
	char *name;
	char *val_str;
	struct ndis_setting_val value;
};


struct ndis_file
{
	struct list_head list;
	char name[32];
	int size;
	void *data;
};


/*
 * There is one of these per driver. One per loaded driver exists.
 *
 */
struct ndis_driver
{
	struct list_head list;
	char name[DRIVERNAME_MAX];
	char version[NDIS_VERSION_STRING_MAX];

	struct list_head devices;
	struct list_head files;

	int bustype;

	union {
		struct pci_driver pci;
		struct usb_driver usb;
	} driver;
	union {
		struct pci_device_id *pci;
		struct usb_device_id *usb;
	} idtable;

	int nr_devices;
	int started;

	unsigned int dev_registered;

	void *image;
	unsigned int (*entry)(void *obj, char *p2) STDCALL;
	struct miniport_char miniport_char;
	struct ndis_device *current_device;
};

/*
 * There is one of these per handeled device-id
 *
 */
struct ndis_device
{
	struct list_head list;
	struct list_head settings;
	struct ndis_driver *driver;

	int bustype;
	int vendor;
	int device;
	int pci_subvendor;
	int pci_subdevice;
	int fuzzy;
};

typedef __u64 LARGE_INTEGER;
struct ndis_wireless_stats {
	LARGE_INTEGER length;
	LARGE_INTEGER tx_frag;
	LARGE_INTEGER tx_multi_frag;
	LARGE_INTEGER failed;
	LARGE_INTEGER retry;
	LARGE_INTEGER multi_retry;
	LARGE_INTEGER rtss_succ;
	LARGE_INTEGER rtss_fail;
	LARGE_INTEGER ack_fail;
	LARGE_INTEGER frame_dup;
	LARGE_INTEGER rx_frag;
	LARGE_INTEGER rx_multi_frag;
	LARGE_INTEGER fcs_err;
};

#define NDIS_ESSID_MAX_SIZE 32
struct packed ndis_essid
{
	unsigned int length;
	char essid[NDIS_ESSID_MAX_SIZE];
};

#define NDIS_ENCODING_TOKEN_MAX 32
struct packed ndis_encr_key
{
	unsigned long struct_size;
	unsigned long index;
	unsigned long length;
	unsigned char key[NDIS_ENCODING_TOKEN_MAX];
};

typedef unsigned char mac_address[ETH_ALEN];

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

enum auth_mode
{
	AUTHMODE_OPEN,
	AUTHMODE_RESTRICTED,
	AUTHMODE_AUTO,
	AUTHMODE_WPA,
	AUTHMODE_WPAPSK,
	AUTHMODE_WPANONE
};

enum encr_mode
{
	ENCR1_ENABLED,
	ENCR_DISABLED,
	ENCR1_NOKEY,
	ENCR1_NO_SUPPORT,
	ENCR2_ENABLED,
	ENCR2_ABSENT,
	ENCR3_ENABLED,
	ENCR3_ABSENT,
};

struct fixed_ies
{
    unsigned char time_stamp[8];
    unsigned short beacon_interval;
    unsigned short capa;
};

struct variable_ies
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

enum wrapper_work
{
	WRAPPER_LINK_STATUS,
	SET_OP_MODE,
	SET_ESSID,
};

enum op_mode
{
	NDIS_MODE_ADHOC,
	NDIS_MODE_INFRA,
	NDIS_MODE_AUTO
};

enum hw_status
{
	HW_NORMAL,
	HW_SUSPENDED,
	HW_UNAVAILABLE,
};

#define MAX_ENCR_KEYS 4
struct encr_info
{
	struct encr_key
	{
		unsigned int length;
		unsigned char key[NDIS_ENCODING_TOKEN_MAX];
	} keys[MAX_ENCR_KEYS];
	int active;
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

#define XMIT_RING_SIZE 16

enum ndis_medium {
	NDIS_MEDIUM_802_3,
	NDIS_MEDIUM_802_5,
	NDIS_MEDIUM_FDDI,
	NDIS_MEDIUM_WAN,
	NDIS_MEDIUM_LOCALTALK,
	NDIS_MEDIUM_DIX,
	NDIS_MEDIUM_ARCNETRAW,
	NDIS_MEDIUM_ARCNET878_2,
	NDIS_MEDIUM_ATM,
	NDIS_MEDIUM_WIRELESSWAN,
	NDIS_MEDIUM_IRDA,
	NDIS_MEDIUM_BPC,
	NDIS_MEDIUM_COWAN,
	NDIS_MEDIUM_1394,
	NDIS_MEDIUM_MAX
};


enum ndis_phys_medium
{
    NDIS_PHYSICAL_MEDIUM_UNSPECIFIED,
    NDIS_PHYSICAL_MEDIUM_WIRELESSLAN,
    NDIS_PHYSICAL_MEDIUM_CABLEMODEM,
    NDIS_PHYSICAL_MEDIUM_PHONELINE,
    NDIS_PHYSICAL_MEDIUM_POWERLINE,
    NDIS_PHYSICAL_MEDIUM_DSL,
    NDIS_PHYSICAL_MEDIUM_FIBRECHANNEL,
    NDIS_PHYSICAL_MEDIUM_1394,
    NDIS_PHYSICAL_MEDIUM_WIRELESSWAN,
    NDIS_PHYSICAL_MEDIUM_MAX,
};

/*
 * This is the per device struct. One per PCI-device exists.
 *
 *  This struct contains function pointers that the drivers references directly via macros,
 * so it's important that they are at the correct position hence the paddings.
 */
struct packed ndis_handle
{
	char fill1[232];
	void *rx_packet;
	void *send_complete;
	void *send_resource_avail;
	void *reset_complete;
//	char fill2[132];

	unsigned long media_type;
	unsigned int bus_number;
	unsigned int bus_type;
	unsigned int adapter_type;
	void *device_obj;
	void *phys_device_obj;
	void *next_device_obj;
	void *mapreg;
	void *call_mgraflist;
	void *miniport_thread;
	void *setinfobuf;
	unsigned short setinfo_buf_len;
	unsigned short max_send_pkts;
	unsigned int fake_status;
	void *lock_handler;
	struct ustring *adapter_instance_name;
	void *timer_queue;
	u32 mac_options;
	void *pending_req;
	u32 max_long_addrs;
	u32 max_short_addrs;
	u32 cur_lookahead;
	u32 max_lookahead;
	void *interrupt;
	void *disable_intr;
	void *enable_intr;
	void *send_pkts;
	void *deferred_send;
	void *eth_rx_indicate;
	void *txrx_indicate;
	void *fddi_rx_indicate;
	void *eth_rx_complete;
	void *txrx_complete;
	void *fddi_rx_complete;

	void *status;
	void *status_complete;
	void *td_complete;

	void *query_complete;
	void *set_complete;
	void *wan_tx_complete;
	void *wan_rx;
	void *wan_rx_complete;

	char fill3[200];

	union {
		struct pci_dev *pci;
		struct usb_device *usb;
		void *ptr;
	} dev;
	struct net_device *net_dev;
	void *adapter_ctx;
	void *shutdown_ctx;

	struct work_struct irq_bh;

	struct ndis_irq *ndis_irq;
	unsigned long mem_start;
	unsigned long mem_end;

	struct net_device_stats stats;
	struct iw_statistics wireless_stats;
	struct ndis_wireless_stats ndis_stats;
	struct ndis_driver *driver;
	struct ndis_device *device;
	struct device_object *phy_dev;

	struct work_struct xmit_work;
	struct wrap_spinlock xmit_ring_lock;
	struct ndis_buffer *xmit_ring[XMIT_RING_SIZE];
	unsigned int xmit_ring_start;
	unsigned int xmit_ring_pending;

	int send_status;
	struct ndis_packet *send_packet;
	struct wrap_spinlock send_packet_lock;
	struct wrap_spinlock send_packet_done_lock;

	struct semaphore ndis_comm_mutex;
	wait_queue_head_t ndis_comm_wq;
	int ndis_comm_res;
	int ndis_comm_done;

	int serialized;
	int use_scatter_gather;
	int map_count;
	int multicast_list_size;
	char *multicast_list;
	dma_addr_t *map_dma_addr;

	int hangcheck_interval;
	unsigned short hangcheck;
	struct timer_list hangcheck_timer;
	struct work_struct hangcheck_work;
	int reset_status;

	struct timer_list statcollector_timer;
	struct work_struct statcollector_work;

	unsigned long scan_timestamp;

	u32 link_status;
	struct encr_info encr_info;
	char nick[IW_ESSID_MAX_SIZE+1];

	u32 pci_state[16];
	unsigned long hw_status;

	struct ndis_essid essid;

	unsigned long capa;
	enum auth_mode auth_mode;
	enum encr_mode encr_mode;
	enum op_mode op_mode;

	struct list_head recycle_packets;
	struct wrap_spinlock recycle_packets_lock;
	struct work_struct recycle_packets_work;

	/* List of initialized timers */
	struct list_head timers;

	struct proc_dir_entry *procfs_iface;

	struct work_struct set_rx_mode_work;

	struct work_struct wrapper_worker;
	unsigned long wrapper_work;

	unsigned short surprise_remove;
};

struct ndis_timer
{
	struct ktimer ktimer;
	struct kdpc kdpc;
};

struct ndis_miniport_timer
{
	struct ktimer ktimer;
	struct kdpc kdpc;
	void *timer_func;
	void *timer_ctx;
	struct ndis_handle *handle;
	struct ndis_miniport_timer *next;
};

struct packed ndis_resource_entry
{
	__u8 type;
	__u8 share;
	__u16 flags;
	__u32 param1;
	__u32 param2;
	__u32 param3;
};

struct packed ndis_resource_list
{
	__u16 version;
	__u16 revision;
	__u32 length;
	struct ndis_resource_entry list[0];
};


struct ndis_event
{
	int state;
};

#define NDIS_MAX_RATES 16
struct ssid_item
{
	unsigned long length;
	__u8 mac[ETH_ALEN];
	unsigned char reserved[2];
	struct ndis_essid ssid;
	unsigned long privacy;
	long rssi;
	unsigned int net_type;
	struct ndis_configuration config;
	unsigned int mode;
	unsigned char rates[NDIS_MAX_RATES];
	unsigned long ie_length;
	unsigned char ies[1];
};

#define WLAN_EID_GENERIC 221
#define MAX_WPA_IE_LEN 64

struct bssid_list
{
	unsigned long num_items;
	struct ssid_item items[1];
};

enum priv_filter
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

enum ndis_pm_state
{
	NDIS_PM_STATE_D0 = 1,
	NDIS_PM_STATE_D1 = 2,
	NDIS_PM_STATE_D2 = 3,
	NDIS_PM_STATE_D3 = 4,
};

enum ndis_power_profile
{
	NDIS_POWER_PROFILE_BATTERY,
	NDIS_POWER_PROFILE_AC,
};

enum status_type
{
	NDIS_STATUS_AUTHENTICATION,
	NDIS_STATUS_MAX,
};

struct status_indication
{
	enum status_type status_type;
};

struct auth_req
{
	unsigned long length;
	mac_address bssid;
	unsigned long flags;
};

void sendpacket_done(struct ndis_handle *handle, struct ndis_packet *packet);
STDCALL void NdisMIndicateReceivePacket(struct ndis_handle *handle,
					struct ndis_packet **packets,
					unsigned int nr_packets);
STDCALL void NdisMSendComplete(struct ndis_handle *handle,
			       struct ndis_packet *packet,
			       unsigned int status);
STDCALL void NdisMSendResourcesAvailable(struct ndis_handle *handle);
STDCALL void NdisMIndicateStatus(struct ndis_handle *handle,
				 unsigned int status, void *buf,
				 unsigned int len);
STDCALL void NdisMIndicateStatusComplete(struct ndis_handle *handle);
STDCALL void NdisMQueryInformationComplete(struct ndis_handle *handle,
					   unsigned int status);
STDCALL void NdisMSetInformationComplete(struct ndis_handle *handle,
					 unsigned int status);
STDCALL void NdisMResetComplete(struct ndis_handle *handle, int status,
				int reset_status);
STDCALL unsigned long NDIS_BUFFER_TO_SPAN_PAGES(struct ndis_buffer *buffer);
STDCALL void NdisSetEvent(struct ndis_event *event);
STDCALL void NdisMDeregisterInterrupt(struct ndis_irq *ndis_irq);
STDCALL void EthRxIndicateHandler(void *adapter_ctx, void *rx_ctx,
				  char *header1, char *header,
				  u32 header_size, char *look_aheader,
				  u32 look_aheader_size, u32 packet_size);
STDCALL void EthRxComplete(struct ndis_handle *handle);
void free_handle_ctx(struct ndis_handle *handle);
STDCALL void NdisMTransferDataComplete(struct ndis_handle *handle,
				       struct ndis_packet *packet,
				       unsigned int status,
				       unsigned int bytes_txed);

STDCALL int RtlUnicodeStringToAnsiString(struct ustring *dst,
					 struct ustring *src,
					 unsigned int dup);
STDCALL int RtlAnsiStringToUnicodeString(struct ustring *dst,
					 struct ustring *src,
					 unsigned int dup);
int getSp(void);
void init_ndis(void);

int ndiswrapper_procfs_init(void);
int ndiswrapper_procfs_add_iface(struct ndis_handle *handle);
void ndiswrapper_procfs_remove_iface(struct ndis_handle *handle);
void ndiswrapper_procfs_remove(void);

int doquery(struct ndis_handle *handle, unsigned int oid, char *buf,
	    int bufsize, unsigned int *written , unsigned int *needed);
int dosetinfo(struct ndis_handle *handle, unsigned int oid, char *buf,
	      int bufsize, unsigned int *written , unsigned int *needed);
int set_int(struct ndis_handle *handle, int oid, int data);
int query_int(struct ndis_handle *handle, int oid, int *data);
int doreset(struct ndis_handle *handle);
void ndis_set_rx_mode(struct net_device *dev);
void hangcheck_add(struct ndis_handle *handle);
void hangcheck_del(struct ndis_handle *handle);
int ndis_suspend(struct pci_dev *pdev, u32 state);
int ndis_resume(struct pci_dev *pdev);


void packet_recycler(void *param);

int stricmp(const char *s1, const char *s2);

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
};

#define WPA_SET_WPA 			SIOCIWFIRSTPRIV+1
#define WPA_SET_KEY 			SIOCIWFIRSTPRIV+2
#define WPA_ASSOCIATE		 	SIOCIWFIRSTPRIV+3
#define WPA_DISASSOCIATE 		SIOCIWFIRSTPRIV+4
#define WPA_DROP_UNENCRYPTED 		SIOCIWFIRSTPRIV+5
#define WPA_SET_COUNTERMEASURES 	SIOCIWFIRSTPRIV+6
#define WPA_DEAUTHENTICATE	 	SIOCIWFIRSTPRIV+7
#define WPA_SET_AUTH_ALG	 	SIOCIWFIRSTPRIV+8

#endif /* NDIS_H */
