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

typedef int NDIS_STATUS;

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
#ifdef CONFIG_X86_64
	uint64_t quad;
#else
	uint32_t quad_low;
	int32_t quad_high;
#endif
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

enum ndis_request_type {
	NDIS_REQUEST_QUERY_INFORMATION,
	NDIS_REQUEST_SET_INFORMATION,
	NDIS_REQUEST_QUERY_STATISTICS,
	NDIS_REQUEST_OPEN,
	NDIS_REQUEST_CLOSE,
	NDIS_REQUEST_SEND,
	NDIS_REQUEST_TRANSFER_DATA,
	NDIS_REQUEST_RESET,
	NDIS_REQUEST_GENERIC1,
	NDIS_REQUEST_GENERIC2,
	NDIS_REQUEST_GENERIC3,
	NDIS_REQUEST_GENERIC4
};

struct ndis_request {
	mac_address mac;
	enum ndis_request_type request_type;
	union data {
		struct query_info {
			unsigned int oid;
			void *buf;
			unsigned int buf_len;
			unsigned int written;
			unsigned int needed;
		} query_info;
		struct set_info {
			unsigned int oid;
			void *buf;
			unsigned int buf_len;
			unsigned int written;
			unsigned int needed;
		} set_info;
	} data;
};

typedef void (*ndis_isr_handler)(unsigned int *taken, unsigned int *callme,
				 void *ctx) STDCALL;
typedef void (*ndis_interrupt_handler)(void *ctx) STDCALL;

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
	ndis_interrupt_handler handle_interrupt;

	/* Start miniport driver */
	unsigned int (*init)(unsigned int *OpenErrorStatus,
			     unsigned int *SelectedmediumIndex,
			     unsigned int *MediumArray,
			     unsigned int MediumArraySize, void *ndis_handle,
			     void *conf_handle) STDCALL;

	/* Interrupt TH */
	ndis_isr_handler isr;

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
	unsigned int (*co_create_vc)(void *ctx, void *vc_handle,
				      void *vc_ctx) STDCALL;
	unsigned int (*co_delete_vc)(void *vc_ctx) STDCALL;
	unsigned int (*co_activate_vc)(void *vc_ctx,
				       void *call_params) STDCALL;
	unsigned int (*co_deactivate_vc)(void *vc_ctx) STDCALL;
	unsigned int (*co_send_packets)(void *vc_ctx, void **packets,
					unsigned int nr_of_packets) STDCALL;
	unsigned int (*co_request)(void *ctx, void *vc_ctx,
					unsigned int *req) STDCALL;

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

/* this should be same as wrap_spinlock */
struct ndis_spinlock
{
	KSPIN_LOCK lock;
	KIRQL use_bh;
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

struct ndis_io_work_item
{
	void *ctx;
	void *device_object;
	void (*func)(void *device_object, void *ctx) STDCALL;
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
	NDIS_SCHED_WORK,
	NDIS_ALLOC_MEM,
	NDIS_FREE_MEM,
	NDIS_IO_WORK_ITEM,
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
		struct ndis_io_work_item *io_work_item;
	} entry;
};

struct ndis_irq
{
	/* void *intr_obj is used for irq */
	int irq;
	/* KSPIN_LOCK lock (pointer to unsigned long) is used for spinlock */
	/* Taken by ISR, DisableInterrupt and SynchronizeWithInterrupt */
	spinlock_t *spinlock;
	void *id;
	ndis_isr_handler isr;
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

struct ndis_binary_data {
	unsigned short len;
	void *buf;
};

enum ndis_config_param_type {
	NDIS_CONFIG_PARAM_INT,
	NDIS_CONFIG_PARAM_HEXINT,
	NDIS_CONFIG_PARAM_STRING,
	NDIS_CONFIG_PARAM_MULTISTRING,
	NDIS_CONFIG_PARAM_BINARY,
	NDIS_CONFIG_PARAM_NONE,
};

struct ndis_config_param
{
	enum ndis_config_param_type type;
	union
	{
		unsigned long intval;
		struct ustring ustring;
		struct ndis_binary_data binary_data;
	} data;
};

struct device_setting
{
	struct list_head list;
	char name[MAX_NDIS_SETTING_NAME_LEN];
	char value[MAX_NDIS_SETTING_VALUE_LEN];
	struct ndis_config_param config_param;
};

struct ndis_bin_file
{
	char name[MAX_NDIS_SETTING_NAME_LEN];
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
	char name[MAX_NDIS_SETTING_NAME_LEN];
	char version[MAX_NDIS_SETTING_VALUE_LEN];

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
	struct ndis_device **devices;

	unsigned int num_pe_images;
	struct pe_image pe_images[MAX_PE_IMAGES];

	int nr_bin_files;
	struct ndis_bin_file **bin_files;

	int started;
	unsigned int dev_registered;
	struct miniport_char miniport_char;
};

/*
 * There is one of these per handeled device-id
 *
 */
struct ndis_device
{
	struct list_head settings;
	int bustype;
	int vendor;
	int device;
	int pci_subvendor;
	int pci_subdevice;
	int fuzzy;

	struct ndis_driver *driver;
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

enum wrapper_work
{
	WRAPPER_LINK_STATUS,
	SET_OP_MODE,
	SET_ESSID,
	SET_PACKET_FILTER,
	COLLECT_STATS,
	SUSPEND_RESUME,
	/* do not work when this is set */
	SHUTDOWN
};

enum ndis_attributes
{
	ATTR_SERIALIZED,
	ATTR_SURPRISE_REMOVE,
	ATTR_HALT_ON_SUSPEND,
};

enum hw_status
{
	HW_NORMAL,
	HW_SUSPENDED,
	HW_HALTED,
	HW_UNAVAILABLE,
};

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

struct encr_info
{
	struct encr_key
	{
		unsigned int length;
		unsigned char key[NDIS_ENCODING_TOKEN_MAX];
	} keys[MAX_ENCR_KEYS];
	int active;
};

struct packed ndis_essid
{
	unsigned int length;
	char essid[NDIS_ESSID_MAX_SIZE];
};

struct packed ndis_encr_key
{
	unsigned long struct_size;
	unsigned long index;
	unsigned long length;
	unsigned char key[NDIS_ENCODING_TOKEN_MAX];
};

enum auth_mode
{
	AUTHMODE_OPEN,
	AUTHMODE_RESTRICTED,
	AUTHMODE_AUTO,
	AUTHMODE_WPA,
	AUTHMODE_WPAPSK,
	AUTHMODE_WPANONE,
	AUTHMODE_WPA2,
	AUTHMODE_WPA2PSK,
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

enum op_mode
{
	NDIS_MODE_ADHOC,
	NDIS_MODE_INFRA,
	NDIS_MODE_AUTO
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
	struct kevent kevent;
};

struct ndis_bind_paths {
	unsigned int number;
	struct ustring paths[1];
};

struct ndis_reference {
	KSPIN_LOCK spinlock;
	unsigned short ref_count;
	BOOLEAN closing;
};

struct ndis_miniport_interrupt {
	void *object;
	KSPIN_LOCK dpc_count_lock;
	void *reserved;
	ndis_isr_handler irq_th;
	ndis_interrupt_handler irq_bh;
	struct kdpc interrupt_dpc;
	struct ndis_miniport_block *miniport;
	UCHAR dpc_count;
	BOOLEAN filler1;
	struct kevent dpcs_completed_event;
        BOOLEAN shared_interrupt;
	BOOLEAN isr_requested;
};

struct ndis_filterdbs {
	union {
		void *eth_db;
		void *null_db;
	} u;
	void *trdb;
	void *fddidb;
	void *arcdb;
};

/*
 * This is the per device struct. One per PCI-device exists.
 *
 *  This struct contains function pointers that the drivers references directly via macros,
 * so it's important that they are at the correct position hence the paddings.
 */
struct packed ndis_handle
{
	void *signature;
	struct ndis_handle *next;
	struct ndis_driver *driver;
	void *adapter_ctx;
	struct ustring name;
	struct ndis_bind_paths *bindpaths;
	void *openqueue;
	struct ndis_reference reference;
	void *device_ctx;
	UCHAR padding;
	UCHAR lock_acquired;
	UCHAR pmode_opens;
	UCHAR assigned_cpu;
	KSPIN_LOCK lock;
	enum ndis_request_type *mediarequest;
	struct ndis_miniport_interrupt *interrupt;
	unsigned long flags;
	unsigned long pnp_flags;
	struct list_entry packet_list;
	struct ndis_packet *first_pending_tx_packet;
	struct ndis_packet *return_packet_queue;
	unsigned long request_buffer;
	void *set_mcast_buffer;
	struct ndis_handle *primary_miniport;
	void *wrapper_ctx;
	void *bus_data_ctx;
	unsigned long pnp_capa;
	void *resources;
	struct ndis_timer wakeup_dpc_timer;
	struct ustring basename;
	struct ustring symlink_name;
	unsigned long ndis_hangcheck_interval;
	unsigned short hanghcheck_ticks;
	unsigned short hangcheck_tick;
	NDIS_STATUS ndis_reset_status;
	void *resetopen;
	struct ndis_filterdbs filterdbs;
	void *rx_packet;
	void *send_complete;
	void *send_resource_avail;
	void *reset_complete;

	unsigned long media_type;
	unsigned int bus_number;
	unsigned int bus_type;
	unsigned int adapter_type;
	struct device_object *device_obj;
	struct device_object *phys_device_obj;
	struct device_object *next_device_obj;
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

	ndis_interrupt_handler irq_bh;
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

	/* the rest are ndiswrapper specific */

	/* keep a barrier in cases of over-stepping */
	char barrier[200];

	union {
		struct pci_dev *pci;
		struct usb_device *usb;
		void *ptr;
	} dev;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	struct usb_interface *intf;
#endif
	struct net_device *net_dev;
//	void *adapter_ctx;
	void *shutdown_ctx;

	struct work_struct irq_work;

	struct ndis_irq *ndis_irq;
	unsigned long mem_start;
	unsigned long mem_end;

	struct net_device_stats stats;
	struct iw_statistics wireless_stats;
	struct ndis_wireless_stats ndis_stats;
	struct ndis_device *device;

	struct work_struct xmit_work;
	struct wrap_spinlock xmit_ring_lock;
	struct ndis_packet *xmit_ring[XMIT_RING_SIZE];
	struct ndis_packet **xmit_array;
	unsigned int xmit_ring_start;
	unsigned int xmit_ring_pending;
	unsigned int max_send_packets;

	unsigned char send_ok;
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
	int hangcheck_active;
	struct timer_list hangcheck_timer;
	int reset_status;

	struct timer_list stats_timer;

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

	mac_address mac;
	struct list_head recycle_packets;
	struct wrap_spinlock recycle_packets_lock;
	struct work_struct recycle_packets_work;

	/* List of initialized timers */
	struct list_head timers;
	struct wrap_spinlock timers_lock;

	struct proc_dir_entry *procfs_iface;

	struct work_struct wrapper_worker;
	unsigned long wrapper_work;

	unsigned long attributes;
};

enum ndis_pm_state
{
	NDIS_PM_STATE_D0 = 1,
	NDIS_PM_STATE_D1 = 2,
	NDIS_PM_STATE_D2 = 3,
	NDIS_PM_STATE_D3 = 4,
};

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
STDCALL int NdisWaitEvent(struct ndis_event *event, unsigned int timeout);
STDCALL void NdisSetEvent(struct ndis_event *event);
STDCALL void NdisMDeregisterInterrupt(struct ndis_irq *ndis_irq);
STDCALL void EthRxIndicateHandler(void *adapter_ctx, void *rx_ctx,
				  char *header1, char *header,
				  u32 header_size, char *look_aheader,
				  u32 look_aheader_size, u32 packet_size);
STDCALL void EthRxComplete(struct ndis_handle *handle);
STDCALL void NdisMTransferDataComplete(struct ndis_handle *handle,
				       struct ndis_packet *packet,
				       unsigned int status,
				       unsigned int bytes_txed);
STDCALL void NdisWriteConfiguration(unsigned int *status,
				    struct ndis_handle *handle,
				    struct ustring *key,
				    struct ndis_config_param *val);

STDCALL int RtlUnicodeStringToAnsiString(struct ustring *dst,
					 struct ustring *src,
					 unsigned int dup);
STDCALL int RtlAnsiStringToUnicodeString(struct ustring *dst,
					 struct ustring *src,
					 unsigned int dup);
STDCALL void RtlInitAnsiString(struct ustring *dst, char *src);
STDCALL void RtlFreeUnicodeString(struct ustring *string);
STDCALL void RtlFreeAnsiString(struct ustring *string);

void *get_sp(void);
void ndis_init(void);
void ndis_cleanup_handle(struct ndis_handle *handle);

int ndiswrapper_procfs_init(void);
int ndiswrapper_procfs_add_iface(struct ndis_handle *handle);
void ndiswrapper_procfs_remove_iface(struct ndis_handle *handle);
void ndiswrapper_procfs_remove(void);

void packet_recycler(void *param);
int stricmp(const char *s1, const char *s2);
int string_to_mac(unsigned char *mac, unsigned char *string, int string_len);

#endif /* NDIS_H */
