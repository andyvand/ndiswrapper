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

#ifndef NDIS_H
#define NDIS_H

#include "ntoskernel.h"

#define NDIS_DMA_24BITS 0
#define NDIS_DMA_32BITS 1
#define NDIS_DMA_64BITS 2

typedef UINT NDIS_STATUS;
typedef UCHAR NDIS_DMA_SIZE;
typedef LONG ndis_rssi;
typedef ULONG ndis_key_index;
typedef ULONG ndis_tx_power_level;
typedef ULONGULONG ndis_key_rsc;
typedef UCHAR ndis_rates[NDIS_MAX_RATES_EX];
typedef UCHAR mac_address[ETH_ALEN];
typedef ULONG ndis_fragmentation_threshold;
typedef ULONG ndis_rts_threshold;
typedef ULONG ndis_antenna;
typedef ULONG ndis_oid;

typedef uint64_t NDIS_PHY_ADDRESS;

struct ndis_sg_element {
	PHYSICAL_ADDRESS address;
	ULONG length;
	ULONG_PTR reserved;
};

struct ndis_sg_list {
	ULONG nent;
	ULONG_PTR reserved;
	struct ndis_sg_element *elements;
};

struct ndis_phy_addr_unit {
	NDIS_PHY_ADDRESS phy_addr;
	UINT length;
};

typedef struct mdl ndis_buffer;

enum ndis_per_packet_info {
	TcpIpChecksumPacketInfo,
	IpSecPacketInfo,
	TcpLargeSendPacketInfo,
	ClassificationHandlePacketInfo,
	NdisReserved,
	ScatterGatherListPacketInfo,
	Ieee8021QInfo,
	OriginalPacketInfo,
	PacketCancelId,
	MaxPerPacketInfo
};

struct ndis_packet_extension {
	void *info[MaxPerPacketInfo];
};

struct ndis_packet_private {
	UINT nr_pages;
	UINT len;
	ndis_buffer *buffer_head;
	ndis_buffer *buffer_tail;
	void *pool;
	UINT count;
	ULONG flags;
	BOOLEAN valid_counts;
	UCHAR packet_flags;
	USHORT oob_offset;
};

struct ndis_packet {

	struct ndis_packet_private private;

	/* for use by miniport */
	union {
		/* for connectionless mininports */
		struct {
			UCHAR miniport_reserved[2 * sizeof(void *)];
			UCHAR wrapper_reserved[2 * sizeof(void *)];
		} cl_reserved;
		/* for deserialized miniports */
		struct {
			UCHAR miniport_reserved_ex[3 * sizeof(void *)];
			UCHAR wrapper_reserved_ex[sizeof(void *)];
		} deserailized_reserved;
		struct {
			UCHAR mac_reserved[4 * sizeof(void *)];
		} mac_reserved;
	} u;
	ULONG_PTR reserved[2];
	UCHAR protocol_reserved[1];

	/* OOB data */
	union {
		ULONGLONG time_to_tx;
		ULONGLONG time_txed;
	} oob_tx;
	ULONGLONG time_rxed;
	UINT header_size;
	UINT mediaspecific_size;
	void *mediaspecific;
	NDIS_STATUS status;

	struct ndis_packet_extension extension;

	struct scatterlist *sg_list;
	unsigned int sg_ents;
	/* ndiswrapper-specific info */
	struct ndis_sg_list ndis_sg_list;
	struct ndis_sg_element *ndis_sg_elements;
	/* RTL8180L overshoots past ndis_eg_elements (during
	 * MiniportSendPackets) and overwrites what is below, so put a
	 * barrier */
	void *dummy;
	dma_addr_t dataphys;
	unsigned char header[ETH_HLEN];
	unsigned char *look_ahead;
	unsigned int look_ahead_size;
};

enum ndis_device_pnp_event {
	NdisDevicePnPEventQueryRemoved,
	NdisDevicePnPEventRemoved,
	NdisDevicePnPEventSurpriseRemoved,
	NdisDevicePnPEventQueryStopped,
	NdisDevicePnPEventStopped,
	NdisDevicePnPEventPowerProfileChanged,
	NdisDevicePnPEventMaximum
};

enum ndis_request_type {
	NdisRequestQueryInformation,
	NdisRequestSetInformation,
	NdisRequestQueryStatistics,
	NdisRequestOpen,
	NdisRequestClose,
	NdisRequestSend,
	NdisRequestTransferData,
	NdisRequestReset,
	NdisRequestGeneric1,
	NdisRequestGeneric2,
	NdisRequestGeneric3,
	NdisRequestGeneric4
};

struct ndis_request {
	mac_address mac;
	enum ndis_request_type request_type;
	union data {
		struct query_info {
			UINT oid;
			void *buf;
			UINT buf_len;
			UINT written;
			UINT needed;
		} query_info;
		struct set_info {
			UINT oid;
			void *buf;
			UINT buf_len;
			UINT written;
			UINT needed;
		} set_info;
	} data;
};

enum ndis_medium {
	NdisMedium802_3,
	NdisMedium802_5,
	NdisMediumFddi,
	NdisMediumWan,
	NdisMediumLocalTalk,
	NdisMediumDix,
	NdisMediumArcnetRaw,
	NdisMediumArcnet878_2,
	NdisMediumAtm,
	NdisMediumWirelessWan,
	NdisMediumIrda,
	NdisMediumBpc,
	NdisMediumCoWan,
	NdisMedium1394,
	NdisMediumMax
};

enum ndis_phys_medium {
	NdisPhysicalMediumUnspecified,
	NdisPhysicalMediumWirelessLan,
	NdisPhysicalMediumCableModem,
	NdisPhysicalMediumPhoneLine,
	NdisPhysicalMediumPowerLine,
	NdisPhysicalMediumDSL,
	NdisPhysicalMediumFibreChannel,
	NdisPhysicalMedium1394,
	NdisPhysicalMediumWirelessWan,
	NdisPhysicalMediumMax
};

enum ndis_pm_state {
	NdisDeviceStateUnspecified = 0,
	NdisDeviceStateD0,
	NdisDeviceStateD1,
	NdisDeviceStateD2,
	NdisDeviceStateD3,
	NdisDeviceStateMaximum
};

typedef void (*ndis_isr_handler)(unsigned int *taken, unsigned int *callme,
				 void *ctx) STDCALL;
typedef void (*ndis_interrupt_handler)(void *ctx) STDCALL;

struct miniport_char {
	/* NDIS 3.0 */
	UCHAR majorVersion;
	UCHAR minorVersion;
	USHORT filler;
	UINT reserved;

	BOOLEAN (*hangcheck)(void *ctx) STDCALL;
	void (*disable_interrupts)(void *ctx) STDCALL;
	void (*enable_interrupts)(void *ctx) STDCALL;

	/* Stop miniport */
	void (*halt)(void *ctx) STDCALL;

	/* Interrupt BH */
	ndis_interrupt_handler handle_interrupt;

	/* Start miniport driver */
	UINT (*init)(UINT *status, UINT *medium_index,
		     enum ndis_medium medium[], UINT medium_array_size,
		     void *ndis_handle, void *conf_handle) STDCALL;

	/* Interrupt TH */
	ndis_isr_handler isr;

	/* Query parameters */
	UINT (*query)(void *ctx, UINT oid, char *buffer,
		      UINT buflen, UINT *written, UINT *needed) STDCALL;

	void * ReconfigureHandler;
	INT (*reset)(INT *needs_set, void *ctx) STDCALL;

	/* Send one packet */
	UINT (*send)(void *ctx, struct ndis_packet *packet,
		     UINT flags) STDCALL;

	/* Set parameters */
	UINT (*setinfo)(void *ctx, UINT oid, char *buffer, UINT buflen,
			UINT *written, UINT *needed) STDCALL;

	/* transfer data from received packet */
	UINT (*tx_data)(struct ndis_packet *ndis_packet, UINT *bytes_txed,
				void *adapter_ctx, void *rx_ctx,
				UINT offset, UINT bytes_to_tx) STDCALL;

	/* NDIS 4.0 extensions */
	/* upper layer is done with RX packet */
	void (*return_packet)(void *ctx, void *packet) STDCALL;

	/* Send packets */
	UINT (*send_packets)(void *ctx, struct ndis_packet **packets,
			     INT nr_of_packets) STDCALL;

	void (*alloc_complete)(void *handle, void *virt,
			       NDIS_PHY_ADDRESS *phys,
			       ULONG size, void *ctx) STDCALL;

	/* NDIS 5.0 extensions */
	UINT (*co_create_vc)(void *ctx, void *vc_handle, void *vc_ctx) STDCALL;
	UINT (*co_delete_vc)(void *vc_ctx) STDCALL;
	UINT (*co_activate_vc)(void *vc_ctx, void *call_params) STDCALL;
	UINT (*co_deactivate_vc)(void *vc_ctx) STDCALL;
	UINT (*co_send_packets)(void *vc_ctx, void **packets,
				UINT nr_of_packets) STDCALL;
	UINT (*co_request)(void *ctx, void *vc_ctx, UINT *req) STDCALL;

	/* NDIS 5.1 extensions */
	void *cancel_send_packets;
	void (*pnp_event_notify)(void *ctx, enum ndis_device_pnp_event,
				 void *inf_buf, ULONG inf_buf_len) STDCALL;
	void (*adapter_shutdown)(void *ctx) STDCALL;
	void *reserved1;
	void *reserved2;
	void *reserved3;
	void *reserved4;

};

#ifdef CONFIG_DEBUG_SPINLOCK
#define NDIS_SPINLOCK(lock) (lock)->lock
#else
#define NDIS_SPINLOCK(lock) (struct wrap_spinlock *)(lock)
#endif

struct ndis_spinlock {
	KSPIN_LOCK lock;
	KIRQL use_bh;
};

struct handle_ctx_entry {
	struct list_head list;
	void *handle;
	void *ctx;
};

struct ndis_sched_work_item {
	void *ctx;
	void (*func)(struct ndis_sched_work_item *, void *) STDCALL;
	UCHAR reserved[8 * sizeof(void *)];
};

struct ndis_io_work_item {
	void *ctx;
	void *device_object;
	void (*func)(void *device_object, void *ctx) STDCALL;
};

struct ndis_alloc_mem_work_item {
	unsigned long size;
	char cached;
	void *ctx;
};

struct ndis_free_mem_work_item {
	void *addr;
	unsigned int length;
	unsigned int flags;
};

enum ndis_work_entry_type {
	NDIS_SCHED_WORK_ITEM,
	NDIS_ALLOC_MEM_WORK_ITEM,
	NDIS_FREE_MEM_WORK_ITEM,
	NDIS_IO_WORK_ITEM,
	NDIS_RETURN_PACKET_WORK_ITEM,
};

struct ndis_work_entry {
	struct list_head list;
	enum ndis_work_entry_type type;
	struct ndis_handle *handle;
	union {
		struct ndis_sched_work_item *sched_work_item;
		struct ndis_alloc_mem_work_item alloc_mem_work_item;
		struct ndis_free_mem_work_item free_mem_work_item;
		struct ndis_io_work_item *io_work_item;
		struct ndis_packet *return_packet;
	} entry;
};

struct ndis_irq {
	/* void *intr_obj is used for irq */
	union {
		void *intr_obj;
		unsigned int irq;
	} irq;
	/* Taken by ISR, DisableInterrupt and SynchronizeWithInterrupt */
	KSPIN_LOCK lock;
	void *id;
	ndis_isr_handler isr;
	void *dpc;

	struct kdpc intr_dpc;
	struct ndis_handle *handle;
	UCHAR dpc_count;
	/* unsigned char filler1 is used for enabled */
	UCHAR enabled;
	struct kevent completed_event;
	UCHAR shared;
	UCHAR req_isr;
};

struct ndis_binary_data {
	USHORT len;
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

struct ndis_config_param {
	enum ndis_config_param_type type;
	union {
		ULONG intval;
		struct unicode_string ustring;
		struct ndis_binary_data binary_data;
	} data;
};

struct device_setting {
	struct list_head list;
	char name[MAX_NDIS_SETTING_NAME_LEN];
	char value[MAX_NDIS_SETTING_VALUE_LEN];
	struct ndis_config_param config_param;
};

struct ndis_bin_file {
	char name[MAX_NDIS_SETTING_NAME_LEN];
	int size;
	void *data;
};

/*
 * There is one of these per driver. One per loaded driver exists.
 *
 */
struct ndis_driver {
	CSHORT type;
	CSHORT size;
	void *dev_object;
	ULONG flags;
	void *driver_start;
	ULONG driver_size;
	void *driver_section;
	void *driver_extension;
	struct ustring *driver_name;
	void *hardware_database;
	void *fast_io_dispatch;
	void *driver_init;
	void *driver_start_io;
	void (*driver_unload)(struct ndis_driver *driver) STDCALL;
	void *major_func[IRP_MJ_MAXIMUM_FUNCTION + 1];

	/* rest is ndiswrapper specific info */
	void *entry;
	struct list_head list;
	char name[MAX_NDIS_SETTING_NAME_LEN];
	char version[MAX_NDIS_SETTING_VALUE_LEN];

	int bustype;

	unsigned int num_pe_images;
	struct pe_image pe_images[MAX_PE_IMAGES];

	int num_bin_files;
	struct ndis_bin_file *bin_files;

	atomic_t users;
	struct miniport_char miniport_char;
};

struct ndis_handle;

/*
 * There is one of these per handeled device-id
 *
 */
struct ndis_device {
	struct list_head settings;
	int bustype;
	int vendor;
	int device;
	int subvendor;
	int subdevice;

	struct ndis_driver *driver;
	char driver_name[MAX_DRIVER_NAME_LEN];
	struct ndis_handle *handle;
};

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

enum ndis_status_type {
	Ndis802_11StatusType_Authentication,
	Ndis802_11StatusTypeMax
};

enum wrapper_work {
	WRAPPER_LINK_STATUS,
	SET_INFRA_MODE,
	SET_ESSID,
	SET_PACKET_FILTER,
	COLLECT_STATS,
	SUSPEND_RESUME,
	/* do not work when this is set */
	SHUTDOWN
};

enum ndis_attributes {
	ATTR_SERIALIZED,
	ATTR_SURPRISE_REMOVE,
	ATTR_HALT_ON_SUSPEND,
};

enum hw_status {
	HW_NORMAL,
	HW_SUSPENDED,
	HW_HALTED,
	HW_UNAVAILABLE,
};

struct encr_info {
	struct encr_key {
		ULONG length;
		UCHAR key[NDIS_ENCODING_TOKEN_MAX];
	} keys[MAX_ENCR_KEYS];
	unsigned short active;
};

struct ndis_essid {
	ULONG length;
	UCHAR essid[NDIS_ESSID_MAX_SIZE];
};

enum network_infrastructure {
	Ndis802_11IBSS,
	Ndis802_11Infrastructure,
	Ndis802_11AutoUnknown,
	Ndis802_11InfrastructureMax
};

enum authentication_mode {
	Ndis802_11AuthModeOpen,
	Ndis802_11AuthModeShared,
	Ndis802_11AuthModeAutoSwitch,
	Ndis802_11AuthModeWPA,
	Ndis802_11AuthModeWPAPSK,
	Ndis802_11AuthModeWPANone,
	Ndis802_11AuthModeWPA2,
	Ndis802_11AuthModeWPA2PSK,
	Ndis802_11AuthModeMax
};

enum encryption_status {
	Ndis802_11WEPEnabled,
	Ndis802_11Encryption1Enabled = Ndis802_11WEPEnabled,
	Ndis802_11WEPDisabled,
	Ndis802_11EncryptionDisabled = Ndis802_11WEPDisabled,
	Ndis802_11WEPKeyAbsent,
	Ndis802_11Encryption1KeyAbsent = Ndis802_11WEPKeyAbsent,
	Ndis802_11WEPNotSupported,
	Ndis802_11EncryptionNotSupported = Ndis802_11WEPNotSupported,
	Ndis802_11Encryption2Enabled,
	Ndis802_11Encryption2KeyAbsent,
	Ndis802_11Encryption3Enabled,
	Ndis802_11Encryption3KeyAbsent
};

struct ndis_timer {
	struct ktimer ktimer;
	struct kdpc kdpc;
};

struct ndis_miniport_timer {
	struct ktimer ktimer;
	struct kdpc kdpc;
	void *timer_func;
	void *timer_ctx;
	struct ndis_handle *handle;
	struct ndis_miniport_timer *next;
};

#pragma pack(push,4)
struct ndis_resource_entry {
	UCHAR type;
	UCHAR share;
	USHORT flags;
	union {
		struct {
			PHYSICAL_ADDRESS start;
			ULONG length;
		} generic;
		struct {
			PHYSICAL_ADDRESS start;
			ULONG length;
		} port;
		struct {
			ULONG level;
			ULONG vector;
			KAFFINITY affinity;
		} interrupt;
		struct {
			PHYSICAL_ADDRESS start;
			ULONG length;
		} memory;
		struct {
			ULONG channel;
			ULONG port;
			ULONG reserved1;
		} dma;
		struct {
			ULONG data[3];
		} device_private;
		struct {
			ULONG start;
			ULONG length;
			ULONG reserved;
		} bus_number;
		struct {
			ULONG data_size;
			ULONG reserved1;
			ULONG reserved2;
		} device_specific_data;
	} u;
};
#pragma pack(pop)

struct ndis_resource_list {
	USHORT version;
	USHORT revision;
	ULONG length;
	struct ndis_resource_entry list[0];
};

struct ndis_event {
	struct kevent kevent;
};

struct ndis_bind_paths {
	UINT number;
	struct unicode_string paths[1];
};

struct ndis_reference {
	KSPIN_LOCK lock;
	USHORT ref_count;
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

enum ndis_interface_type {
	NdisInterfaceInternal,
	NdisInterfaceIsa,
	NdisInterfaceEisa,
	NdisInterfaceMca,
	NdisInterfaceTurboChannel,
	NdisInterfacePci,
	NdisInterfacePcMcia,
};

/*
 * This is the per device struct. One per PCI-device exists.
 *
 * This struct contains function pointers that the drivers references
 * directly via macros, so it's important that they are at the correct
 * position hence the paddings.
 */
struct ndis_handle {
	void *signature;
	struct ndis_handle *next;
	struct ndis_driver *driver;
	void *adapter_ctx;
	struct unicode_string name;
	struct ndis_bind_paths *bindpaths;
	void *openqueue;
	struct ndis_reference reference;
	void *device_ctx;
	UCHAR padding;
	UCHAR lock_acquired;
	UCHAR pmode_opens;
	UCHAR assigned_cpu;
	KSPIN_LOCK kspin_lock;
	enum ndis_request_type *mediarequest;
	struct ndis_miniport_interrupt *interrupt;
	ULONG flags;
	ULONG pnp_flags;
	struct list_entry packet_list;
	struct ndis_packet *first_pending_tx_packet;
	struct ndis_packet *return_packet_queue;
	ULONG request_buffer;
	void *set_mcast_buffer;
	struct ndis_handle *primary_miniport;
	void *wrapper_ctx;
	void *bus_data_ctx;
	ULONG pnp_capa;
	void *resources;
	struct ndis_timer wakeup_dpc_timer;
	struct unicode_string basename;
	struct unicode_string symlink_name;
	ULONG ndis_hangcheck_interval;
	USHORT hanghcheck_ticks;
	USHORT hangcheck_tick;
	NDIS_STATUS ndis_reset_status;
	void *resetopen;
	struct ndis_filterdbs filterdbs;
	void *rx_packet;
	void *send_complete;
	void *send_resource_avail;
	void *reset_complete;

	enum ndis_medium media_type;
	ULONG bus_number;
	enum ndis_interface_type bus_type;
	enum ndis_interface_type adapter_type;
	struct device_object *device_obj;
	struct device_object *phys_device_obj;
	struct device_object *next_device_obj;
	void *mapreg;
	void *call_mgraflist;
	void *miniport_thread;
	void *setinfobuf;
	USHORT setinfo_buf_len;
	USHORT max_send_pkts;
	NDIS_STATUS fake_status;
	void *lock_handler;
	struct unicode_string *adapter_instance_name;
	void *timer_queue;
	UINT mac_options;
	void *pending_req;
	UINT max_long_addrs;
	UINT max_short_addrs;
	UINT cur_lookahead;
	UINT max_lookahead;

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
	int sg_dma;
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

	unsigned char link_status;
	struct encr_info encr_info;
	char nick[IW_ESSID_MAX_SIZE+1];

	u32 pci_state[16];
	unsigned long hw_status;

	struct ndis_essid essid;

	unsigned long capa;
	enum authentication_mode auth_mode;
	enum encryption_status encr_mode;
	enum network_infrastructure infrastructure_mode;

	mac_address mac;

	/* List of initialized timers */
	struct list_head timers;
	struct wrap_spinlock timers_lock;

	struct proc_dir_entry *procfs_iface;

	struct work_struct wrapper_worker;
	unsigned long wrapper_work;

	unsigned long attributes;
	struct wrap_spinlock lock;
	struct ndis_resource_list *pci_resources;
};

STDCALL void NdisMIndicateReceivePacket(struct ndis_handle *handle,
					struct ndis_packet **packets,
					UINT nr_packets);
STDCALL void NdisMSendComplete(struct ndis_handle *handle,
			       struct ndis_packet *packet, NDIS_STATUS status);
STDCALL void NdisMSendResourcesAvailable(struct ndis_handle *handle);
STDCALL void NdisMIndicateStatus(struct ndis_handle *handle,
				 NDIS_STATUS status, void *buf, UINT len);
STDCALL void NdisMIndicateStatusComplete(struct ndis_handle *handle);
STDCALL void NdisMQueryInformationComplete(struct ndis_handle *handle,
					   NDIS_STATUS status);
STDCALL void NdisMSetInformationComplete(struct ndis_handle *handle,
					 NDIS_STATUS status);
STDCALL void NdisMResetComplete(struct ndis_handle *handle, NDIS_STATUS status,
				BOOLEAN address_reset);
STDCALL ULONG NDIS_BUFFER_TO_SPAN_PAGES(ndis_buffer *buffer);
STDCALL BOOLEAN NdisWaitEvent(struct ndis_event *event, UINT timeout);
STDCALL void NdisSetEvent(struct ndis_event *event);
STDCALL void NdisMDeregisterInterrupt(struct ndis_irq *ndis_irq);
STDCALL void EthRxIndicateHandler(void *adapter_ctx, void *rx_ctx,
				  char *header1, char *header,
				  UINT header_size, void *look_ahead,
				  UINT look_ahead_size, UINT packet_size);
STDCALL void EthRxComplete(struct ndis_handle *handle);
STDCALL void NdisMTransferDataComplete(struct ndis_handle *handle,
				       struct ndis_packet *packet,
				       NDIS_STATUS status, UINT bytes_txed);
STDCALL void NdisWriteConfiguration(NDIS_STATUS *status,
				    struct ndis_handle *handle,
				    struct unicode_string *key,
				    struct ndis_config_param *val);

STDCALL NT_STATUS RtlUnicodeStringToAnsiString(struct ansi_string *dst,
					       struct unicode_string *src,
					       BOOLEAN dup);
STDCALL NT_STATUS RtlAnsiStringToUnicodeString(struct unicode_string *dst,
					       struct ansi_string *src,
					       BOOLEAN dup);
STDCALL void RtlInitAnsiString(struct ansi_string *dst, CHAR *src);
STDCALL void RtlInitString(struct ansi_string *dst, CHAR *src);
STDCALL void RtlFreeUnicodeString(struct unicode_string *string);
STDCALL void RtlFreeAnsiString(struct ansi_string *string);

void *get_sp(void);
int ndis_init(void);
void ndis_exit_handle(struct ndis_handle *handle);
void ndis_exit(void);

int usb_init(void);
void usb_exit(void);

int ndiswrapper_procfs_init(void);
int ndiswrapper_procfs_add_iface(struct ndis_handle *handle);
void ndiswrapper_procfs_remove_iface(struct ndis_handle *handle);
void ndiswrapper_procfs_remove(void);

void packet_recycler(void *param);
int stricmp(const char *s1, const char *s2);

void usb_cleanup(void);

/* Required OIDs */
#define OID_GEN_SUPPORTED_LIST			0x00010101
#define OID_GEN_HARDWARE_STATUS			0x00010102
#define OID_GEN_MEDIA_SUPPORTED			0x00010103
#define OID_GEN_MEDIA_IN_USE			0x00010104
#define OID_GEN_MAXIMUM_LOOKAHEAD		0x00010105
#define OID_GEN_MAXIMUM_FRAME_SIZE		0x00010106
#define OID_GEN_LINK_SPEED			0x00010107
#define OID_GEN_TRANSMIT_BUFFER_SPACE		0x00010108
#define OID_GEN_RECEIVE_BUFFER_SPACE		0x00010109
#define OID_GEN_TRANSMIT_BLOCK_SIZE		0x0001010A
#define OID_GEN_RECEIVE_BLOCK_SIZE		0x0001010B
#define OID_GEN_VENDOR_ID			0x0001010C
#define OID_GEN_VENDOR_DESCRIPTION		0x0001010D
#define OID_GEN_CURRENT_PACKET_FILTER		0x0001010E
#define OID_GEN_CURRENT_LOOKAHEAD		0x0001010F
#define OID_GEN_DRIVER_VERSION			0x00010110
#define OID_GEN_MAXIMUM_TOTAL_SIZE		0x00010111
#define OID_GEN_PROTOCOL_OPTIONS		0x00010112
#define OID_GEN_MAC_OPTIONS			0x00010113
#define OID_GEN_MEDIA_CONNECT_STATUS		0x00010114
#define OID_GEN_MAXIMUM_SEND_PACKETS		0x00010115
#define OID_GEN_VENDOR_DRIVER_VERSION		0x00010116
#define OID_GEN_SUPPORTED_GUIDS			0x00010117
#define OID_GEN_NETWORK_LAYER_ADDRESSES		0x00010118	/* Set only */
#define OID_GEN_TRANSPORT_HEADER_OFFSET		0x00010119	/* Set only */
#define OID_GEN_MACHINE_NAME			0x0001021A
#define OID_GEN_RNDIS_CONFIG_PARAMETER		0x0001021B	/* Set only */
#define OID_GEN_VLAN_ID				0x0001021C

/* Optional OIDs. */
#define OID_GEN_MEDIA_CAPABILITIES		0x00010201
#define OID_GEN_PHYSICAL_MEDIUM			0x00010202

/* Required statistics OIDs. */
#define OID_GEN_XMIT_OK				0x00020101
#define OID_GEN_RCV_OK				0x00020102
#define OID_GEN_XMIT_ERROR			0x00020103
#define OID_GEN_RCV_ERROR			0x00020104
#define OID_GEN_RCV_NO_BUFFER			0x00020105

/* Optional OID statistics */
#define OID_GEN_DIRECTED_BYTES_XMIT		0x00020201
#define OID_GEN_DIRECTED_FRAMES_XMIT		0x00020202
#define OID_GEN_MULTICAST_BYTES_XMIT		0x00020203
#define OID_GEN_MULTICAST_FRAMES_XMIT		0x00020204
#define OID_GEN_BROADCAST_BYTES_XMIT		0x00020205
#define OID_GEN_BROADCAST_FRAMES_XMIT		0x00020206
#define OID_GEN_DIRECTED_BYTES_RCV		0x00020207
#define OID_GEN_DIRECTED_FRAMES_RCV		0x00020208
#define OID_GEN_MULTICAST_BYTES_RCV		0x00020209
#define OID_GEN_MULTICAST_FRAMES_RCV		0x0002020A
#define OID_GEN_BROADCAST_BYTES_RCV		0x0002020B
#define OID_GEN_BROADCAST_FRAMES_RCV		0x0002020C
#define OID_GEN_RCV_CRC_ERROR			0x0002020D
#define OID_GEN_TRANSMIT_QUEUE_LENGTH		0x0002020E
#define OID_GEN_GET_TIME_CAPS			0x0002020F
#define OID_GEN_GET_NETCARD_TIME		0x00020210
#define OID_GEN_NETCARD_LOAD			0x00020211
#define OID_GEN_DEVICE_PROFILE			0x00020212

/* 802.3 (ethernet) OIDs */
#define OID_802_3_PERMANENT_ADDRESS		0x01010101
#define OID_802_3_CURRENT_ADDRESS		0x01010102
#define OID_802_3_MULTICAST_LIST		0x01010103
#define OID_802_3_MAXIMUM_LIST_SIZE		0x01010104
#define OID_802_3_MAC_OPTIONS			0x01010105
#define NDIS_802_3_MAC_OPTION_PRIORITY		0x00000001
#define OID_802_3_RCV_ERROR_ALIGNMENT		0x01020101
#define OID_802_3_XMIT_ONE_COLLISION		0x01020102
#define OID_802_3_XMIT_MORE_COLLISIONS		0x01020103
#define OID_802_3_XMIT_DEFERRED			0x01020201
#define OID_802_3_XMIT_MAX_COLLISIONS		0x01020202
#define OID_802_3_RCV_OVERRUN			0x01020203
#define OID_802_3_XMIT_UNDERRUN			0x01020204
#define OID_802_3_XMIT_HEARTBEAT_FAILURE	0x01020205
#define OID_802_3_XMIT_TIMES_CRS_LOST		0x01020206
#define OID_802_3_XMIT_LATE_COLLISIONS		0x01020207

/* PnP and power management OIDs */
#define OID_PNP_CAPABILITIES			0xFD010100
#define OID_PNP_SET_POWER			0xFD010101
#define OID_PNP_QUERY_POWER			0xFD010102
#define OID_PNP_ADD_WAKE_UP_PATTERN		0xFD010103
#define OID_PNP_REMOVE_WAKE_UP_PATTERN		0xFD010104
#define OID_PNP_WAKE_UP_PATTERN_LIST		0xFD010105
#define OID_PNP_ENABLE_WAKE_UP			0xFD010106

/* PnP/PM Statistics (Optional). */
#define OID_PNP_WAKE_UP_OK			0xFD020200
#define OID_PNP_WAKE_UP_ERROR			0xFD020201

/* The following bits are defined for OID_PNP_ENABLE_WAKE_UP */
#define NDIS_PNP_WAKE_UP_MAGIC_PACKET		0x00000001
#define NDIS_PNP_WAKE_UP_PATTERN_MATCH		0x00000002
#define NDIS_PNP_WAKE_UP_LINK_CHANGE		0x00000004

/* 802.11 OIDs */
#define OID_802_11_BSSID			0x0D010101
#define OID_802_11_SSID				0x0D010102
#define OID_802_11_NETWORK_TYPES_SUPPORTED	0x0D010203
#define OID_802_11_NETWORK_TYPE_IN_USE		0x0D010204
#define OID_802_11_TX_POWER_LEVEL		0x0D010205
#define OID_802_11_RSSI				0x0D010206
#define OID_802_11_RSSI_TRIGGER			0x0D010207
#define OID_802_11_INFRASTRUCTURE_MODE		0x0D010108
#define OID_802_11_FRAGMENTATION_THRESHOLD	0x0D010209
#define OID_802_11_RTS_THRESHOLD		0x0D01020A
#define OID_802_11_NUMBER_OF_ANTENNAS		0x0D01020B
#define OID_802_11_RX_ANTENNA_SELECTED		0x0D01020C
#define OID_802_11_TX_ANTENNA_SELECTED		0x0D01020D
#define OID_802_11_SUPPORTED_RATES		0x0D01020E
#define OID_802_11_DESIRED_RATES		0x0D010210
#define OID_802_11_CONFIGURATION		0x0D010211
#define OID_802_11_STATISTICS			0x0D020212
#define OID_802_11_ADD_WEP			0x0D010113
#define OID_802_11_REMOVE_WEP			0x0D010114
#define OID_802_11_DISASSOCIATE			0x0D010115
#define OID_802_11_POWER_MODE			0x0D010216
#define OID_802_11_BSSID_LIST			0x0D010217
#define OID_802_11_AUTHENTICATION_MODE		0x0D010118
#define OID_802_11_PRIVACY_FILTER		0x0D010119
#define OID_802_11_BSSID_LIST_SCAN		0x0D01011A
#define OID_802_11_WEP_STATUS			0x0D01011B
#define OID_802_11_ENCRYPTION_STATUS		OID_802_11_WEP_STATUS
#define OID_802_11_RELOAD_DEFAULTS		0x0D01011C
#define OID_802_11_ADD_KEY			0x0D01011D
#define OID_802_11_REMOVE_KEY			0x0D01011E
#define OID_802_11_ASSOCIATION_INFORMATION	0x0D01011F
#define OID_802_11_TEST				0x0D010120

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

#endif /* NDIS_H */
