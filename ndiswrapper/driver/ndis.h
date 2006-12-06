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

#ifndef _NDIS_H_
#define _NDIS_H_

#include "ntoskernel.h"

#define NDIS_DMA_24BITS 0
#define NDIS_DMA_32BITS 1
#define NDIS_DMA_64BITS 2

#ifdef CONFIG_X86_64
#define MAXIMUM_PROCESSORS  64
#else
#define MAXIMUM_PROCESSORS  32
#endif

typedef UINT NDIS_STATUS;
typedef UCHAR NDIS_DMA_SIZE;
typedef LONG ndis_rssi;
typedef ULONG ndis_key_index;
typedef ULONG ndis_tx_power_level;
typedef ULONGULONG ndis_key_rsc;
typedef UCHAR ndis_rates[NDIS_MAX_RATES];
typedef UCHAR ndis_rates_ex[NDIS_MAX_RATES_EX];
typedef UCHAR mac_address[ETH_ALEN];
typedef ULONG ndis_fragmentation_threshold;
typedef ULONG ndis_rts_threshold;
typedef ULONG ndis_antenna;
typedef ULONG ndis_oid;
typedef ULONG NET_IFINDEX;
typedef ULONG NDIS_PORT_NUMBER;
typedef ULONG NDIS_OID;
typedef UINT16 NET_IFTYPE;

typedef uint64_t NDIS_PHY_ADDRESS;

#define IF_MAX_PHYS_ADDRESS_LENGTH 32
#define NDIS_MAX_PHYS_ADDRESS_LENGTH IF_MAX_PHYS_ADDRESS_LENGTH

typedef PHYSICAL_ADDRESS NDIS_PHYSICAL_ADDRESS;

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

struct ndis_buffer_pool {
	int max_descr;
	int num_allocated_descr;
	ndis_buffer *free_descr;
	NT_SPIN_LOCK lock;
};

#define NDIS_PROTOCOL_ID_DEFAULT	0x00
#define NDIS_PROTOCOL_ID_TCP_IP		0x02
#define NDIS_PROTOCOL_ID_IPX		0x06
#define NDIS_PROTOCOL_ID_NBF		0x07
#define NDIS_PROTOCOL_ID_MAX		0x0F
#define NDIS_PROTOCOL_ID_MASK		0x0F

#define fPACKET_WRAPPER_RESERVED		0x3F
#define fPACKET_CONTAINS_MEDIA_SPECIFIC_INFO	0x40
#define fPACKET_ALLOCATED_BY_NDIS		0x80

#define PROTOCOL_RESERVED_SIZE_IN_PACKET (4 * sizeof(void *))

struct transport_header_offset {
	USHORT protocol_type;
	USHORT header_offset;
};

struct ndis_network_address {
	USHORT length;
	USHORT type;
	UCHAR address[1];
};

struct ndis_network_address_list {
	LONG count;
	USHORT type;
	struct ndis_network_address address[1];
};

struct ndis_tcp_ip_checksum_packet_info {
	union {
		struct {
			ULONG v4:1;
			ULONG v6:1;
			ULONG tcp:1;
			ULONG udp:1;
			ULONG ip:1;
		} tx;
		struct {
			ULONG tcp_failed:1;
			ULONG udp_failed:1;
			ULONG ip_failed:1;
			ULONG tcp_succeeded:1;
			ULONG udp_succeeded:1;
			ULONG ip_succeeded:1;
			ULONG loopback:1;
		} rx;
		ULONG value;
	};
};

enum ndis_task {
	TcpIpChecksumNdisTask, IpSecNdisTask, TcpLargeSendNdisTask, MaxNdisTask
};

enum ndis_encapsulation {
	UNSPECIFIED_Encapsulation, NULL_Encapsulation,
	IEEE_802_3_Encapsulation, IEEE_802_5_Encapsulation,
	LLC_SNAP_ROUTED_Encapsulation, LLC_SNAP_BRIDGED_Encapsulation
};

#define NDIS_TASK_OFFLOAD_VERSION 1

struct ndis_encapsulation_format {
	enum ndis_encapsulation encapsulation;
	struct {
		ULONG fixed_header_size:1;
		ULONG reserved:31;
	} flags;
	ULONG header_size;
};

struct ndis_task_offload_header {
	ULONG version;
	ULONG size;
	ULONG reserved;
	ULONG offset_first_task;
	struct ndis_encapsulation_format encapsulation_format;
};

struct ndis_task_offload {
	ULONG version;
	ULONG size;
	enum ndis_task task;
	ULONG offset_next_task;
	ULONG task_buf_length;
	UCHAR task_buf[1];
};

struct v4_checksum {
	union {
		struct {
			ULONG ip_supported:1;
			ULONG tcp_supported:1;
			ULONG tcp_csum:1;
			ULONG udp_csum:1;
			ULONG ip_csum:1;
		};
		ULONG value;
	};

};

struct v6_checksum {
	ULONG ip_supported:1;
	ULONG tcp_supported:1;
	ULONG tcp_csum:1;
	ULONG udp_csum:1;
};

struct ndis_task_tcp_ip_checksum {
	struct v4_checksum v4_tx;
	struct v4_checksum v4_rx;
	struct v6_checksum v6_tx;
	struct v6_checksum v6_rx;
};

enum ndis_per_packet_info {
	TcpIpChecksumPacketInfo, IpSecPacketInfo, TcpLargeSendPacketInfo,
	ClassificationHandlePacketInfo, NdisReserved,
	ScatterGatherListPacketInfo, Ieee8021QInfo, OriginalPacketInfo,
	PacketCancelId, MaxPerPacketInfo
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

/* OOB data */
struct ndis_packet_oob_data {
	union {
		ULONGLONG time_to_tx;
		ULONGLONG time_txed;
	};
	ULONGLONG time_rxed;
	UINT header_size;
	UINT mediaspecific_size;
	void *mediaspecific;
	NDIS_STATUS status;

	/* ndiswrapper specific info */
	struct ndis_packet_extension extension;

	struct ndis_packet *next;
	struct scatterlist *sg_list;
	unsigned int sg_ents;
	struct ndis_sg_list ndis_sg_list;
	struct ndis_sg_element *ndis_sg_elements;
	/* RTL8180L overshoots past ndis_eg_elements (during
	 * MiniportSendPackets) and overwrites what is below, if SG
	 * DMA is used, so don't use ndis_sg_element in that
	 * case. This structure is used only when SG is disabled */
	struct ndis_sg_element ndis_sg_element;

	unsigned char header[ETH_HLEN];
	unsigned char *look_ahead;
	UINT look_ahead_size;
	struct sk_buff *skb;
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
};

#define NDIS_PACKET_OOB_DATA(packet)					\
	(struct ndis_packet_oob_data *)(((void *)(packet)) +		\
					(packet)->private.oob_offset)

struct ndis_packet_pool {
	UINT max_descr;
	UINT num_allocated_descr;
	UINT num_used_descr;
	struct ndis_packet *free_descr;
	NT_SPIN_LOCK lock;
	UINT proto_rsvd_length;
	struct nt_list list;
};

enum ndis_device_pnp_event {
	NdisDevicePnPEventQueryRemoved, NdisDevicePnPEventRemoved,
	NdisDevicePnPEventSurpriseRemoved, NdisDevicePnPEventQueryStopped,
	NdisDevicePnPEventStopped, NdisDevicePnPEventPowerProfileChanged,
	NdisDevicePnPEventFilterListChanged, NdisDevicePnPEventMaximum
};

enum ndis_request_type {
	NdisRequestQueryInformation, NdisRequestSetInformation,
	NdisRequestQueryStatistics, NdisRequestOpen, NdisRequestClose,
	NdisRequestSend, NdisRequestTransferData, NdisRequestReset,
	NdisRequestGeneric1, NdisRequestGeneric2, NdisRequestGeneric3,
	NdisRequestGeneric4, NdisRequestMethod,
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
	NdisMedium802_3, NdisMedium802_5, NdisMediumFddi, NdisMediumWan,
	NdisMediumLocalTalk, NdisMediumDix, NdisMediumArcnetRaw,
	NdisMediumArcnet878_2, NdisMediumAtm, NdisMediumWirelessWan,
	NdisMediumIrda, NdisMediumBpc, NdisMediumCoWan,
	NdisMedium1394, NdisMediumMax
};

enum ndis_physical_medium {
	NdisPhysicalMediumUnspecified, NdisPhysicalMediumWirelessLan,
	NdisPhysicalMediumCableModem, NdisPhysicalMediumPhoneLine,
	NdisPhysicalMediumPowerLine, NdisPhysicalMediumDSL,
	NdisPhysicalMediumFibreChannel, NdisPhysicalMedium1394,
	NdisPhysicalMediumWirelessWan, NdisPhysicalMediumMax
};

enum ndis_power_state {
	NdisDeviceStateUnspecified = 0,
	NdisDeviceStateD0, NdisDeviceStateD1, NdisDeviceStateD2,
	NdisDeviceStateD3, NdisDeviceStateMaximum
};

enum ndis_power_profile {
	NdisPowerProfileBattery, NdisPowerProfileAcOnLine
};

struct ndis_pm_wakeup_capabilities {
	enum ndis_power_state min_magic_packet_wakeup;
	enum ndis_power_state min_pattern_wakeup;
	enum ndis_power_state min_link_change_wakeup;
};

#define NDIS_PNP_WAKE_UP_MAGIC_PACKET			0x00000001
#define NDIS_PNP_WAKE_UP_PATTERN_MATCH			0x00000002
#define NDIS_PNP_WAKE_UP_LINK_CHANGE			0x00000004

struct ndis_pnp_capabilities {
	ULONG flags;
	struct ndis_pm_wakeup_capabilities wakeup_capa;
};

typedef void (*ndis_isr_handler)(BOOLEAN *recognized, BOOLEAN *queue_handler,
				 void *handle) wstdcall;
typedef void (*ndis_interrupt_handler)(void *ctx) wstdcall;

struct ndis_irq {
	/* void *intr_obj is used for irq */
	union {
		void *intr_obj;
		unsigned int irq;
	} irq;
	/* Taken by ISR, DisableInterrupt and SynchronizeWithInterrupt */
	NT_SPIN_LOCK lock;
	void *id;
	ndis_isr_handler isr;
	void *dpc;
	struct kdpc intr_dpc;
	struct ndis_miniport_block *nmb;
	UCHAR dpc_count;
	/* unsigned char filler1 is used for enabled */
	UCHAR enabled;
	struct nt_event completed_event;
	UCHAR shared;
	UCHAR req_isr;
};

struct miniport_char {
	/* NDIS 3.0 */
	UCHAR major_version;
	UCHAR minor_version;
	USHORT filler;
	UINT reserved;
	BOOLEAN (*hangcheck)(void *ctx) wstdcall;
	void (*disable_interrupt)(void *ctx) wstdcall;
	void (*enable_interrupt)(void *ctx) wstdcall;
	void (*miniport_halt)(void *ctx) wstdcall;
	ndis_interrupt_handler handle_interrupt;
	NDIS_STATUS (*init)(NDIS_STATUS *error_status, UINT *medium_index,
			    enum ndis_medium medium[], UINT medium_array_size,
			    void *handle, void *conf_handle) wstdcall;
	ndis_isr_handler isr;
	NDIS_STATUS (*query)(void *ctx, ndis_oid oid, void *buffer,
			     ULONG buflen, ULONG *written,
			     ULONG *needed) wstdcall;
	void *reconfig;
	NDIS_STATUS (*reset)(BOOLEAN *reset_address, void *ctx) wstdcall;
	NDIS_STATUS (*send)(void *ctx, struct ndis_packet *packet,
			    UINT flags) wstdcall;
	NDIS_STATUS (*setinfo)(void *ctx, ndis_oid oid, void *buffer,
			       ULONG buflen, ULONG *written,
			       ULONG *needed) wstdcall;
	NDIS_STATUS (*tx_data)(struct ndis_packet *ndis_packet,
			       UINT *bytes_txed, void *adapter_ctx,
			       void *rx_ctx, UINT offset,
			       UINT bytes_to_tx) wstdcall;
	/* NDIS 4.0 extensions */
	void (*return_packet)(void *ctx, void *packet) wstdcall;
	void (*send_packets)(void *ctx, struct ndis_packet **packets,
			     INT nr_of_packets) wstdcall;
	void (*alloc_complete)(void *handle, void *virt,
			       NDIS_PHY_ADDRESS *phys,
			       ULONG size, void *ctx) wstdcall;
	/* NDIS 5.0 extensions */
	NDIS_STATUS (*co_create_vc)(void *ctx, void *vc_handle,
				    void *vc_ctx) wstdcall;
	NDIS_STATUS (*co_delete_vc)(void *vc_ctx) wstdcall;
	NDIS_STATUS (*co_activate_vc)(void *vc_ctx, void *call_params) wstdcall;
	NDIS_STATUS (*co_deactivate_vc)(void *vc_ctx) wstdcall;
	NDIS_STATUS (*co_send_packets)(void *vc_ctx, void **packets,
				       UINT nr_of_packets) wstdcall;
	NDIS_STATUS (*co_request)(void *ctx, void *vc_ctx, UINT *req) wstdcall;
	/* NDIS 5.1 extensions */
	void (*cancel_send_packets)(void *ctx, void *id) wstdcall;
	void (*pnp_event_notify)(void *ctx, enum ndis_device_pnp_event event,
				 void *inf_buf, ULONG inf_buf_len) wstdcall;
	void (*shutdown)(void *ctx) wstdcall;
	void *reserved1;
	void *reserved2;
	void *reserved3;
	void *reserved4;
};

struct ndis_spinlock {
	NT_SPIN_LOCK klock;
	KIRQL irql;
};

union ndis_rw_lock_refcount {
	UINT ref_count;
	UCHAR cache_line[16];
};

struct ndis_rw_lock {
	union {
		struct {
			NT_SPIN_LOCK klock;
			void *context;
		} s;
		UCHAR reserved[16];
	} u;
	union ndis_rw_lock_refcount ref_count[MAXIMUM_PROCESSORS];
};

struct ndis_work_item;
typedef void (*NDIS_PROC)(struct ndis_work_item *, void *) wstdcall;

struct ndis_work_item {
	void *ctx;
	NDIS_PROC func;
	UCHAR reserved[8 * sizeof(void *)];
};

struct alloc_shared_mem {
	void *ctx;
	ULONG size;
	BOOLEAN cached;
};

struct ndis_work_entry {
	struct nt_list list;
	struct ndis_work_item *ndis_work_item;
};

struct ndis_miniport_block;

struct ndis_binary_data {
	USHORT len;
	void *buf;
};

enum ndis_parameter_type {
	NdisParameterInteger, NdisParameterHexInteger,
	NdisParameterString, NdisParameterMultiString,
};

typedef struct unicode_string NDIS_STRING;

struct ndis_configuration_parameter {
	enum ndis_parameter_type type;
	union {
		ULONG integer;
		NDIS_STRING string;
	} data;
};

/* IDs used to store extensions in driver_object's custom extension */
#define NDIS_DRIVER_CLIENT_ID 10

struct ndis_wireless_stats {
	ULONG length;
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
	LARGE_INTEGER tkip_local_mic_failures;
	LARGE_INTEGER tkip_icv_errors;
	LARGE_INTEGER tkip_counter_measures_invoked;
	LARGE_INTEGER tkip_replays;
	LARGE_INTEGER ccmp_format_errors;
	LARGE_INTEGER ccmp_replays;
	LARGE_INTEGER ccmp_decrypt_errors;
	LARGE_INTEGER fourway_handshake_failures;
	LARGE_INTEGER wep_undecryptable_count;
	LARGE_INTEGER wep_icv_errorcount;
	LARGE_INTEGER decrypt_success_count;
	LARGE_INTEGER decrypt_failure_count;
};

enum ndis_status_type {
	Ndis802_11StatusType_Authentication,
	Ndis802_11StatusType_MediaStreamMode,
	Ndis802_11StatusType_PMKID_CandidateList,
	Ndis802_11StatusType_RadioState,
};

enum ndis_radio_status {
	Ndis802_11RadioStatusOn, Ndis802_11RadioStatusHardwareOff,
	Ndis802_11RadioStatusSoftwareOff,
};

struct ndis_radio_status_indication
{
	enum ndis_status_type status_type;
	enum ndis_radio_status radio_state;
};

enum ndis_media_stream_mode {
	Ndis802_11MediaStreamOff, Ndis802_11MediaStreamOn
};

enum wrapper_work {
	LINK_STATUS_CHANGED, SET_MULTICAST_LIST, COLLECT_STATS, MINIPORT_RESET,
	/* do not work when this is set */
	SHUTDOWN
};

struct encr_info {
	struct encr_key {
		ULONG length;
		UCHAR key[NDIS_ENCODING_TOKEN_MAX];
	} keys[MAX_ENCR_KEYS];
	unsigned short tx_key_index;
};

struct ndis_essid {
	ULONG length;
	UCHAR essid[NDIS_ESSID_MAX_SIZE];
};

enum network_infrastructure {
	Ndis802_11IBSS, Ndis802_11Infrastructure, Ndis802_11AutoUnknown,
	Ndis802_11InfrastructureMax
};

enum authentication_mode {
	Ndis802_11AuthModeOpen, Ndis802_11AuthModeShared,
	Ndis802_11AuthModeAutoSwitch, Ndis802_11AuthModeWPA,
	Ndis802_11AuthModeWPAPSK, Ndis802_11AuthModeWPANone,
	Ndis802_11AuthModeWPA2, Ndis802_11AuthModeWPA2PSK,
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
	Ndis802_11Encryption2Enabled, Ndis802_11Encryption2KeyAbsent,
	Ndis802_11Encryption3Enabled, Ndis802_11Encryption3KeyAbsent
};

struct ndis_auth_encr_pair {
	enum authentication_mode auth_mode;
	enum encryption_status encr_mode;
};

struct ndis_capability {
	ULONG length;
	ULONG version;
	ULONG num_PMKIDs;
	ULONG num_auth_encr_pair;
	struct ndis_auth_encr_pair auth_encr_pair[1];
};

struct ndis_guid {
	struct guid guid;
	union {
		ndis_oid oid;
		NDIS_STATUS status;
	};
	ULONG size;
	ULONG flags;
};

struct ndis_timer {
	struct nt_timer nt_timer;
	struct kdpc kdpc;
};

struct ndis_miniport_timer {
	struct nt_timer nt_timer;
	struct kdpc kdpc;
	DPC func;
	void *ctx;
	struct ndis_miniport_block *nmb;
	struct ndis_miniport_timer *next;
};

typedef struct cm_partial_resource_list ndis_resource_list_t;

struct ndis_event {
	struct nt_event nt_event;
};

struct ndis_bind_paths {
	UINT number;
	struct unicode_string paths[1];
};

struct ndis_reference {
	NT_SPIN_LOCK lock;
	USHORT ref_count;
	BOOLEAN closing;
};

struct ndis_miniport_interrupt {
	void *object;
	NT_SPIN_LOCK dpc_count_lock;
	void *reserved;
	ndis_isr_handler irq_th;
	ndis_interrupt_handler irq_bh;
	struct kdpc interrupt_dpc;
	struct ndis_miniport_block *nmb;
	UCHAR dpc_count;
	BOOLEAN filler1;
	struct nt_event dpcs_completed_event;
	BOOLEAN shared_interrupt;
	BOOLEAN isr_requested;
};

#define NDIS_OBJECT_TYPE_DEFAULT				0x80
#define NDIS_OBJECT_TYPE_MINIPORT_INIT_PARAMETERS		0x81
#define NDIS_OBJECT_TYPE_SG_DMA_DESCRIPTION			0x83
#define NDIS_OBJECT_TYPE_MINIPORT_INTERRUPT			0x84
#define NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES		0x85
#define NDIS_OBJECT_TYPE_BIND_PARAMETERS			0x86
#define NDIS_OBJECT_TYPE_OPEN_PARAMETERS			0x87
#define NDIS_OBJECT_TYPE_RSS_CAPABILITIES			0x88
#define NDIS_OBJECT_TYPE_RSS_PARAMETERS				0x89
#define NDIS_OBJECT_TYPE_MINIPORT_DRIVER_CHARACTERISTICS	0x8A
#define NDIS_OBJECT_TYPE_FILTER_DRIVER_CHARACTERISTICS		0x8B
#define NDIS_OBJECT_TYPE_FILTER_PARTIAL_CHARACTERISTICS		0x8C
#define NDIS_OBJECT_TYPE_FILTER_ATTRIBUTES			0x8D
#define NDIS_OBJECT_TYPE_CLIENT_CHIMNEY_OFFLOAD_GENERIC_CHARACTERISTICS	0x8E
#define NDIS_OBJECT_TYPE_PROVIDER_CHIMNEY_OFFLOAD_GENERIC_CHARACTERISTICS 0x8F
#define NDIS_OBJECT_TYPE_CO_PROTOCOL_CHARACTERISTICS		0x90
#define NDIS_OBJECT_TYPE_CO_MINIPORT_CHARACTERISTICS		0x91
#define NDIS_OBJECT_TYPE_MINIPORT_PNP_CHARACTERISTICS		0x92
#define NDIS_OBJECT_TYPE_CLIENT_CHIMNEY_OFFLOAD_CHARACTERISTICS	0x93
#define NDIS_OBJECT_TYPE_PROVIDER_CHIMNEY_OFFLOAD_CHARACTERISTICS 0x94
#define NDIS_OBJECT_TYPE_PROTOCOL_DRIVER_CHARACTERISTICS	0x95
#define NDIS_OBJECT_TYPE_REQUEST_EX				0x96
#define NDIS_OBJECT_TYPE_OID_REQUEST				0x96
#define NDIS_OBJECT_TYPE_TIMER_CHARACTERISTICS			0x97
#define NDIS_OBJECT_TYPE_STATUS_INDICATION			0x98
#define NDIS_OBJECT_TYPE_FILTER_ATTACH_PARAMETERS		0x99
#define NDIS_OBJECT_TYPE_FILTER_PAUSE_PARAMETERS		0x9A
#define NDIS_OBJECT_TYPE_FILTER_RESTART_PARAMETERS		0x9B
#define NDIS_OBJECT_TYPE_PORT_CHARACTERISTICS			0x9C
#define NDIS_OBJECT_TYPE_PORT_STATE				0x9D
#define NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES	0x9E
#define NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES		0x9F
#define NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_OFFLOAD_ATTRIBUTES		0xA0
#define NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_NATIVE_802_11_ATTRIBUTES	0xA1
#define NDIS_OBJECT_TYPE_RESTART_GENERAL_ATTRIBUTES			0xA2
#define NDIS_OBJECT_TYPE_PROTOCOL_RESTART_PARAMETERS			0xA3
#define NDIS_OBJECT_TYPE_MINIPORT_ADD_DEVICE_REGISTRATION_ATTRIBUTES	0xA4
#define NDIS_OBJECT_TYPE_CO_CALL_MANAGER_OPTIONAL_HANDLERS		0xA5
#define NDIS_OBJECT_TYPE_CO_CLIENT_OPTIONAL_HANDLERS			0xA6
#define NDIS_OBJECT_TYPE_OFFLOAD					0xA7
#define NDIS_OBJECT_TYPE_OFFLOAD_ENCAPSULATION				0xA8
#define NDIS_OBJECT_TYPE_CONFIGURATION_OBJECT				0xA9
#define NDIS_OBJECT_TYPE_DRIVER_WRAPPER_OBJECT				0xAA
#define NDIS_OBJECT_TYPE_RESERVED					0xAB
#define NDIS_OBJECT_TYPE_NSI_NETWORK_RW_STRUCT				0xAC
#define NDIS_OBJECT_TYPE_NSI_COMPARTMENT_RW_STRUCT			0xAD
#define NDIS_OBJECT_TYPE_NSI_INTERFACE_PERSIST_RW_STRUCT		0xAE

struct ndis_object_header {
	UCHAR type;
	UCHAR revision;
	USHORT size;
};

struct ndis_generic_object {
	struct ndis_object_header header;
	void *caller;
	void *parent_caller;
	struct driver_object *driver_obj;
};

enum ndis_interface_type {
	NdisInterfaceInternal = Internal,
	NdisInterfaceIsa = Isa,
	NdisInterfaceEisa = Eisa,
	NdisInterfaceMca = MicroChannel,
	NdisInterfaceTurboChannel = TurboChannel,
	NdisInterfacePci = PCIBus,
	NdisInterfacePcMcia = PCMCIABus,
	NdisInterfaceCBus = CBus,
	NdisInterfaceMPIBus = MPIBus,
	NdisInterfaceMPSABus = MPSABus,
	NdisInterfaceProcessorInternal = ProcessorInternal,
	NdisInterfaceInternalPowerBus = InternalPowerBus,
	NdisInterfacePNPISABus = PNPISABus,
	NdisInterfacePNPBus = PNPBus,
	NdisInterfaceUSB,
	NdisInterfaceIrda,
	NdisInterface1394,
	NdisMaximumInterfaceType
};

struct mp_registration_attributes {
	struct ndis_object_header obj_header;
	void *ctx;
	ULONG flags;
	UINT hang_check_secs;
	enum ndis_interface_type interface_type;
};

typedef BOOLEAN (*mp_isr_handler)(void *, BOOLEAN *, ULONG *) wstdcall;
typedef void (*mp_isr_dpc_handler)(void *, void *, ULONG *, ULONG *) wstdcall;
typedef void (*mp_disable_interrupt_handler)(void *) wstdcall;
typedef void (*mp_enable_interrupt_handler)(void *) wstdcall;
typedef BOOLEAN (*mp_msi_isr_handler)(void *, BOOLEAN *, ULONG *) wstdcall;
typedef void (*mp_msi_isr_dpc_handler)(void *, ULONG, void *,
				       ULONG *, ULONG *) wstdcall;
typedef void (*mp_disable_msi_interrupt_handler)(void *, ULONG) wstdcall;
typedef void (*mp_enable_msi_interrupt_handler)(void *, ULONG) wstdcall;

enum ndis_interrupt_type {
	NDIS_CONNECT_LINE_BASED = 1,
	NDIS_CONNECT_MESSAGE_BASED
};

struct mp_interrupt_characteristics {
	struct ndis_object_header obj_header;
	mp_isr_handler isr;
	mp_isr_dpc_handler isr_dpc_handler;
	mp_disable_interrupt_handler disable_interrupt_handler;
	mp_enable_interrupt_handler enable_interrupt_handler;
	BOOLEAN msi_supported;
	BOOLEAN msi_sync_with_all_messages;
	mp_msi_isr_handler msi_isr;
	mp_msi_isr_dpc_handler msi_dpc_handler;
	mp_disable_msi_interrupt_handler disable_msi_interrupt_handler;
	mp_enable_msi_interrupt_handler enable_msi_interrupt_handler;
	enum ndis_interrupt_type interrupt_type;
	struct io_interrupt_message_info *message_info_table;
};

struct ndis_interrupt {
	NT_SPIN_LOCK lock;
	struct wrap_ndis_device *wnd;
	int vector;
};

struct mp_add_device_registration_attrs {
	struct ndis_object_header header;
	void *ctx;
};

struct mp_pnp_characteristics {
	struct ndis_object_header header;
	NDIS_STATUS (*add_device)(void *, void *) wstdcall;
	void (*remove_device)(void *) wstdcall;
	NDIS_STATUS (*filter_resource_requirements)(void *,
						    struct irp *) wstdcall;
	NDIS_STATUS (*start_device)(void *, struct irp *) wstdcall;
};

struct mp_adapter_registration_attrs {
	struct ndis_object_header header;
	void *ctx;
	ULONG attribute_flags;
	UINT check_for_hang_time_seconds;
	enum ndis_interface_type interface_type;
};

enum net_if_access_type {
	NET_IF_ACCESS_LOOPBACK = 1,
	NET_IF_ACCESS_BROADCAST = 2,
	NET_IF_ACCESS_POINT_TO_POINT = 3,
	NET_IF_ACCESS_POINT_TO_MULTI_POINT = 4,
	NET_IF_ACCESS_MAXIMUM = 5
};

enum net_if_direction_type {
	NET_IF_DIRECTION_SENDRECEIVE,
	NET_IF_DIRECTION_SENDONLY,
	NET_IF_DIRECTION_RECEIVEONLY,
	NET_IF_DIRECTION_MAXIMUM
};

enum net_if_connection_type {
	NET_IF_CONNECTION_DEDICATED = 1,
	NET_IF_CONNECTION_PASSIVE = 2,
	NET_IF_CONNECTION_DEMAND = 3,
	NET_IF_CONNECTION_MAXIMUM = 4
};

enum ndis_media_connect_state {
	MediaConnectStateUnknown, MediaConnectStateConnected,
	MediaConnectStateDisconnected
};

enum ndis_media_duplex_state {
	MediaDuplexStateUnknown, MediaDuplexStateHalf, MediaDuplexStateFull
};

enum ndis_supported_pause_functions {
	NdisPauseFunctionsUnsupported, NdisPauseFunctionsSendOnly,
	NdisPauseFunctionsReceiveOnly, NdisPauseFunctionsSendAndReceive,
	NdisPauseFunctionsUnknown
};

struct mp_adapter_general_attrs {
	struct ndis_object_header header;
	ULONG flags;
	enum ndis_medium media_type;
	enum ndis_physical_medium physical_medium_type;
	ULONG mtu_size;
	ULONG64 max_tx_link_speed;
	ULONG64 tx_link_speed;
	ULONG64 max_rx_link_speed;
	ULONG64 rx_link_speed;
	enum ndis_media_connect_state media_connec_tstate;
	enum ndis_media_duplex_state media_duplex_state;
	ULONG lookahead_size;
	struct ndis_pnp_capabilities *pm_capabilities;
	ULONG mac_options;
	ULONG supported_packet_filters;
	ULONG max_multicast_list_size;
	USHORT mac_address_length;
	UCHAR permanent_mac_address[NDIS_MAX_PHYS_ADDRESS_LENGTH];
	UCHAR current_mac_address[NDIS_MAX_PHYS_ADDRESS_LENGTH];
	struct ndis_rx_scale_capabilities *rx_scale_capabilities;
	enum net_if_access_type access_type;
	enum net_if_direction_type direction_type; 
	enum net_if_connection_type connection_type; 
	NET_IFTYPE if_type;
	BOOLEAN if_connector_present;
	ULONG supported_statistics; 
	ULONG supported_pause_functions;
	ULONG data_back_fill_size;
	ULONG context_back_fill_size;
	NDIS_OID *supported_oid_list;
	ULONG supported_oid_list_length;
	ULONG auto_negotiation_flags;
};

struct ndis_tcp_ip_checksum_offload {
	struct {
		ULONG encapsulation;
		ULONG ip_options_supported:2;
		ULONG tcp_options_supported:2;
		ULONG tcp_checksum:2;
		ULONG udp_checksum:2;
		ULONG ip_checksum:2;
	} ipv4_tx;
	struct {
		ULONG encapsulation;
		ULONG ip_options_supported:2;
		ULONG tcp_options_supported:2;
		ULONG tcp_checksum:2;
		ULONG udp_checksum:2;
		ULONG ip_checksum:2;
	} ipv4_rx;
	struct {
		ULONG encapsulation;
		ULONG ip_extension_headers_supported:2;
		ULONG tcp_options_supported:2;
		ULONG tcp_checksum:2;
		ULONG udp_checksum:2;
	} ipv6_tx;
	struct {
		ULONG encapsulation;
		ULONG ip_extension_headers_supported:2;
		ULONG tcp_options_supported:2;
		ULONG tcp_checksum:2;
		ULONG udp_checksum:2;
	} ipv6_rx;
};

struct ndis_ipsec_offload_v1 {
	struct {
		ULONG encapsulation;
		ULONG ah_esp_combined;
		ULONG transport_tunnel_combined;
		ULONG ipv4_options;
		ULONG flags;
	} supported;
	struct {
		ULONG md5:2;
		ULONG sha_1:2;
		ULONG transport:2;
		ULONG tunnel:2;
		ULONG tx:2;
		ULONG rx:2;
	} ipv4_ah;
	struct {
		ULONG des:2;
		ULONG flags:2;
		ULONG triple_des:2;
		ULONG null_esp:2;
		ULONG transport:2;
		ULONG tunnel:2;
		ULONG tx:2;
		ULONG rx;
	} ipv4_esp;
};

struct ndis_tcp_large_send_offload_v1 {
	struct {
		ULONG encapsulation;
		ULONG max_offload_size;
		ULONG min_segment_count;
		ULONG tcp_options:2;
		ULONG ip_options:2;
	} ipv4;
};

struct ndis_tcp_large_send_offload_v2 {
	struct {
		ULONG encapsulation;
		ULONG max_offload_size;
		ULONG min_segment_count;
	} ipv4;
	struct {
		ULONG encapsulation;
		ULONG max_offload_size;
		ULONG min_segment_count;
		ULONG ip_extension_headers_supported:2;
		ULONG tcp_options_supported:2;
	} ipv6;
};

struct ndis_offload {
	struct ndis_object_header header;
	struct ndis_tcp_ip_checksum_offload checksum;
	struct ndis_tcp_large_send_offload_v1 lso_v1;
	struct ndis_ipsec_offload_v1 ipsec_v1;
	struct ndis_tcp_large_send_offload_v2 lso_v2;
	ULONG flags; 
};

struct mp_adapter_offload_attrs {
	struct ndis_object_header header;
	struct ndis_offload *default_offload_config;
	struct ndis_offload *hw_offload_capa;
	struct ndis_tcp_connection_offload *default_tcp_offload_conf;
	struct ndis_tcp_connection_offload *tcp_offload_hw_capa;
};

#define NDIS_TCP_CONNECTION_OFFLOAD_REVISION_1 1
struct ndis_tcp_connection_offload
{
	struct ndis_object_header header;
	ULONG encapsulation;
	ULONG supportipv4:2;
	ULONG supportipv6:2;
	ULONG supportipv6extensionheaders:2;
	ULONG supportsack:2;
	ULONG tcpconnectionoffloadcapacity;
	ULONG flags;
};

enum dot11_phy_type {
	dot11_phy_type_unknown = 0,
	dot11_phy_type_any = dot11_phy_type_unknown,
	dot11_phy_type_fhss = 1,
	dot11_phy_type_dsss = 2,
	dot11_phy_type_irbaseband = 3,
	dot11_phy_type_ofdm = 4,
	dot11_phy_type_hrdsss = 5,
	dot11_phy_type_erp = 6,
	dot11_phy_type_IHV_start = 0x80000000,
	dot11_phy_type_IHV_end = 0xffffffff
};

enum dot11_temp_type {
	dot11_temp_type_unknown = 0,
	dot11_temp_type_1 = 1,
	dot11_temp_type_2 = 2
};

enum dot11_diversity_support {
	dot11_diversity_support_unknown = 0,
	dot11_diversity_support_fixedlist = 1,
	dot11_diversity_support_notsupported = 2,
	dot11_diversity_support_dynamic = 3
};

struct dot11_hrdsss_phy_attributes {
	BOOLEAN short_preamble_implemented;
	BOOLEAN pbcco_implemented;
	BOOLEAN channef_lagility_present;
	ULONG hrcca_supported;
};

struct dot11_ofdm_phy_attributes {
	ULONG freq_bands;
};

struct dot11_erp_phy_attributes {
	struct dot11_hrdsss_phy_attributes hrdss_attributes;
	BOOLEAN erppbcc_implemented;
	BOOLEAN dsssofdm_implemented;
	BOOLEAN short_slottime_implemented;
};

struct dot11_data_rate_mapping_entry {
	UCHAR index;
	UCHAR flag;
	USHORT value;
};

#define MAX_NUM_SUPPORTED_RATES_V2	255

struct dot11_supported_data_rates_value_v2 {
	UCHAR ucSupportedTxDataRatesValue[MAX_NUM_SUPPORTED_RATES_V2];
	UCHAR ucSupportedRxDataRatesValue[MAX_NUM_SUPPORTED_RATES_V2];
};

#define DOT11_RATE_SET_MAX_LENGTH		126
#define DOT11_PHY_ATTRIBUTES_REVISION_1		1

struct dot11_phy_attributes {
	struct ndis_object_header header;
	enum dot11_phy_type phy_type;
	BOOLEAN hw_phy_state;
	BOOLEAN sw_phy_state;
	BOOLEAN cf_pollable;
	ULONG mpdu_max_length;
	enum dot11_temp_type temp_type;
	enum dot11_diversity_support diversity_support;
	union {
		struct dot11_hrdsss_phy_attributes hrdsss_attrs;
		struct dot11_ofdm_phy_attributes ofdm_attrs;
		struct dot11_erp_phy_attributes erp_attrs;
		ULONG supported_power_levels;
		ULONG tx_power_levels[8];
		ULONG num_data_rate_mapping_entries;
		struct dot11_data_rate_mapping_entry data_rate_mapping_entries[DOT11_RATE_SET_MAX_LENGTH];
		struct dot11_supported_data_rates_value_v2 supported_data_rates_value;
	};
};

enum dot11_auth_algorithm {
	DOT11_AUTH_ALGO_80211_OPEN = 1,
	DOT11_AUTH_ALGO_80211_SHARED_KEY = 2,
	DOT11_AUTH_ALGO_WPA = 3,
	DOT11_AUTH_ALGO_WPA_PSK = 4,
	DOT11_AUTH_ALGO_WPA_NONE = 5,               // used in NatSTA only
	DOT11_AUTH_ALGO_RSNA = 6,
	DOT11_AUTH_ALGO_RSNA_PSK = 7,
	DOT11_AUTH_ALGO_IHV_START = 0x80000000,
	DOT11_AUTH_ALGO_IHV_END = 0xffffffff
};

enum dot11_cipher_algorithm {
    DOT11_CIPHER_ALGO_NONE = 0x00,
    DOT11_CIPHER_ALGO_WEP40 = 0x01,
    DOT11_CIPHER_ALGO_TKIP = 0x02,
    DOT11_CIPHER_ALGO_CCMP = 0x04,
    DOT11_CIPHER_ALGO_WEP104 = 0x05,
    DOT11_CIPHER_ALGO_WPA_USE_GROUP = 0x100,
    DOT11_CIPHER_ALGO_RSN_USE_GROUP = 0x100,
    DOT11_CIPHER_ALGO_WEP = 0x101,
    DOT11_CIPHER_ALGO_IHV_START = 0x80000000,
    DOT11_CIPHER_ALGO_IHV_END = 0xffffffff
};

struct dot11_auth_cipher_pair {
	enum dot11_auth_algorithm auth_algo_id;
	enum dot11_cipher_algorithm cipher_algo_id;
};

typedef UCHAR dot11_country_region_string_t[3];

#define DOT11_EXTSTA_ATTRIBUTES_REVISION_1  1
struct dot11_extsta_attributes {
	struct ndis_object_header header;
	ULONG scan_ssid_size;
	ULONG desired_bssid_size;
	ULONG desired_ssid_size;
	ULONG excluded_mac_size;
	ULONG privacy_exemption_size;
	ULONG key_mapping_size;
	ULONG default_key__size;
	ULONG wep_key_max_length;
	ULONG pmkid_cache_size;
	ULONG max_num_per_sta_default_key_tables;
	BOOLEAN strictly_ordered_service_class;
	UCHAR qos_protocol_flags;
	BOOLEAN safe_mode;
	ULONG num_country_region_strings;
	dot11_country_region_string_t country_region_strings;
	ULONG num_infra_ucast_algo_pairs;
	struct dot11_auth_cipher_pair infra_ucast_algo_pairs;
	ULONG num_infra_mcast_algo_pairs;
	struct dot11_auth_cipher_pair infra_mcast_algo_pairs;
	ULONG num_adhoc_ucast_algo_pairs;
	struct dot11_auth_cipher_pair adhoc_ucast_algo_pairs;
	ULONG num_adhoc_mcast_algo_pairs;
	struct dot11_auth_cipher_pair adhoc_mcast_algo_pairs;
};

struct mp_adapter_native_802_11_attrs {
	struct ndis_object_header header;
	ULONG op_mode_capability;
	ULONG num_tx_bufs;
	ULONG num_rx_bufs;
	BOOLEAN multi_domain_capability_implemented;
	ULONG num_supported_phys;
	struct dot11_phy_attributes supported_phy_attrs;
	struct dot11_extsta_attributes *ext_sta_attrs;
};

union mp_adapter_attrs {
	struct mp_add_device_registration_attrs add_device_reg_attrs;
	struct mp_adapter_registration_attrs registration_attrs;
	struct mp_adapter_general_attrs general_attrs;
	struct mp_adapter_offload_attrs offload_attrs;
	struct mp_adapter_native_802_11_attrs native_802_11_attrs;
};

struct nw_interrupt {
	unsigned int vector;
	NT_SPIN_LOCK lock;
	struct wrap_ndis_device *wnd;
};

struct ndis_link_state {
	struct ndis_object_header header;
	enum ndis_media_connect_state media_connect_state;
	enum ndis_media_duplex_state media_duplex_state;
	ULONG64 tx_link_speed;
	ULONG64 rx_link_speed;
	enum ndis_supported_pause_functions pause_funcs;
	ULONG auto_negotiation_flags;
};

struct ndis5_status_indication {
	enum ndis_status_type status_type;
};

struct ndis_status_indication {
	struct ndis_object_header header;
	void *src_handle;
	NDIS_PORT_NUMBER port;
	NDIS_STATUS code;
	ULONG flags;
	void *dst_handle;
	void *request_id;
	void *buf;
	ULONG buf_size;
	struct guid guid;
	void *reserved[4];
};

#define NDIS_MINIPORT_PAUSE_PARAMETERS_REVISION_1	1

struct mp_pause_params {
	struct ndis_object_header header;
	ULONG flags;
	ULONG reason;
};

struct ndis_restart_attrs {
	struct ndis_restart_attrs *next;
	NDIS_OID oid;
	ULONG data_length;
	unsigned char data[1] _align_(MEMORY_ALLOCATION_ALIGNMENT);
};

union net_luid {
	ULONG64 value;
	struct {
		ULONG64 reserved:24;
		ULONG64 net_luid_index:24;
		ULONG64 if_type:16;
	} info;
};

struct mp_restart_params {
	struct ndis_object_header header;
	char *filter_module_name;
	ULONG *filter_module_name_length;
	struct ndis_restart_attrs *attrs;
	NET_IFINDEX bound_if_index;
	union net_luid bound_if_net_luid;
	ULONG flags;
};

struct ndis_restart_general_attrs {
	struct ndis_object_header header;
	ULONG mtusize;
	ULONG64 max_tx_link_speed;
	ULONG64 max_rx_link_speed;
	ULONG lookahead_size;
	ULONG mac_options;
	ULONG supported_packet_filters;
	ULONG max_multicastlist_size;
	struct ndis_rx_scale_capabilities *rx_scale_capabilities;
	enum net_if_access_type access_type;
	enum net_if_direction_type direction_type; 
	enum net_if_connection_type connection_type; 
	ULONG supported_statistics; 
	ULONG data_back_fill_size;
	ULONG context_back_fill_size;
	NDIS_OID *supported_oid_list;
	ULONG supported_oid_list_length;
};

typedef struct unicode_string ndis_string_t;

struct ndis_device_object_attributes {
	struct ndis_object_header header;
	ndis_string_t dev_name;
	ndis_string_t symbolic_name;
	driver_dispatch_t **major_funcs;
	ULONG ext_size;
	struct unicode_string default_sddl_string;
	struct guid class_guid;
};

struct net_device_pnp_event {
	struct ndis_object_header header;
	NDIS_PORT_NUMBER port;
	enum ndis_device_pnp_event device_pnp_event;
	void *info_buf;
	ULONG info_buf_length;
	UCHAR reserved[2 * sizeof(void *)];
};

struct ndis_driver_optional_handlers {
	struct ndis_object_header header;
};

/* IDs used to store extensions in driver_object's custom extension */
#define NDIS_DRIVER_CLIENT_ID 10

enum ndis_port_control_state {
	NdisPortControlStateUnknown, NdisPortControlStateControlled,
	NdisPortControlStateUncontrolled
};

enum ndis_port_authorization_state {
	NdisPortAuthorizationUnknown, NdisPortAuthorized, NdisPortUnauthorized,
	NdisPortReauthorizing
};

struct ndis_port_authentication_params {
	struct ndis_object_header header;
	enum ndis_port_control_state tx_control_state;
	enum ndis_port_control_state rx_control_state;
	enum ndis_port_authorization_state tx_auth_state;
	enum ndis_port_authorization_state rx_auth_state;
};

struct ndis_pci_device_custom_props {
	struct ndis_object_header header;
	UINT32 device_type;
	UINT32 current_speed_and_mode;
	UINT32 current_payload_size;
	UINT32 max_payload_size;
	UINT32 max_read_request_size;
	UINT32 current_link_speed;
	UINT32 current_link_width;
	UINT32 max_link_speed;
	UINT32 max_link_width;
};

struct mp_init_params {
	struct ndis_object_header header;
	ULONG flags;
	ndis_resource_list_t allocated_resources;
	void *im_dev_instance_ctx;
	void *mp_add_dev_ctx;
	NET_IFINDEX if_index;
	union net_luid net_luid;
	struct ndis_port_authentication_params default_port_auth_states;
	struct ndis_pci_device_custom_props pci_dev_custom_props;
};

enum ndis_halt_action  {
	NdisHaltDeviceDisabled, NdisHaltDeviceInstanceDeInitialized,
	NdisHaltDevicePoweredDown, NdisHaltDeviceSurpriseRemoved,
	NdisHaltDeviceFailed, NdisHaltDeviceInitializationFailed,
	NdisHaltDeviceStopped
};

#define NDIS_OID_REQUEST_REVISION_1             1
#define NDIS_OID_REQUEST_TIMEOUT_INFINITE       0
#define NDIS_OID_REQUEST_NDIS_RESERVED_SIZE     16

struct ndis_oid_request {
	struct ndis_object_header header;
	enum ndis_request_type type;
	NDIS_PORT_NUMBER port;
	UINT timeout_sec;
	void *id;
	void *handle;
	union request_data {
		struct query {
			NDIS_OID oid;
			void *buf;
			UINT buf_length;
			UINT bytes_written;
			UINT bytes_needed;
		} query_info;
		struct set {
			NDIS_OID oid;
			void *buf;
			UINT buf_length;
			UINT bytes_written;
			UINT bytes_needed;
		} set_info;
		struct method {
			NDIS_OID oid;
			void *buf;
			ULONG in_buf_length;
			ULONG out_buf_length;
			UINT bytes_written;
			UINT bytes_read;
			UINT bytes_needed;
		} method_info;
	} data;
	UCHAR reserved[NDIS_OID_REQUEST_NDIS_RESERVED_SIZE * sizeof(void *)];
	UCHAR mp_reserved[2 * sizeof(void *)];
	UCHAR source_reserved[2 * sizeof(void *)];
	UCHAR supported_revision;
	UCHAR reserved1;
	USHORT reserved2;
};

struct ndis_filterdbs {
	union {
		void *eth_db;
		void *null_db;
	};
	void *tr_db;
	void *fddi_db;
	void *arc_db;
};

struct auth_encr_capa {
	unsigned long auth;
	unsigned long encr;
};

enum driver_type { DRIVER_WIRELESS = 1, DRIVER_ETHERNET, };

enum hw_status {
	HW_INITIALIZED = 1, HW_SUSPENDED, HW_HALTED,
};

struct ndis_rx_scale_capabilities {
	struct ndis_object_header header;
	ULONG flags;
	ULONG num_interrupt_msgs;
	ULONG num_recv_queues;
};

struct ndis_pool_info {
	struct nt_list list;
	ULONG tag;
	ULONG data_length;
	USHORT ctx_size;
	void *pool;
	BOOLEAN with_mdl;
	struct wrap_ndis_device *wnd;
};

union net_buffer_data_length {
	ULONG ulength;
	SIZE_T szlength;
};

struct net_buffer_data {
	struct net_buffer *next;
	struct mdl *current_mdl;
	ULONG current_mdl_offset;
	union net_buffer_data_length data_length;
	struct mdl *mdl_chain;
	ULONG data_offset;
};

union net_buffer_header {
	struct net_buffer_data data;
	nt_slist_header link;
};

struct net_buffer {
	union net_buffer_header header;
	USHORT csum_bias;
	USHORT reserved;
	struct ndis_pool_info *pool;
	void *ndis_reserved[2] _align_(MEMORY_ALLOCATION_ALIGNMENT);
	void *proto_reserved[6] _align_(MEMORY_ALLOCATION_ALIGNMENT);
	void *mp_reserved[4] _align_(MEMORY_ALLOCATION_ALIGNMENT);
	NDIS_PHYSICAL_ADDRESS ndis_reserved1;
};

struct net_buffer_list_context {
	struct net_buffer_list_context *next;
	USHORT size;
	USHORT offset;
	UCHAR context_data[];
};

enum ndis_net_buffer_list_info {
	TcpIpChecksumNetBufferListInfo,
	TcpOffloadBytesTransferred = TcpIpChecksumNetBufferListInfo,
	IPsecOffloadV1NetBufferListInfo,
	TcpLargeSendNetBufferListInfo,
	TcpReceiveNoPush = TcpLargeSendNetBufferListInfo,
	ClassificationHandleNetBufferListInfo,
	Ieee8021QNetBufferListInfo,
	NetBufferListCancelId,
	MediaSpecificInformation,
	NetBufferListFrameType,
	NetBufferListProtocolId = NetBufferListFrameType,
	NetBufferListHashValue,
	NetBufferListHashInfo,
	WfpNetBufferListInfo,
	MaxNetBufferListInfo
};

struct net_buffer_list;

struct net_buffer_list_data {
	struct net_buffer_list *next;
	struct net_buffer *first_buffer;
};

union net_buffer_list_header {
	struct net_buffer_list_data net_buffer_list_data;
	nt_slist_header link;
};

struct net_buffer_list {
	union net_buffer_list_header header;
	struct net_buffer_list_context *context;
	struct net_buffer_list *parent;
	struct ndis_pool_info *pool_handle;
	void *ndis_reserved[2] _align_(MEMORY_ALLOCATION_ALIGNMENT);
	void *proto_reserved[4] _align_(MEMORY_ALLOCATION_ALIGNMENT);
	void *mp_reserved[2] _align_(MEMORY_ALLOCATION_ALIGNMENT);
	void *scratch;
	void *source_handle;
	ULONG nbl_flags;
	LONG child_ref_count;
	ULONG flags;
	NDIS_STATUS status;
	void *net_buffer_list_info[MaxNetBufferListInfo];
};

struct net_buffer_pool_params {
	struct ndis_object_header header;
	ULONG tag;
	ULONG data_size;
};

struct net_buffer_list_ctx {
	struct net_buffer_list_ctx *next;
	USHORT size;
	USHORT offset;
	UCHAR ctx_data[0] _align_(MEMORY_ALLOCATION_ALIGNMENT);
};

struct net_buffer_list_pool_params {
	struct ndis_object_header header;
	UCHAR protocol_id;
	BOOLEAN fallocate_net_buffer;
	USHORT ctx_size;
	ULONG pool_tag;
	ULONG data_size;
};

struct ndis_timer_characteristics {
	struct ndis_object_header header;
	ULONG alloc_tag;
	void *func;
	void *ctx;
};

enum ndis_shutdown_action {
	NdisShutdownPowerOff, NdisShutdownBugCheck
};

struct mp_driver_characteristics {
	struct ndis_object_header header;
	UCHAR major_version;
	UCHAR minor_version;
	UCHAR major_driver_version;
	UCHAR minor_driver_version;
	ULONG flags;
	NDIS_STATUS (*set_options)(void *, void *) wstdcall;
	NDIS_STATUS (*initialize)(void *, void *,
				  struct mp_init_params *) wstdcall;
	void (*halt)(void *, enum ndis_halt_action) wstdcall;
	void (*unload)(struct driver_object *) wstdcall;
	NDIS_STATUS (*pause)(void *, struct mp_pause_params *) wstdcall;
	NDIS_STATUS (*restart)(void *, struct mp_restart_params *) wstdcall;
	NDIS_STATUS (*oid_request)(void *,
				   struct ndis_oid_request *) wstdcall;
	void (*send_net_buffer_lists)(void *, struct net_buffer_list *,
				      NDIS_PORT_NUMBER, ULONG) wstdcall;
	void (*return_net_buffer_lists)(void *, struct net_buffer_list *,
					ULONG) wstdcall;
	void (*cancel_send)(void *, void *) wstdcall;
	BOOLEAN (*check_for_hang)(void *) wstdcall;
	NDIS_STATUS (*reset)(void *, BOOLEAN *) wstdcall;
	void (*device_pnp_event_notify)(void *,
					struct net_device_pnp_event *) wstdcall;
	void (*shutdown)(void *, enum ndis_shutdown_action) wstdcall;
	void (*cancel_oid)(void *, void *) wstdcall;
};

struct wrap_ndis_driver {
	struct wrap_driver *wrap_driver;
	struct mp_driver_characteristics mp_driver_chars;
	struct mp_pnp_characteristics mp_pnp_chars;
	struct miniport_char miniport;
	void *mp_driver_ctx;
};

struct ndis_miniport_block {
	void *signature;
	struct ndis_miniport_block *next;
	struct driver_object *drv_obj;
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
	NT_SPIN_LOCK lock;
	enum ndis_request_type *mediarequest;
	struct ndis_miniport_interrupt *interrupt;
	ULONG flags;
	ULONG pnp_flags;
	struct nt_list packet_list;
	struct ndis_packet *first_pending_tx_packet;
	struct ndis_packet *return_packet_queue;
	ULONG request_buffer;
	void *set_mcast_buffer;
	struct ndis_miniport_block *primary_miniport;
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
	struct device_object *fdo;
	struct device_object *pdo;
	struct device_object *next_device;
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
	void *tr_rx_indicate;
	void *fddi_rx_indicate;
	void *eth_rx_complete;
	void *tr_rx_complete;
	void *fddi_rx_complete;

	void *status;
	void *status_complete;
	void *td_complete;

	void *query_complete;
	void *set_complete;
	void *wan_tx_complete;
	void *wan_rx;
	void *wan_rx_complete;
	/* ndiswrapper specific */
	struct wrap_ndis_device *wnd;
};

struct wrap_ndis_device {
	struct ndis_miniport_block *nmb;
	void *adapter_ctx;
	struct nt_list pool_list;
	struct ndis_interrupt interrupt;
	NT_SPIN_LOCK lock;
	struct wrap_device *wd;
	struct device_object *pdo;
	struct net_device *net_dev;
	unsigned long hw_status;
	void *shutdown_ctx;
	struct tasklet_struct irq_tasklet;
	struct ndis_irq *ndis_irq;
	unsigned long mem_start;
	unsigned long mem_end;
	struct mp_add_device_registration_attrs add_device_attrs;
	struct mp_adapter_registration_attrs registration_attrs;
	struct mp_adapter_general_attrs general_attrs;
	struct mp_adapter_offload_attrs offload_attrs;
	struct mp_adapter_native_802_11_attrs native_802_11_attrs;

	struct net_device_stats stats;
	struct iw_statistics wireless_stats;
	BOOLEAN stats_enabled;
	struct ndis_wireless_stats ndis_stats;

	work_struct_t tx_work;
	struct ndis_packet *tx_ring[TX_RING_SIZE];
	u8 tx_ring_start;
	u8 tx_ring_end;
	u8 is_tx_ring_full;
	struct semaphore tx_ring_mutex;
	unsigned int max_tx_packets;
	u8 tx_ok;
	struct semaphore ndis_comm_mutex;
	wait_queue_head_t ndis_comm_wq;
	s8 ndis_comm_done;
	NDIS_STATUS ndis_comm_status;
	ULONG packet_filter;

	BOOLEAN use_sg_dma;
	ULONG dma_map_count;
	dma_addr_t *dma_map_addr;

	int hangcheck_interval;
	struct timer_list hangcheck_timer;
	int stats_interval;
	struct timer_list stats_timer;
	unsigned long scan_timestamp;
	struct encr_info encr_info;
	char nick[IW_ESSID_MAX_SIZE+1];
	struct ndis_essid essid;
	struct auth_encr_capa capa;
	enum authentication_mode auth_mode;
	enum encryption_status encr_mode;
	enum network_infrastructure infrastructure_mode;
	int num_pmkids;
	mac_address mac;
	struct proc_dir_entry *procfs_iface;

	work_struct_t wrap_ndis_work;
	unsigned long wrap_ndis_pending_work;
	UINT attributes;
	int iw_auth_set;
	int iw_auth_wpa_version;
	int iw_auth_cipher_pairwise;
	int iw_auth_cipher_group;
	int iw_auth_key_mgmt;
	int iw_auth_80211_auth_alg;
	struct ndis_packet_pool *tx_packet_pool;
	struct ndis_buffer_pool *tx_buffer_pool;
	int multicast_size;
	struct v4_checksum rx_csum;
	struct ndis_tcp_ip_checksum_packet_info tx_csum_info;
	enum ndis_physical_medium physical_medium;
	u32 ndis_wolopts;
	struct nt_list timer_list;
	char netdev_name[IFNAMSIZ];
	ULONG frame_length;
	int drv_ndis_version;
};

struct ndis_pmkid_candidate {
	mac_address bssid;
	unsigned long flags;
};

struct ndis_pmkid_candidate_list {
	unsigned long version;
	unsigned long num_candidates;
	struct ndis_pmkid_candidate candidates[1];
};

irqreturn_t mp_isr(int irq, void *data ISR_PT_REGS_PARAM_DECL);
void init_nmb_functions(struct ndis_miniport_block *nmb);

int ndis_init(void);
void ndis_exit_device(struct wrap_ndis_device *wnd);
void ndis_exit(void);
void insert_ndis_kdpc_work(struct kdpc *kdpc);
BOOLEAN remove_ndis_kdpc_work(struct kdpc *kdpc);

int wrap_procfs_add_ndis_device(struct wrap_ndis_device *wnd);
void wrap_procfs_remove_ndis_device(struct wrap_ndis_device *wnd);

void NdisAllocatePacketPoolEx(NDIS_STATUS *status,
			      struct ndis_packet_pool **pool_handle,
			      UINT num_descr, UINT overflowsize,
			      UINT proto_rsvd_length) wstdcall;
void NdisFreePacketPool(struct ndis_packet_pool *pool) wstdcall;
void NdisAllocatePacket(NDIS_STATUS *status, struct ndis_packet **packet,
			struct ndis_packet_pool *pool) wstdcall;
void NdisFreePacket(struct ndis_packet *descr) wstdcall;
void NdisAllocateBufferPool(NDIS_STATUS *status,
			    struct ndis_buffer_pool **pool_handle,
			    UINT num_descr) wstdcall;
void NdisFreeBufferPool(struct ndis_buffer_pool *pool) wstdcall;
void NdisAllocateBuffer(NDIS_STATUS *status, ndis_buffer **buffer,
			struct ndis_buffer_pool *pool, void *virt,
			UINT length) wstdcall;
void NdisFreeBuffer(ndis_buffer *descr) wstdcall;
void NdisMIndicateReceivePacket(struct ndis_miniport_block *nmb,
				struct ndis_packet **packets,
				UINT nr_packets) wstdcall;
void NdisMSendComplete(struct ndis_miniport_block *nmb,
		       struct ndis_packet *packet, NDIS_STATUS status) wstdcall;
void NdisMSendResourcesAvailable(struct ndis_miniport_block *nmb) wstdcall;
void NdisMIndicateStatus(struct ndis_miniport_block *nmb,
			 NDIS_STATUS status, void *buf, UINT len) wstdcall;
void NdisMIndicateStatusComplete(struct ndis_miniport_block *nmb) wstdcall;
void NdisMQueryInformationComplete(struct ndis_miniport_block *nmb,
				   NDIS_STATUS status) wstdcall;
void NdisMSetInformationComplete(struct ndis_miniport_block *nmb,
				 NDIS_STATUS status) wstdcall;
void NdisMResetComplete(struct ndis_miniport_block *nmb,
			NDIS_STATUS status, BOOLEAN address_reset) wstdcall;
ULONG NDIS_BUFFER_TO_SPAN_PAGES(ndis_buffer *buffer) wstdcall;
BOOLEAN NdisWaitEvent(struct ndis_event *event, UINT timeout) wstdcall;
void NdisSetEvent(struct ndis_event *event) wstdcall;
void NdisMDeregisterInterrupt(struct ndis_irq *ndis_irq) wstdcall;
void EthRxIndicateHandler(struct ndis_miniport_block *nmb, void *rx_ctx,
			  char *header1, char *header, UINT header_size,
			  void *look_ahead, UINT look_ahead_size,
			  UINT packet_size) wstdcall;
void EthRxComplete(struct ndis_miniport_block *nmb) wstdcall;
void NdisMTransferDataComplete(struct ndis_miniport_block *nmb,
			       struct ndis_packet *packet, NDIS_STATUS status,
			       UINT bytes_txed) wstdcall;
void NdisWriteConfiguration(NDIS_STATUS *status, struct ndis_miniport_block *nmb,
			    struct unicode_string *key,
			    struct ndis_configuration_parameter *param) wstdcall;
void NdisReadConfiguration(NDIS_STATUS *status,
			   struct ndis_configuration_parameter **param,
			   struct ndis_miniport_block *nmb,
			   struct unicode_string *key,
			   enum ndis_parameter_type type) wstdcall;

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
#define OID_802_11_MEDIA_STREAM_MODE		0x0D010121
#define OID_802_11_CAPABILITY			0x0D010122
#define OID_802_11_PMKID			0x0D010123

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
#define NDIS_STATUS_NETWORK_UNREACHABLE		0xC000023C

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
#define NDIS_PACKET_TYPE_DIRECTED		0x00000001
#define NDIS_PACKET_TYPE_MULTICAST		0x00000002
#define NDIS_PACKET_TYPE_ALL_MULTICAST		0x00000004
#define NDIS_PACKET_TYPE_BROADCAST		0x00000008
#define NDIS_PACKET_TYPE_SOURCE_ROUTING		0x00000010
#define NDIS_PACKET_TYPE_PROMISCUOUS		0x00000020
#define NDIS_PACKET_TYPE_SMT			0x00000040
#define NDIS_PACKET_TYPE_ALL_LOCAL		0x00000080
#define NDIS_PACKET_TYPE_GROUP			0x00001000
#define NDIS_PACKET_TYPE_ALL_FUNCTIONAL		0x00002000
#define NDIS_PACKET_TYPE_FUNCTIONAL		0x00004000
#define NDIS_PACKET_TYPE_MAC_FRAME		0x00008000

/* memory allocation flags */
#define NDIS_MEMORY_CONTIGUOUS			0x00000001
#define NDIS_MEMORY_NONCACHED			0x00000002

/* Atrribute flags to NdisMSetAtrributesEx */
#define NDIS_ATTRIBUTE_IGNORE_PACKET_TIMEOUT	0x00000001
#define NDIS_ATTRIBUTE_IGNORE_REQUEST_TIMEOUT	0x00000002
#define NDIS_ATTRIBUTE_IGNORE_TOKEN_RING_ERRORS	0x00000004
#define NDIS_ATTRIBUTE_BUS_MASTER		0x00000008
#define NDIS_ATTRIBUTE_INTERMEDIATE_DRIVER	0x00000010
#define NDIS_ATTRIBUTE_DESERIALIZE		0x00000020
#define NDIS_ATTRIBUTE_NO_HALT_ON_SUSPEND	0x00000040
#define NDIS_ATTRIBUTE_SURPRISE_REMOVE_OK	0x00000080
#define NDIS_ATTRIBUTE_NOT_CO_NDIS		0x00000100
#define NDIS_ATTRIBUTE_USES_SAFE_BUFFER_APIS	0x00000200

#define NDIS_FLAGS_PROTOCOL_ID_MASK		0x0000000F
#define NDIS_FLAGS_DONT_LOOPBACK		0x00000080

#define NDIS_PROTOCOL_ID_TCP_IP			0x02

#define OID_TCP_TASK_OFFLOAD			0xFC010201

/* introduced in 6.0 */
#define NDIS_STATUS_LINK_STATE			0x40010017L
#define NDIS_STATUS_NETWORK_CHANGE		0x40010018L
#define NDIS_STATUS_MEDIA_SPECIFIC_INDICATION_EX 0x40010019L
#define NDIS_STATUS_PORT_STATE			0x40010022L
#define NDIS_STATUS_OPER_STATUS			0x40010023L
#define NDIS_STATUS_PACKET_FILTER		0x40010024L

#define NDIS_STATUS_OFFLOAD_PAUSE		0x40020001L
#define NDIS_STATUS_OFFLOAD_ALL			0x40020001L
#define NDIS_STATUS_OFFLOAD_RESUME		0x40020001L
#define NDIS_STATUS_OFFLOAD_PARTIAL_SUCCESS	0x40020001L
#define NDIS_STATUS_OFFLOAD_STATE_INVALID	0x40020001L
#define NDIS_STATUS_OFFLOAD_CURRENT_CONFIG	0x40020001L
#define NDIS_STATUS_OFFLOAD_HARDWARE_CAPABILITIES 0x40020001L
#define NDIS_STATUS_TCP_CONNECTION_OFFLOAD_HARDWARE_CAPABILITIES 0x4002000BL

#define NDIS_STATUS_DOT11_SCAN_CONFIRM			0x40030000
#define NDIS_STATUS_DOT11_MPDU_MAX_LENGTH_CHANGED	0x40030001
#define NDIS_STATUS_DOT11_ASSOCIATION_START		0x40030002
#define NDIS_STATUS_DOT11_ASSOCIATION_COMPLETION	0x40030003
#define NDIS_STATUS_DOT11_CONNECTION_START		0x40030004
#define NDIS_STATUS_DOT11_CONNECTION_COMPLETION		0x40030005
#define NDIS_STATUS_DOT11_ROAMING_START			0x40030006
#define NDIS_STATUS_DOT11_ROAMING_COMPLETION		0x40030007
#define NDIS_STATUS_DOT11_DISASSOCIATION		0x40030008
#define NDIS_STATUS_DOT11_TKIPMIC_FAILURE		0x40030009
#define NDIS_STATUS_DOT11_PMKID_CANDIDATE_LIST		0x4003000A
#define NDIS_STATUS_DOT11_PHY_STATE_CHANGED		0x4003000B
#define NDIS_STATUS_DOT11_LINK_QUALITY			0x4003000C

#define	NDIS_STATUS_SEND_ABORTED		STATUS_NDIS_REQUEST_ABORTED
#define	NDIS_STATUS_PAUSED			STATUS_NDIS_PAUSED
#define	NDIS_STATUS_INTERFACE_NOT_FOUND		STATUS_NDIS_INTERFACE_NOT_FOUND
#define	NDIS_STATUS_INVALID_PARAMETER		STATUS_INVALID_PARAMETER
#define	NDIS_STATUS_UNSUPPORTED_REVISION	STATUS_NDIS_UNSUPPORTED_REVISION
#define	NDIS_STATUS_INVALID_PORT		STATUS_NDIS_INVALID_PORT
#define	NDIS_STATUS_INVALID_PORT_STATE		STATUS_NDIS_INVALID_PORT_STATE
#define	NDIS_STATUS_INVALID_STATE		STATUS_INVALID_DEVICE_STATE
#define	NDIS_STATUS_MEDIA_DISCONNECTED		STATUS_NDIS_MEDIA_DISCONNECTED
#define	NDIS_STATUS_LOW_POWER_STATE		STATUS_NDIS_LOW_POWER_STATE

#define	NDIS_STATUS_DOT11_AUTO_CONFIG_ENABLED	STATUS_NDIS_DOT11_AUTO_CONFIG_ENABLED
#define	NDIS_STATUS_DOT11_MEDIA_IN_USE		STATUS_NDIS_DOT11_MEDIA_IN_USE
#define NDIS_STATUS_DOT11_POWER_STATE_INVALID	STATUS_NDIS_DOT11_POWER_STATE_INVALID

#define NDIS_STATUS_UPLOAD_IN_PROGRESS			0xC0231001L
#define NDIS_STATUS_REQUEST_UPLOAD			0xC0231002L
#define NDIS_STATUS_UPLOAD_REQUESTED			0xC0231003L
#define NDIS_STATUS_OFFLOAD_TCP_ENTRIES			0xC0231004L
#define NDIS_STATUS_OFFLOAD_PATH_ENTRIES		0xC0231005L
#define NDIS_STATUS_OFFLOAD_NEIGHBOR_ENTRIES		0xC0231006L
#define NDIS_STATUS_OFFLOAD_IP_ADDRESS_ENTRIES		0xC0231007L
#define NDIS_STATUS_OFFLOAD_HW_ADDRESS_ENTRIES		0xC0231008L
#define NDIS_STATUS_OFFLOAD_VLAN_ENTRIES		0xC0231009L
#define NDIS_STATUS_OFFLOAD_TCP_XMIT_BUFFER		0xC023100AL
#define NDIS_STATUS_OFFLOAD_TCP_RCV_BUFFER		0xC023100BL
#define NDIS_STATUS_OFFLOAD_TCP_RCV_WINDOW		0xC023100CL
#define NDIS_STATUS_OFFLOAD_VLAN_MISMATCH		0xC023100DL
#define NDIS_STATUS_OFFLOAD_DATA_NOT_ACCEPTED		0xC023100EL
#define NDIS_STATUS_OFFLOAD_POLICY			0xC023100FL
#define NDIS_STATUS_OFFLOAD_DATA_PARTIALLY_ACCEPTED	0xC0231010L
#define NDIS_STATUS_OFFLOAD_REQUEST_RESET		0xC0231011L

#define NDIS_RECEIVE_SCALE_CAPABILITIES_REVISION_1	1

#define NDIS_RSS_CAPS_MESSAGE_SIGNALED_INTERRUPTS	0x01000000
#define NDIS_RSS_CAPS_CLASSIFICATION_AT_ISR		0x02000000
#define NDIS_RSS_CAPS_CLASSIFICATION_AT_DPC		0x04000000
#define NDIS_RSS_CAPS_HASH_TYPE_TCP_IPV4		0x00000100
#define NDIS_RSS_CAPS_HASH_TYPE_TCP_IPV6		0x00000200
#define NDIS_RSS_CAPS_HASH_TYPE_TCP_IPV6_EX		0x00000400

/* end of ndis 6.0 */

#define NDIS_MAC_OPTION_COPY_LOOKAHEAD_DATA	0x00000001
#define NDIS_MAC_OPTION_RECEIVE_SERIALIZED	0x00000002
#define NDIS_MAC_OPTION_TRANSFERS_NOT_PEND	0x00000004
#define NDIS_MAC_OPTION_NO_LOOPBACK		0x00000008
#define NDIS_MAC_OPTION_FULL_DUPLEX		0x00000010
#define NDIS_MAC_OPTION_EOTX_INDICATION		0x00000020
#define NDIS_MAC_OPTION_8021P_PRIORITY		0x00000040
#define NDIS_MAC_OPTION_SUPPORTS_MAC_ADDRESS_OVERWRITE	0x00000080
#define NDIS_MAC_OPTION_RECEIVE_AT_DPC		0x00000100
#define NDIS_MAC_OPTION_8021Q_VLAN		0x00000200
#define NDIS_MAC_OPTION_RESERVED		0x80000000

#define deserialized_driver(wnd) (wnd->attributes & NDIS_ATTRIBUTE_DESERIALIZE)

static inline void serialize_lock(struct wrap_ndis_device *wnd)
{
	nt_spin_lock(&wnd->nmb->lock);
}

static inline void serialize_unlock(struct wrap_ndis_device *wnd)
{
	nt_spin_unlock(&wnd->nmb->lock);
}

static inline KIRQL serialize_lock_irql(struct wrap_ndis_device *wnd)
{
	if (deserialized_driver(wnd))
		return raise_irql(DISPATCH_LEVEL);
	else
		return nt_spin_lock_irql(&wnd->nmb->lock, DISPATCH_LEVEL);
}

static inline void serialize_unlock_irql(struct wrap_ndis_device *wnd,
					 KIRQL irql)
{
	if (deserialized_driver(wnd))
		lower_irql(irql);
	else
		nt_spin_unlock_irql(&wnd->nmb->lock, irql);
}

static inline void if_serialize_lock(struct wrap_ndis_device *wnd)
{
	if (!deserialized_driver(wnd))
		nt_spin_lock(&wnd->nmb->lock);
}

static inline void if_serialize_unlock(struct wrap_ndis_device *wnd)
{
	if (!deserialized_driver(wnd))
		nt_spin_unlock(&wnd->nmb->lock);
}

#endif /* NDIS_H */
