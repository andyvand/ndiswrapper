/*
 *  Copyright (C) 2003 Pontus Fuchs
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


#include <linux/types.h>
#include <linux/timer.h>

#include <linux/netdevice.h>
#include <linux/wireless.h>
#include <linux/pci.h>
#include <linux/wait.h>

#include <linux/version.h>

/* Workqueue / task queue backwards compatibility stuff */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,5,41)
#include <linux/workqueue.h>
#else
#include <linux/tqueue.h>
#define work_struct tq_struct
#define INIT_WORK INIT_TQUEUE
#define schedule_work schedule_task
#endif

/* Interrupt backwards compatibility stuff */
#include <linux/interrupt.h>
#ifndef IRQ_HANDLED
#define IRQ_HANDLED
#define IRQ_NONE
#define irqreturn_t void
#endif

#ifndef free_netdev
#define free_netdev kfree
#endif


#define STDCALL __attribute__((__stdcall__))
#define packed __attribute__((packed))

#define NDIS_STATUS_SUCCESS     0x00000000
#define NDIS_STATUS_FAILURE     0xc0000001
#define NDIS_STATUS_PENDING     0x00000103

#define NDIS_STATUS_BAD_VERSION 0xc0010004
#define NDIS_STATUS_BAD_CHAR    0xc0010005
int getSp(void);

#define DEBUG 0

#if DEBUG > 0
#define DBGTRACE(s, args...) printk(s, args)
#else
#define DBGTRACE(s, ...)
#endif

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

	/* 20 Number of buffers */
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
};


struct packed miniport_char
{
	unsigned char majorVersion;
	unsigned char minorVersion;
	__u16 reserved1;
	__u32 reserved2;

	void * CheckForHangTimer;
	void * DisableInterruptHandler;
	void * EnableInterruptHandler;

	/* Stop miniport */
	void (*halt)(void *ctx) STDCALL;

	/* Interrupt BH */
	void (*handle_interrupt)(void *ctx) STDCALL;

	/* Start miniport driver */
	unsigned int (*init)(unsigned int *OpenErrorStatus, unsigned int *SelectedmediumIndex, unsigned int *MediumArray, unsigned int MediumArraySize, void *ndis_handle, void *conf_handle) STDCALL;

	/* Interrupt TH */
	void (*isr)(unsigned int *taken, unsigned int *callme, void *ctx) STDCALL;

	/* Query parameters */
	unsigned int (*query)(void *ctx, unsigned int oid, char *buffer, unsigned int buflen, unsigned int *written, unsigned int *needed) STDCALL;

	void * ReconfigureHandler;
	void * ResetHandler;		//s

	/* Send one packet */
	unsigned int (*send)(void *ctx, struct ndis_packet *packet, unsigned int flags) STDCALL;

	/* Set parameters */
	unsigned int (*setinfo)(void *ctx, unsigned int oid, char *buffer, unsigned int buflen, unsigned int *written, unsigned int *needed) STDCALL;

	void * TransferDataHandler;

	/* upper layer is done with RX packet */	
	void (*return_packet)(void *ctx, void *packet) STDCALL;

	/* Send packets */
	void (*send_packets)(void *ctx, struct ndis_packet **packets, int nr_of_packets) STDCALL;
};

struct ndis_work
{
	void (*func)(struct ndis_work *work, void *ctx) STDCALL;
	void *ctx;
	struct list_head list;
};


struct ndis_workentry
{
	struct list_head list;
	struct ndis_work *work;
};



struct ndis_irq
{
	int irq;
	struct ndis_handle *handle;

	/* Taken by ISR, DisableInterrupt and SynchronizeWithInterrupt */
	spinlock_t spinlock;

};


struct packed ustring
{
	__u16 len;
	__u16 buflen;
	char *buf;
};

struct ndis_setting_val
{
	unsigned int type;
	union
	{
		unsigned int intval;
		struct ustring ustring;
	} data;
};

struct ndis_setting
{
	struct list_head list;
	char *name;
	struct ndis_setting_val val;
};


/*
 * There is one of these per driver. One per loaded driver exists.
 *
 */
struct ndis_driver
{
	struct list_head list;
	char name[32];

	struct pci_driver pci_driver;
	struct pci_device_id pci_id[2];
	
	unsigned int pci_registered; 
	struct list_head settings;

	void *image;
	unsigned int (*entry)(void *obj, char *p2) STDCALL;
	struct miniport_char miniport_char;
	int key_len ;
	unsigned char key_val[IW_ENCODING_TOKEN_MAX] ;
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
	void *indicate_receive_packet;
	void *send_complete;
	char fill2[140];
	void *indicate_status;
	void *indicate_status_complete;
	char fill3[4];
	void *query_complete;
	char fill4[200];

	struct pci_dev *pci_dev;
	struct net_device *net_dev;
	void *adapter_ctx;

	struct work_struct irq_bh;

	int irq;
	unsigned long mem_start;
	unsigned long mem_end;

	struct net_device_stats stats;
	struct iw_statistics wireless_stats;
	struct ndis_driver *driver;
	
	spinlock_t query_lock;
	int query_wait_res;
	int query_wait_done;

	int use_scatter_gather;
};

struct ndis_timer
{
	struct timer_list timer;
	struct work_struct bh;
	void *func;
	void *ctx;
	int repeat;
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

struct packed ndis_phy_address
{
	__u32 low;
	__u32 high;
};


struct packed essid_req
{
	unsigned int len;
	char essid[32];
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

struct packed wep_req
{
	unsigned long len;
	unsigned long keyindex;
	unsigned long keylength;
	unsigned char keymaterial[IW_ENCODING_TOKEN_MAX];
};

#define NDIS_ENCODE_ENABLED 0
#define NDIS_ENCODE_DISABLED 1
#define NDIS_ENCODE_NOKEY 2

#define NDIS_ENCODE_OPEN 0
#define NDIS_ENCODE_RESTRICTED 1
#define NDIS_ENCODE_OPEN_RESTRICTED 2

void ndis_sendpacket_done(struct ndis_handle *handle, struct ndis_packet *packet);



void NdisMIndicateReceivePacket(struct ndis_handle *handle, struct ndis_packet **packets, unsigned int nr_packets) STDCALL;
void NdisMSendComplete(struct ndis_handle *handle, struct ndis_packet *packet, unsigned int status) STDCALL;
void NdisIndicateStatus(struct ndis_handle *handle, unsigned int status, void *buf, unsigned int len) STDCALL;
void NdisIndicateStatusComplete(struct ndis_handle *handle) STDCALL;
void NdisMQueryInformationComplete(struct ndis_handle *handle, unsigned int status) STDCALL;

#define NDIS_OID_STAT_TX_OK         0x00020101
#define NDIS_OID_STAT_RX_OK         0x00020102
#define NDIS_OID_STAT_TX_ERROR      0x00020103
#define NDIS_OID_STAT_RX_ERROR      0x00020104

#define NDIS_OID_ESSID              0x0D010102
#define NDIS_OID_BSSID              0x0D010101
#define NDIS_OID_MODE               0x0D010108
#define NDIS_OID_RSSI               0x0D010206
#define NDIS_OID_CONFIGURATION      0x0D010211
#define NDIS_OID_TX_POWER_LEVEL     0x0D010205
#define NDIS_OID_RTS_THRESH         0x0D01020A
#define NDIS_OID_FRAG_THRESH        0x0D010209
#define NDIS_OID_PACKET_FILTER      0x0001010E
#define NDIS_OID_ADD_WEP            0x0D010113
#define NDIS_OID_WEP_STATUS         0x0D01011B
#define NDIS_OID_AUTH_MODE          0x0D010118
#define NDIS_OID_PRIVACY_FILTER     0x0D010119

/* general OIDs */
#define NDIS_OID_GEN_SPEED          0x00010107

#define UNIMPL() printk(KERN_ERR "%s --UNIMPLEMENTED--\n", __FUNCTION__ )




#define FALSE 0
#define TRUE 1

#define InternalBaseType              (0xcc)         //What is this???? - took it from reactos
#define InternalNotificationEvent     (InternalBaseType + 1)
#define InternalSynchronizationEvent  (InternalBaseType + 2)

#define assert(x)

/*
 * VOID
 * InitializeListHead (
 *		PLIST_ENTRY	ListHead
 *		);
 *
 * FUNCTION: Initializes a double linked list
 * ARGUMENTS:
 *         ListHead = Caller supplied storage for the head of the list
 */
#define InitializeListHead(ListHead) \
{ \
	(ListHead)->Flink = (ListHead); \
	(ListHead)->Blink = (ListHead); \
}

typedef enum _EVENT_TYPE
{
  NotificationEvent,
  SynchronizationEvent,
} EVENT_TYPE;

typedef struct _LIST_ENTRY
{
  struct _LIST_ENTRY *Flink;
  struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY;


//Definition of KEVENT and DISPATCHER_HEADER- Taken from reactos: include/ddk/ketypes.h
//struct _DISPATCHER_HEADER;

typedef struct _DISPATCHER_HEADER
{
   unsigned char      Type;
   unsigned char      Absolute;
   unsigned char      Size;
   unsigned char      Inserted;
   long       SignalState;
   LIST_ENTRY WaitListHead;
} /*__attribute__*/ DISPATCHER_HEADER, *PDISPATCHER_HEADER;

typedef struct _KEVENT
{
   DISPATCHER_HEADER Header;
} KEVENT, *PKEVENT;

//Definition of PNDIS_EVENT - Taken from reactos: include/net/ndis.h
typedef struct _NDIS_EVENT {
    KEVENT  Event;
} NDIS_EVENT, *PNDIS_EVENT;


void STDCALL KeInitializeEvent(PKEVENT Event, EVENT_TYPE Type, int State);


#endif /* NDIS_H */
