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
#include <linux/workqueue.h>
#include <linux/netdevice.h>
#define STDCALL __attribute__((__stdcall__))
#define packed __attribute__((packed))

#define NDIS_STATUS_SUCCESS     0x00000000
#define NDIS_STATUS_FAILIURE    0xc0000001
#define NDIS_STATUS_BAD_VERSION 0xc0010004
#define NDIS_STATUS_BAD_CHAR    0xc0010005

int getSp(void);

#define DEBUG 1

#if DEBUG > 0
#define DBGTRACE(s, args...) printk(s, args)
#else
#define DBGTRACE(s, ...)
#endif

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
	STDCALL void (*halt)(void *ctx);

	/* Interrupt BH */
	STDCALL void (*handle_interrupt)(void *ctx);

	/* Start miniport driver */
	STDCALL unsigned int (*init)(unsigned int *OpenErrorStatus, unsigned int *SelectedmediumIndex, unsigned int *MediumArray, unsigned int MediumArraySize, void *ndis_handle, void *conf_handle);

	/* Interrupt TH */
	STDCALL void (*isr)(unsigned int *taken, unsigned int *callme, void *ctx);

	/* Query parameters */
	STDCALL unsigned int (*query)(void *ctx, unsigned int oid, char *buffer, unsigned int buflen, unsigned int *written, unsigned int *needed);

	void * ReconfigureHandler;
	void * ResetHandler;		//s
	void * SendHandler;

	/* Set parameters */
	STDCALL unsigned int (*setinfo)(void *ctx, unsigned int oid, char *buffer, unsigned int buflen, unsigned int *written, unsigned int *needed);

	void * TransferDataHandler;

	/* upper layer is done with RX packet */	
	STDCALL void (*return_packet)(void *ctx, void *packet);

	/* Send packets */
	STDCALL void (*send_packets)(void *ctx, void *packets, int nr_of_packets);

	
};


struct ndis_irq
{
	int irq;
	struct ndis_handle *handle;

	/* Taken by ISR, DisableInterrupt and SynchronizeWithInterrupt */
	spinlock_t spinlock;

};

/*
  This struct contains function pointers that the drivers references directly via macros,
  so it's important that they are at the correct position hence the paddings.
 */
struct packed ndis_handle
{
	char fill1[232];
	void *indicate_receive_packet;
	void *send_complete;
	char fill2[140];
	void *indicate_status;
	void *indicate_status_complete;
	char fill3[200];
	void *image;
	STDCALL unsigned int (*entry)(void *obj, char *p2);
	struct miniport_char miniport_char;
	struct pci_dev *pci_dev;
	struct net_device *net_dev;
	void *adapter_ctx;
	struct work_struct irq_bh;

	int irq;
	unsigned long mem_start;
	unsigned long mem_end;

	struct net_device_stats stats;
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

	void *buffer_head;
	void *buffer_tail;
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
};


struct packed ustring
{
	__u16 x;
	__u16 y;
	char *buf;
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


#define NDIS_OID_STAT_TX_OK         0x00020101
#define NDIS_OID_STAT_RX_OK         0x00020102
#define NDIS_OID_STAT_TX_ERROR      0x00020103
#define NDIS_OID_STAT_RX_ERROR      0x00020104

#define NDIS_OID_ESSID              0x0D010102
#define NDIS_OID_MODE               0x0D010108
#endif /* NDIS_H */
