/*
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

#ifndef _NTOSKERNEL_H_
#define _NTOSKERNEL_H_

#include "ndiswrapper.h"

#define MAX_STR_LEN 512

#define PASSIVE_LEVEL 0
#define DISPATCH_LEVEL 2

#define STATUS_SUCCESS			0
#define STATUS_TIMEOUT			0x00000102
#define STATUS_PENDING			0x00000103
#define STATUS_FAILURE			0xC0000001
#define STATUS_MORE_PROCESSING_REQUIRED	0xC0000016
#define STATUS_RESOURCES		0xC000009A
#define STATUS_NOT_SUPPORTED		0xC00000BB

#define IS_PENDING			0x01
#define CALL_ON_CANCEL			0x20
#define CALL_ON_SUCCESS			0x40
#define CALL_ON_ERROR			0x80


struct slist_entry
{
	struct slist_entry  *next;
};

union slist_head {
	unsigned long long align;
	struct packed
	{
		struct slist_entry  *next;
		unsigned short depth;
		unsigned short sequence;
	} list;
};

typedef unsigned long *KSPIN_LOCK;
typedef unsigned char KIRQL;

struct list_entry
{
	struct list_entry *fwd_link;
	struct list_entry *bwd_link;
};

struct packed dispatch_header
{
	unsigned char type;
	unsigned char absolute;
	unsigned char size;
	unsigned char inserted;
	long signal_state;
	struct list_entry wait_list_head;
};

struct ktimer;
struct kdpc;

#define WRAPPER_TIMER_MAGIC 47697249
struct wrapper_timer
{
	struct list_head list;
	struct timer_list timer;
#ifdef DEBUG_TIMER
	unsigned long wrapper_timer_magic;
#endif
	long repeat;
	int active;
	struct ktimer *ktimer;
	struct kdpc *kdpc;
};

struct packed kdpc
{
	short type;
	unsigned char number;
	unsigned char importance;
	struct list_entry dpc_list_entry;

	void *func;
	void *ctx;
	void *arg1;
	void *arg2;
	unsigned long *lock;
};

enum pool_type
{
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
};

struct irp;

struct packed device_object
{
	short type;
	unsigned short size;
	long fill1;
	void *drv_obj;
	struct device_object *next_dev;
	void *fill2;
	struct irp *current_irp;
	void *fill4;
	unsigned long flags;
	unsigned long characteristics;
	void *fill5;
	void *dev_ext;
	unsigned long dev_type;
	char stack_size;
	char fill6[3+10*4];
	unsigned long align_req;
	char fill7[100]; /* more than required */

	/* ndiswrapper-specific data */
	union {
		struct usb_device *usb;
	} device;
};

struct io_status_block {
	long status;
	unsigned long status_info;
};

#define IRP_MJ_DEVICE_CONTROL           0x0E
#define IRP_MJ_INTERNAL_DEVICE_CONTROL  0x0F

struct packed io_stack_location {
	char major_fn;
	char minor_fn;
	char flags;
	char control;
	union {
		struct {
			unsigned long output_buf_len;
			unsigned long input_buf_len; /*align to pointer size*/
			unsigned long code; /*align to pointer size*/
			void *type3_input_buf;
		} ioctl;
		struct {
			void *arg1;
			void *arg2;
			void *arg3;
			void *arg4;
		} generic;
	} params;
	struct device_object *dev_obj;
	void *fill;
	unsigned long (*completion_handler)(struct device_object *,
	                                    struct irp *, void *) STDCALL;
	void *handler_arg;
};

struct packed irp {
	short type;
	unsigned short size;
	void *mdl;
	unsigned long flags;
	union {
		struct irp *master_irp;
		void *sys_buf;
	} associated_irp;

	void *fill1[2];

	struct io_status_block io_status;
	char requestor_mode;
	unsigned char pending_returned;
	char stack_size;
	char stack_pos;
	unsigned char cancel;
	unsigned char cancel_irql;

	char fill2[2];

	struct io_status_block *user_status;
	struct kevent *user_event;

	void *fill3[2];

	void (*cancel_routine)(struct device_object *, struct irp *) STDCALL;
	void *user_buf;
	void *driver_context[4];
	void *thread;

	void *fill4;

	struct list_entry list_entry;
	struct io_stack_location *current_stack_location;

	void *fill5[3];
};

struct ktimer
{
	struct dispatch_header dispatch_header;
	u64 due_time;
	struct list_entry timer_list;
	/* the space for kdpc is used for wrapper timer */
	/* struct kdpc *kdpc; */
	struct wrapper_timer *wrapper_timer;
	long period;
};

#define NOTIFICATION_TIMER 1

struct kevent
{
	struct dispatch_header header;
};

#define NOTIFICATION_EVENT	0
#define SYNCHRONIZATION_EVENT	1

typedef STDCALL void *LOOKASIDE_ALLOC_FUNC(enum pool_type pool_type,
					   size_t size, unsigned long tag);
typedef STDCALL void LOOKASIDE_FREE_FUNC(void *);

struct packed npaged_lookaside_list {
	union slist_head head;
	unsigned short depth;
	unsigned short maxdepth;
	unsigned long totalallocs;
	unsigned long allocmisses;
	unsigned long totalfrees;
	unsigned long freemisses;
	enum pool_type pool_type;
	unsigned long tag;
	unsigned long size;
	LOOKASIDE_ALLOC_FUNC *alloc_func;
	LOOKASIDE_FREE_FUNC *free_func;
	struct list_entry listent;
	unsigned long lasttotallocs;
	unsigned long lastallocmisses;
	unsigned long pad[2];
	KSPIN_LOCK obsolete;
};

void wrapper_timer_handler(unsigned long data);
void wrapper_init_timer(struct ktimer *ktimer, void *handle);
int wrapper_set_timer(struct wrapper_timer *wrapper_timer,
                      unsigned long expires, unsigned long repeat);
void wrapper_cancel_timer(struct wrapper_timer *wrapper_timer, char *canceled);

STDCALL KIRQL KeGetCurrentIrql(void);
STDCALL void KeInitializeSpinLock(KSPIN_LOCK *lock);

static inline void wrapper_set_timer_dpc(struct wrapper_timer *wrapper_timer,
                                         struct kdpc *kdpc)
{
	wrapper_timer->kdpc = kdpc;
}

static inline void init_dpc(struct kdpc *kdpc, void *func, void *ctx)
{
	kdpc->func = func;
	kdpc->ctx  = ctx;
}

#endif // _NTOSKERNEL_H_
