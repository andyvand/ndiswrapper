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

#define DISPATCH_LEVEL 2

struct slist_entry
{
	struct slist_entry  *next;
};

union slist_head {
	unsigned long long align;
	struct
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

typedef unsigned long POOL_TYPE;

struct dispatch_header
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

struct kdpc
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

typedef STDCALL void *LOOKASIDE_ALLOC_FUNC(POOL_TYPE, unsigned long, unsigned long);
typedef STDCALL void LOOKASIDE_FREE_FUNC(void *);

struct packed npaged_lookaside_list {
	union slist_head head;
	unsigned short depth;
	unsigned short maxdepth;
	unsigned long totalallocs;
	unsigned long allocmisses;
	unsigned long totalfrees;
	unsigned long freemisses;
	POOL_TYPE type;
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
