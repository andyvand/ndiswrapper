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

typedef unsigned long KSPIN_LOCK, *PKSPIN_LOCK;
typedef unsigned char KIRQL;

struct list_entry
{
	struct list_entry *fwd_link;
	struct list_entry *bwd_link;
};

typedef unsigned long POOL_TYPE;

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

struct ktimer
{
	struct timer_list timer;
	unsigned long expires;
	int active;
	struct kdpc *kdpc;
	long repeat;
};

#define NOTIFICATION_TIMER 1

typedef STDCALL void *LOOKASIDE_ALLOC_FUNC(POOL_TYPE, unsigned long, unsigned long);
typedef STDCALL void LOOKASIDE_FREE_FUNC(void *);

#define _FASTCALL __attribute__((__stdcall__)) __attribute__((regparm (3)))

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

#endif // _NTOSKERNEL_H_
