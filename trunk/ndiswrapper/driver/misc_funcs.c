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
#include <linux/types.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <asm/io.h>
#include <linux/ctype.h>
#include <linux/net.h>

#include "ndis.h"
#include "ntoskernel.h"

static struct wrapper_alloc *wrapper_alloc_head;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,0)
#undef __wait_event_interruptible_timeout
#undef wait_event_interruptible_timeout
#define __wait_event_interruptible_timeout(wq, condition, ret)		\
do {									\
	wait_queue_t __wait;						\
	init_waitqueue_entry(&__wait, current);				\
									\
	add_wait_queue(&wq, &__wait);					\
	for (;;) {							\
		set_current_state(TASK_INTERRUPTIBLE);			\
		if (condition)						\
			break;						\
		if (!signal_pending(current)) {				\
			ret = schedule_timeout(ret);			\
			if (!ret)					\
				break;					\
			continue;					\
		}							\
		ret = -ERESTARTSYS;					\
		break;							\
	}								\
	current->state = TASK_RUNNING;					\
	remove_wait_queue(&wq, &__wait);				\
} while (0)

#define wait_event_interruptible_timeout(wq, condition, timeout)	\
({									\
	long __ret = timeout;						\
	if (!(condition))						\
		__wait_event_interruptible_timeout(wq, condition, __ret); \
	__ret;								\
})
#endif

void *wrapper_kmalloc(size_t size, int flags)
{
	struct wrapper_alloc *entry =
		kmalloc(sizeof(struct wrapper_alloc), GFP_KERNEL);
	if (!entry)
	{
		printk(KERN_ERR "%s: couldn't allocate memory\n", __FUNCTION__);
		return NULL;
	}
	
	entry->ptr = kmalloc(size, flags);
	entry->next = wrapper_alloc_head;
	wrapper_alloc_head = entry;
	return entry->ptr;
}

void wrapper_kfree(void *ptr)
{
	struct wrapper_alloc *cur, *prev;

	for (cur = wrapper_alloc_head, prev = NULL; cur ;
		 prev = cur, cur = cur->next)
	{
		if (cur->ptr == ptr)
			break;
	}

	if (!cur)
	{
		printk(KERN_ERR "%s: ptr %p is not allocated by wrapper?\n",
			   __FUNCTION__, ptr);
		return;
	}

	if (prev)
		prev->next = cur->next;
	else
	{
		if (cur != wrapper_alloc_head)
			printk(KERN_ERR "%s: cur %p is not = head %p\n",
				   __FUNCTION__, cur, wrapper_alloc_head);
		else
			wrapper_alloc_head = wrapper_alloc_head->next;
	}
	kfree(ptr);
	kfree(cur);
}

void wrapper_kfree_all(void)
{
	struct wrapper_alloc *next, *cur;

	for (cur = wrapper_alloc_head; cur; cur = next)
	{
		kfree(cur->ptr);
		next = cur->next;
		kfree(cur);
	}

	wrapper_alloc_head = NULL;
}
	

unsigned long RtlCompareMemory(char *b, char *a, unsigned long len)
{
	unsigned long i;
	DBGTRACE("%s: Entry\n", __FUNCTION__);

	for(i = 0; (i < len) && a[i] == b[i]; i++)
		;
	return i;
}

STDCALL long RtlCompareString(const struct ustring *s1,
							  const struct ustring *s2, int case_insensitive)
{
	unsigned int len;
	long ret = 0;
	const char *p1, *p2;
	
	DBGTRACE("%s: entry\n", __FUNCTION__);
	len = min(s1->len, s2->len);
	p1 = s1->buf;
	p2 = s2->buf;
	
	if (case_insensitive)
		while (!ret && len--)
			ret = toupper(*p1++) - toupper(*p2++);
	else
		while (!ret && len--)
			ret = *p1++ - *p2++;
	if (!ret)
		ret = s1->len - s2->len;
	return ret;
}


STDCALL long RtlCompareUnicodeString(const struct ustring *s1,
				     const struct ustring *s2,
				     int case_insensitive)
{
	unsigned int len;
	long ret = 0;
	const __u16 *p1, *p2;
	
	DBGTRACE("%s: entry\n", __FUNCTION__);
	len = min(s1->len, s2->len);
	p1 = (__u16 *)s1->buf;
	p2 = (__u16 *)s2->buf;
	
	if (case_insensitive)
		while (!ret && len--)
			ret = toupper((__u8)*p1++) - toupper((__u8)*p2++);
	else
		while (!ret && len--)
			ret = *p1++ - *p2++;
	if (!ret)
		ret = s1->len - s2->len;
	return ret;
}

STDCALL int RtlEqualString(const struct ustring *s1,
			   const struct ustring *s2, int case_insensitive)
{
	DBGTRACE("%s: entry\n", __FUNCTION__);
	if (s1->len != s2->len)
		return 0;
	return !RtlCompareString(s1, s2, case_insensitive);
}

STDCALL int RtlEqualUnicodeString(const struct ustring *s1,
				  const struct ustring *s2,
				  int case_insensitive)
{
	if (s1->len != s2->len)
		return 0;
	return !RtlCompareUnicodeString(s1, s2, case_insensitive);
}

STDCALL void RtlCopyUnicodeString(struct ustring *dst,
				  const struct ustring *src)
{
	DBGTRACE("%s: entry\n", __FUNCTION__);
	if (src)
	{
		unsigned int len = min(src->len, dst->buflen);
		memcpy(dst->buf, src->buf, len);
		dst->len = len;
		/* append terminating '\0' if enough space */
		if (len < dst->buflen)
			dst->buf[len] = 0;
	}
	else dst->len = 0;
}

STDCALL int RtlAnsiStringToUnicodeString(struct ustring *dst, struct ustring *src, unsigned int dup)
{
	int i;
	__u16 *d;
	__u8 *s;

	DBGTRACE("%s: dup: %d src: %s\n", __FUNCTION__, dup, src->buf);
	if(dup)
	{
		char *buf = kmalloc((src->buflen+1) * sizeof(__u16), GFP_KERNEL);
		if(!buf)
			return NDIS_STATUS_FAILURE;
		dst->buf = buf;
		dst->buflen = (src->buflen+1) * sizeof(__u16);
	}
	else if (dst->buflen < (src->len+1) * sizeof(__u16))
		return NDIS_STATUS_FAILURE;

	dst->len = src->len * sizeof(__u16);
	d = (__u16 *)dst->buf;
	s = (__u8 *)src->buf;
	for(i = 0; i < src->len; i++)
	{
		d[i] = (__u16)s[i];
	}
	d[i] = 0;
	
	return NDIS_STATUS_SUCCESS;
}

STDCALL int RtlUnicodeStringToAnsiString(struct ustring *dst, struct ustring *src, unsigned int dup)
{
	int i;
	__u16 *s;
	__u8 *d;

//	DBGTRACE("%s dup: %d src->len: %d src->buflen: %d, dst: %p\n", __FUNCTION__, dup, src->len, src->buflen, dst);
	if(dup)
	{
		char *buf = kmalloc((src->buflen+1) / sizeof(__u16), GFP_KERNEL);
		if(!buf)
			return NDIS_STATUS_FAILURE;
		dst->buf = buf;
		dst->buflen = (src->buflen+1) / sizeof(__u16);
	}
	else if (dst->buflen < (src->len+1) / sizeof(__u16))
		return NDIS_STATUS_FAILURE;

	dst->len = src->len / sizeof(__u16);
	s = (__u16 *)src->buf;
	d = (__u8 *)dst->buf;
	for(i = 0; i < dst->len; i++)
		d[i] = (__u8)s[i];
	d[i] = 0;

//	DBGTRACE(" buf: %s\n", dst->buf);
	return NDIS_STATUS_SUCCESS;
}

STDCALL int RtlIntegerToUnicodeString(unsigned long value, unsigned long base,
									  struct ustring *ustring)
{
	char string[sizeof(unsigned long) * 8 + 1];
	struct ustring ansi;
	int i;

	DBGTRACE("%s: entry\n", __FUNCTION__);
	if (base == 0)
		base = 10;
	if (!(base == 2 || base == 8 || base == 10 || base == 16))
		return NDIS_STATUS_INVALID_PARAMETER;
	for (i = 0; value && i < sizeof(string); i++)
	{
		int r;
		r = value % base;
		value /= base;
		if (r < 10)
			string[i] = r + '0';
		else
			string[i] = r + 'a' - 10;
	}

	if (i < sizeof(string))
		string[i] = 0;
	else
		return NDIS_STATUS_BUFFER_TOO_SHORT;

	ansi.buf = string;
	ansi.len = strlen(string);
	ansi.buflen = sizeof(string);
	return RtlAnsiStringToUnicodeString(ustring, &ansi, 0);
}

void RtlFreeUnicodeString(void){UNIMPL();}
void RtlUnwind(void){UNIMPL();}

/*
 * This is the packet_recycler that gets scheduled from NdisMIndicateReceivePacket
 */
void packet_recycler(void *param)
{
	struct ndis_handle *handle = (struct ndis_handle*) param;

	DBGTRACE("%s Packet recycler running\n", __FUNCTION__);
	while(1)
	{
		struct ndis_packet * packet;

		spin_lock(&handle->recycle_packets_lock);
		packet = 0;
		if(!list_empty(&handle->recycle_packets))
		{
			packet = (struct ndis_packet*) handle->recycle_packets.next;

			list_del(handle->recycle_packets.next);
			DBGTRACE("%s Picking packet at %p!\n", __FUNCTION__, packet);
			packet = (struct ndis_packet*) ((char*)packet - ((char*) &packet->recycle_list - (char*) &packet->nr_pages));
		}

		spin_unlock(&handle->recycle_packets_lock);
		
		if(!packet)
			break;

		handle->driver->miniport_char.return_packet(handle->adapter_ctx,  packet);
	}
}

void inline my_dumpstack(void)
{
	int *sp = (int*) getSp();
	int i;
	for(i = 0; i < 20; i++)
	{
		printk("%08x\n", sp[i]);
	}
}

int getSp(void)
{
	volatile int i;
	asm("movl %esp,(%esp,1)");
	return i;
}

