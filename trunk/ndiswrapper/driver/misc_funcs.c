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
#include "wrapper.h"

struct list_head wrap_allocs;

void *wrap_kmalloc(size_t size, int flags)
{
	struct wrap_alloc *alloc;
	if (flags & GFP_KERNEL)
		alloc = kmalloc(sizeof(*alloc), GFP_KERNEL);
	else
		alloc = kmalloc(sizeof(*alloc), GFP_ATOMIC);
	if (!alloc)
		return NULL;
	alloc->ptr = kmalloc(size, flags);
	if (!alloc)
	{
		kfree(alloc);
		return NULL;
	}
	list_add(&alloc->list, &wrap_allocs);
	return alloc->ptr;
}

void wrap_kfree(void *ptr)
{
	struct wrap_alloc *alloc;
	alloc = (struct wrap_alloc *)wrap_allocs.next;
	while (alloc)
		if (alloc->ptr == ptr)
		{
			list_del(&alloc->list);
			kfree(alloc->ptr);
			kfree(alloc);
			return;
		}
		else
			alloc = (struct wrap_alloc *)alloc->list.next;

	printk(KERN_ERR "%s: ptr %p is not found in allocated pointers\n",
	       __FUNCTION__, ptr);
	return;
}

void wrap_kfree_all(void)
{
	struct wrap_alloc *alloc;

	while (!list_empty(&wrap_allocs))
	{
		alloc = (struct wrap_alloc *)wrap_allocs.next;
		list_del(&alloc->list);
		kfree(alloc->ptr);
		kfree(alloc);
		
	}
	return;
}

void wrapper_timer_handler(unsigned long data)
{
	struct wrapper_timer *timer = (struct wrapper_timer *)data;
	struct kdpc *kdpc;
	STDCALL void (*func)(void *res1, void *data, void *res3, void *res4);

	if (!timer)
	{
		printk(KERN_ERR "%s: timer is NULL\n", __FUNCTION__);
		return;
	}
	kdpc = timer->kdpc;
#ifdef DEBUG_TIMER
	BUG_ON(timer->wrapper_timer_magic != WRAPPER_TIMER_MAGIC);
	BUG_ON(kdpc == NULL);
#endif
	func = kdpc->func;

	if (!timer->active)
		return;
	if (timer->repeat)
	{
		timer->timer.expires = jiffies + timer->repeat;
		add_timer(&timer->timer);
	}
	else
		timer->active = 0;
	
	if (func)
		func(kdpc, kdpc->ctx, kdpc->arg1, kdpc->arg2);
}

void wrapper_init_timer(struct ktimer *ktimer, void *handle)
{
	struct wrapper_timer *wrapper_timer;
	struct ndis_handle *ndis_handle = (struct ndis_handle *)handle;
	wrapper_timer = wrap_kmalloc(sizeof(struct wrapper_timer), GFP_KERNEL);
	if(!wrapper_timer)
	{
		printk("%s: Cannot malloc mem for timer\n", DRV_NAME);
		return;
	}

	memset(wrapper_timer, 27, sizeof(*wrapper_timer));
	init_timer(&wrapper_timer->timer);
	wrapper_timer->timer.data = (unsigned long)wrapper_timer;
	wrapper_timer->timer.function = &wrapper_timer_handler;
	wrapper_timer->active = 0;
	wrapper_timer->repeat = 0;
	wrapper_timer->kdpc = NULL;
#ifdef DEBUG_TIMER
	wrapper_timer->wrapper_timer_magic = WRAPPER_TIMER_MAGIC;
#endif
	ktimer->wrapper_timer = wrapper_timer;
	if (handle)
		list_add(&wrapper_timer->list, &ndis_handle->timers);
#ifdef DEBUG_TIMER
	printk(KERN_INFO "%s: added timer %p, wrapper_timer->list %p\n",
	       __FUNCTION__, wrapper_timer, &wrapper_timer->list);
#endif
	DBGTRACE("Allocated timer at %08x\n", (int)wrapper_timer);
}

int wrapper_set_timer(struct wrapper_timer *timer,
                      unsigned long expires, unsigned long repeat)
{
	if (!timer)
	{
		printk("%s: Driver calling NdisSetTimer on an uninitilized timer\n", DRV_NAME);		
		return 0;
	}
	
#ifdef DEBUG_TIMER
	if (timer->wrapper_timer_magic != WRAPPER_TIMER_MAGIC)
	{
		printk(KERN_INFO "%s: timer %p is not initialized (%lu)\n",
		       __FUNCTION__, timer, timer->wrapper_timer_magic);
		timer->wrapper_timer_magic = WRAPPER_TIMER_MAGIC;
	}
#endif
	timer->repeat = repeat;
	
	if (timer->active)
	{
#ifdef DEBUG_TIMER
	printk("Modifying timer %p to %lu, %lu\n", timer, expires, repeat);
#endif
		mod_timer(&timer->timer, expires);
		return 1;
	}
	else
	{
#ifdef DEBUG_TIMER
//	printk("Setting timer %p to %lu, %lu\n", timer, expires, repeat);
#endif
		timer->timer.expires = expires;
		add_timer(&timer->timer);
		timer->active = 1;
		return 0;
	}
}

void wrapper_cancel_timer(struct wrapper_timer *timer, char *canceled)
{
	DBGTRACE("%s: timer = %p, canceled = %p\n", __FUNCTION__, timer, canceled);
	if(!timer)
	{
		printk("%s: Driver calling NdisCancelTimer on an uninitilized timer\n", DRV_NAME);		
		return;
	}

	if (!timer->active)
	{
		*canceled = 0;
		return;
	}
#ifdef DEBUG_TIMER
	printk("Canceling timer %p\n", timer);
	BUG_ON(timer->wrapper_timer_magic != WRAPPER_TIMER_MAGIC);
#endif
	
	timer->repeat = 0;
	*canceled = del_timer_sync(&(timer->timer));
	timer->active = 0;
	return;
}

NOREGPARM int wrap_sprintf(char *buf, const char *format, ...)
{
	va_list args;
	int res;
	va_start(args, format);
	res = vsprintf(buf, format, args);
	va_end(args);
	return res;
}

NOREGPARM int wrap_vsprintf (char *str, const char *format, va_list ap)
{
	return vsprintf(str, format, ap);
}

NOREGPARM int wrap_snprintf(char *buf, size_t count, const char *format, ...)
{
	va_list args;
	int res;
	
	va_start(args, format);
	res = vsnprintf(buf, count, format, args);
	va_end(args);
	return res;
}

NOREGPARM int wrap_vsnprintf (char *str, size_t size,
			      const char *format, va_list ap)
{
	return vsnprintf(str, size, format, ap);
}


NOREGPARM char *wrap_strncpy(char *dst, char *src, int n)
{
	return strncpy(dst, src, n);
}

NOREGPARM size_t wrap_strlen(const char *s)
{
       return strlen(s);
}

NOREGPARM int wrap_strncmp(const char *s1, const char *s2, size_t n)
{
	return strncmp(s1, s2, n);
}

NOREGPARM int wrap_strcmp(const char *s1, const char *s2)
{
	return strcmp(s1, s2);
}

int stricmp(const char *s1, const char *s2)
{
	while (*s1 && *s2 && tolower(*s1) == tolower(*s2))
	{
		s1++;
		s2++;
	}
	return (int)*s1 - (int)*s2;
}

NOREGPARM int wrap_tolower(int c)
{
	return tolower(c);
}

NOREGPARM void *wrap_memcpy(void * to, const void * from, size_t n)
{
	return memcpy(to, from, n);
}

NOREGPARM void *wrap_strcpy(void * to, const void * from)
{
	return strcpy(to, from);
}

NOREGPARM void *wrap_memset(void * s, char c,size_t count)
{
	return memset(s, c, count);
}

NOREGPARM void *wrap_memmove(void *to, void *from, size_t count)
{
	return memmove(to, from, count);
}
 
NOREGPARM void wrap_srand(unsigned int seed)
{
	net_srandom(seed);
}

NOREGPARM int wrap_atoi(const char *ptr)
{
	int i = simple_strtol(ptr, NULL, 10);
	return i;
}


STDCALL __s64 _alldiv(__s64 a, __s64 b)
{
	return (a / b);
}

STDCALL __u64 _aulldiv(__u64 a, __u64 b)
{
	return (a / b);
}

STDCALL __s64 _allmul(__s64 a, __s64 b)
{
	return (a * b);
}

STDCALL __u64 _aullmul(__u64 a, __u64 b)
{
	return (a * b);
}

STDCALL __s64 _allrem(__s64 a, __s64 b)
{
	return (a % b);
}

STDCALL __u64 _aullrem(__u64 a, __u64 b)
{
	return (a % b);
}

__attribute__ ((regparm(3))) __s64 _allshl(__s64 a, __u8 b)
{
	return (a << b);
}

__attribute__ ((regparm(3))) __u64 _aullshl(__u64 a, __u8 b)
{
	return (a << b);
}

__attribute__ ((regparm(3))) __s64 _allshr(__s64 a, __u8 b)
{
	return (a >> b);
}

__attribute__ ((regparm(3))) __u64 _aullshr(__u64 a, __u8 b)
{
	return (a >> b);
}

STDCALL size_t RtlCompareMemory(const void *a, const void *b, size_t len)
{
	size_t i, same;
	char *x, *y;
	
	DBGTRACE("%s: Entry\n", __FUNCTION__);

	x = (char *)a;
	y = (char *)b;
	for(i = same = 0; i < len; i++)
		if (x[i] == y[i])
			same++;
	return same;
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

STDCALL int rand(void)
{
	char buf[6];
	int i, r;
	
	get_random_bytes(buf, sizeof(buf));
	for (r = i = 0; i < sizeof(buf) ; i++)
		r += buf[i];
	return r;
}

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

		packet->status = NDIS_STATUS_SUCCESS;
		handle->driver->miniport_char.return_packet(handle->adapter_ctx,  packet);
	}
}

int getSp(void)
{
	volatile int i;
	asm("movl %esp,(%esp,1)");
	return i;
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

struct wrap_func misc_wrap_funcs[] =
{
	WRAP_FUNC_ENTRY(RtlAnsiStringToUnicodeString),
	WRAP_FUNC_ENTRY(RtlCompareMemory),
	WRAP_FUNC_ENTRY(RtlCompareString),
	WRAP_FUNC_ENTRY(RtlCompareUnicodeString),
	WRAP_FUNC_ENTRY(RtlCopyUnicodeString),
	WRAP_FUNC_ENTRY(RtlEqualString),
	WRAP_FUNC_ENTRY(RtlEqualUnicodeString),
	WRAP_FUNC_ENTRY(RtlFreeUnicodeString),
	WRAP_FUNC_ENTRY(RtlIntegerToUnicodeString),
	WRAP_FUNC_ENTRY(RtlUnicodeStringToAnsiString),
	WRAP_FUNC_ENTRY(RtlUnwind),

	WRAP_FUNC_ENTRY(_alldiv),
	WRAP_FUNC_ENTRY(_allmul),
	WRAP_FUNC_ENTRY(_allrem),
	WRAP_FUNC_ENTRY(_aulldiv),
	WRAP_FUNC_ENTRY(_aullmul),
	WRAP_FUNC_ENTRY(_aullrem),
	WRAP_FUNC_ENTRY(_allshl),
	WRAP_FUNC_ENTRY(_aullshl),
	WRAP_FUNC_ENTRY(_allshr),
	WRAP_FUNC_ENTRY(_aullshr),

	{"atoi",   (WRAP_FUNC *)wrap_atoi},
	{"memcpy",   (WRAP_FUNC *)wrap_memcpy},
	{"memmove",   (WRAP_FUNC *)wrap_memmove},
	{"memset",   (WRAP_FUNC *)wrap_memset},
	{"rand",   (WRAP_FUNC *)rand},
	{"snprintf",   (WRAP_FUNC *)wrap_snprintf},
	{"sprintf",   (WRAP_FUNC *)wrap_sprintf},
	{"srand",   (WRAP_FUNC *)wrap_srand},
	{"strcmp",   (WRAP_FUNC *)wrap_strcmp},
	{"strcpy",   (WRAP_FUNC *)wrap_strcpy},
	{"strlen",   (WRAP_FUNC *)wrap_strlen},
	{"strncmp",   (WRAP_FUNC *)wrap_strncmp},
	{"strncpy",   (WRAP_FUNC *)wrap_strncpy},
	{"tolower",   (WRAP_FUNC *)wrap_tolower},
	{"vsnprintf",   (WRAP_FUNC *)wrap_vsnprintf},
	{"vsprintf",   (WRAP_FUNC *)wrap_vsprintf},
	{"_snprintf",   (WRAP_FUNC *)wrap_snprintf},
	{"_vsnprintf",   (WRAP_FUNC *)wrap_vsnprintf},

	{NULL, NULL}
};
