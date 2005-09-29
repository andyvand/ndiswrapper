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

#include <linux/types.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <asm/io.h>
#include <linux/ctype.h>
#include <linux/net.h>
#include <linux/list.h>

#include "ndis.h"

static struct nt_list wrap_allocs;
static KSPIN_LOCK wrap_allocs_lock;
static struct nt_list wrap_timer_list;
KSPIN_LOCK timer_lock;

extern KSPIN_LOCK ntoskernel_lock;

#if defined(CONFIG_X86_64)
static struct timer_list shared_data_timer;
struct kuser_shared_data kuser_shared_data;
static void update_user_shared_data_proc(unsigned long data);
#endif

int misc_funcs_init(void)
{
	InitializeListHead(&wrap_allocs);
	kspin_lock_init(&wrap_allocs_lock);
	kspin_lock_init(&timer_lock);
	InitializeListHead(&wrap_timer_list);

#if defined(CONFIG_X86_64)
	memset(&kuser_shared_data, 0, sizeof(kuser_shared_data));
	init_timer(&shared_data_timer);
	shared_data_timer.function = &update_user_shared_data_proc;
#endif
	return 0;
}

int misc_funcs_init_device(struct wrapper_dev *wd)
{
	InitializeListHead(&wd->wrap_timer_list);

#if defined(CONFIG_X86_64)
	if(wd->ndis_device->vendor == 0x17fe &&
	   wd->ndis_device->device == 0x2220) {
		*((ULONG64 *)SHARED_SYSTEM_TIME) = ticks_1601();
		shared_data_timer.data = (unsigned long)0;
		/* don't use add_timer - to avoid creating more than
		 * one timer */
		mod_timer(&shared_data_timer, jiffies + 10 * HZ / 1000 + 1);
	}
#endif
	return 0;
}

/* called when a handle is being removed */
void misc_funcs_exit_device(struct wrapper_dev *wd)
{
	KIRQL irql;
	BOOLEAN canceled;

	/* cancel any timers left by bugyy windows driver Also free
	 * the memory for timers */
	while (1) {
		struct nt_list *ent;
		struct wrap_timer *wrap_timer;

		irql = kspin_lock_irql(&timer_lock, DISPATCH_LEVEL);
		ent = RemoveHeadList(&wd->wrap_timer_list);
		kspin_unlock_irql(&timer_lock, irql);
		if (!ent)
			break;
		wrap_timer = container_of(ent, struct wrap_timer, list);
		wrap_cancel_timer(wrap_timer, &canceled);
		if (canceled == TRUE)
			WARNING("Buggy Windows driver left timer %p running; "
				"removed it", wrap_timer->ktimer);
		memset(wrap_timer, 0, sizeof(*wrap_timer));
		wrap_kfree(wrap_timer);
	}
}

/* called when module is being removed */
void misc_funcs_exit(void)
{
	KIRQL irql;
	struct nt_list *ent;
	BOOLEAN canceled;

#if defined(CONFIG_X86_64)
	del_timer_sync(&shared_data_timer);
#endif

	/* free kernel (Ke) timers */
	while (1) {
		struct wrap_timer *wrap_timer;

		irql = kspin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
		ent = RemoveTailList(&wrap_timer_list);
		kspin_unlock_irql(&ntoskernel_lock, irql);
		if (!ent)
			break;
		wrap_timer = container_of(ent, struct wrap_timer, list);
		wrap_cancel_timer(wrap_timer, &canceled);
		if (canceled == TRUE)
			WARNING("Buggy Windows driver left timer %p running; "
				"removed it", wrap_timer->ktimer);
		memset(wrap_timer, 0, sizeof(*wrap_timer));
		wrap_kfree(wrap_timer);
	}
	/* free all pointers on the allocated list */
	irql = kspin_lock_irql(&wrap_allocs_lock, DISPATCH_LEVEL);
	while (1) {
		struct wrap_alloc *alloc;

		ent = RemoveHeadList(&wrap_allocs);
		if (!ent)
			break;
		alloc = container_of(ent, struct wrap_alloc, list);
		kfree(alloc->ptr);
		kfree(alloc);
	}
	kspin_unlock_irql(&wrap_allocs_lock, irql);

	TRACEEXIT4(return);
}

#if defined(CONFIG_X86_64)
static void update_user_shared_data_proc(unsigned long data)
{
	/* this function is called only for inprocomm2220 64-bit
	 * driver */

	/* timer is scheduled every 10ms and the system timer is in
	 * 100ns */
	*((ULONG64 *)SHARED_SYSTEM_TIME) = ticks_1601();
	*((ULONG64 *)SHARED_INTERRUPT_TIME) = jiffies * TICKSPERSEC / HZ;
	*((ULONG64 *)SHARED_TICK_COUNT) = jiffies;

	shared_data_timer.expires += (10 * HZ / 1000) + 1;
	add_timer(&shared_data_timer);
}
#endif

/* allocate memory with given flags and add it to list of allocated pointers;
 * if a driver doesn't free this memory for any reason (buggy driver or we
 * allocate space behind driver's back since we need more space than
 * corresponding Windows structure provides etc.), this gets freed
 * automatically during module unloading
 */
void *wrap_kmalloc(size_t size)
{
	struct wrap_alloc *alloc;
	KIRQL irql;
	unsigned int alloc_flags;

	TRACEENTER4("size = %lu", (unsigned long)size);

	if (current_irql() < DISPATCH_LEVEL)
		alloc_flags = GFP_KERNEL;
	else
		alloc_flags = GFP_ATOMIC;
	alloc = kmalloc(sizeof(*alloc), alloc_flags);
	if (!alloc)
		return NULL;
	alloc->ptr = kmalloc(size, alloc_flags);
	if (!alloc->ptr) {
		kfree(alloc);
		return NULL;
	}
	irql = kspin_lock_irql(&wrap_allocs_lock, DISPATCH_LEVEL);
	InsertTailList(&wrap_allocs, &alloc->list);
	kspin_unlock_irql(&wrap_allocs_lock, irql);
	DBGTRACE4("%p, %p", alloc, alloc->ptr);
	TRACEEXIT4(return alloc->ptr);
}

/* free pointer and remove from list of allocated pointers */
void wrap_kfree(void *ptr)
{
	struct wrap_alloc *alloc;
	KIRQL irql;

	TRACEENTER4("%p", ptr);
	irql = kspin_lock_irql(&wrap_allocs_lock, DISPATCH_LEVEL);
	nt_list_for_each_entry(alloc, &wrap_allocs, list) {
		if (alloc->ptr == ptr) {
			RemoveEntryList(&alloc->list);
			kfree(alloc->ptr);
			kfree(alloc);
			break;
		}
	}
	kspin_unlock_irql(&wrap_allocs_lock, irql);
	TRACEEXIT4(return);
}

void wrap_timer_handler(unsigned long data)
{
	struct ktimer *ktimer = (struct ktimer *)data;
	struct wrap_timer *wrap_timer;
	struct kdpc *kdpc;
	KIRQL irql;

	wrap_timer = ktimer->wrap_timer;
	TRACEENTER5("%p: %p", wrap_timer, ktimer);

#ifdef DEBUG_TIMER
	BUG_ON(wrap_timer == NULL);
	BUG_ON(wrap_timer->wrap_timer_magic != WRAP_TIMER_MAGIC);
	BUG_ON(ktimer->wrap_timer_magic != WRAP_TIMER_MAGIC);
#endif
	irql = kspin_lock_irql(&timer_lock, DISPATCH_LEVEL);
	kdpc = ktimer->kdpc;
	if (wrap_timer->type == WRAP_TIMER_KERNEL)
		KeSetEvent((struct kevent *)ktimer, 0, FALSE);
	/* Prism1 USB driver calls NdisSetTimer with due time as 0,
	 * which according to DDK is wrong - minimum delay should be
	 * 10 milliseconds. The driver then sets two timers with 0
	 * delay and expects them to be executed right
	 * away. Scheduling timer which schedules kdpc's with a worker
	 * in this case results in kernel crash. So we check here for
	 * this case and execute kdpc right away */
	if (kdpc && kdpc->func) {
		if (kdpc->type == KDPC_TYPE_KERNEL)
			insert_kdpc_work(kdpc);
		else
			LIN2WIN4(kdpc->func, kdpc, kdpc->ctx,
				 kdpc->arg1, kdpc->arg2);
	}

	/* don't add the timer if aperiodic - see
	 * wrapper_cancel_timer */
	if (wrap_timer->repeat) {
		wrap_timer->timer.expires += wrap_timer->repeat;
		add_timer(&wrap_timer->timer);
	}
	kspin_unlock_irql(&timer_lock, irql);

	TRACEEXIT5(return);
}

/* we don't initialize ktimer event's signal here; that is caller's
 * responsibility */
void wrap_init_timer(struct ktimer *ktimer, void *handle)
{
	struct wrap_timer *wrap_timer;
	struct wrapper_dev *wd = (struct wrapper_dev *)handle;
	KIRQL irql;

	/* TODO: if a timer is initialized more than once, we allocate
	 * memory for wrap_timer more than once for the same ktimer,
	 * wasting memory. We can check if ktimer->wrap_timer_magic is
	 * set and not allocate, but it is not guaranteed always to be
	 * safe */
	TRACEENTER5("%p", ktimer);
	/* we allocate memory for wrap_timer behind driver's back
	 * and there is no NDIS/DDK function where this memory can be
	 * freed, so we use wrap_kmalloc so it gets freed when driver
	 * is unloaded */
	wrap_timer = wrap_kmalloc(sizeof(*wrap_timer));
	if (!wrap_timer) {
		ERROR("couldn't allocate memory for timer");
		return;
	}

	memset(wrap_timer, 0, sizeof(*wrap_timer));
	init_timer(&wrap_timer->timer);
	wrap_timer->timer.data = (unsigned long)ktimer;
	wrap_timer->timer.function = &wrap_timer_handler;
	wrap_timer->ktimer = ktimer;
	ktimer->wrap_timer = wrap_timer;
#ifdef DEBUG_TIMER
	wrap_timer->wrap_timer_magic = WRAP_TIMER_MAGIC;
#endif
	ktimer->wrap_timer_magic = WRAP_TIMER_MAGIC;
	if (wd) {
		irql = kspin_lock_irql(&timer_lock, DISPATCH_LEVEL);
		InsertTailList(&wd->wrap_timer_list, &wrap_timer->list);
		kspin_unlock_irql(&timer_lock, irql);
	} else {
		irql = kspin_lock_irql(&timer_lock, DISPATCH_LEVEL);
		InsertTailList(&wrap_timer_list, &wrap_timer->list);
		kspin_unlock_irql(&timer_lock, irql);
	}

	DBGTRACE5("added timer %p (%p)", wrap_timer, ktimer);
	TRACEEXIT5(return);
}

/* 'expires' is relative to jiffies, so when setting timer, add
 * jiffies to it */
int wrap_set_timer(struct ktimer *ktimer, long expires, unsigned long repeat,
		   enum wrap_timer_type type)
{
	KIRQL irql;
	BOOLEAN ret;
	struct wrap_timer *wrap_timer;

	TRACEENTER5("%p, repeat: %lu", ktimer, repeat);
	if (!ktimer) {
		ERROR("invalid timer");
		return FALSE;
	}
	if (expires < 0) {
		ERROR("expires (%ld) reset to 0", expires);
		expires = 0;
	}

	if (ktimer->wrap_timer_magic != WRAP_TIMER_MAGIC) {
		WARNING("Buggy Windows timer didn't initialize timer %p; "
			"initializing it now", ktimer);
		wrap_init_timer(ktimer, NULL);
	}
	wrap_timer = ktimer->wrap_timer;
	irql = kspin_lock_irql(&timer_lock, DISPATCH_LEVEL);
	wrap_timer->type = type;
#ifdef DEBUG_TIMER
	if (wrap_timer->wrap_timer_magic != WRAP_TIMER_MAGIC) {
		WARNING("timer %p is not initialized (%lu)",
			wrap_timer, wrap_timer->wrap_timer_magic);
		wrap_timer->wrap_timer_magic = WRAP_TIMER_MAGIC;
	}
#endif
	ret = mod_timer(&wrap_timer->timer, jiffies + expires);
	kspin_unlock_irql(&timer_lock, irql);
	return ret;
}

void wrap_cancel_timer(struct wrap_timer *wrap_timer, BOOLEAN *canceled)
{
	KIRQL irql;
	struct ktimer *ktimer;

	TRACEENTER5("timer = %p", wrap_timer);
	if (!wrap_timer) {
		ERROR("invalid wrap_timer");
		return;
	}
	ktimer = wrap_timer->ktimer;
#ifdef DEBUG_TIMER
	DBGTRACE5("canceling timer %p", wrap_timer);
	BUG_ON(wrap_timer->wrap_timer_magic != WRAP_TIMER_MAGIC);
#endif
	/* del_timer_sync may not be called here, as this function can
	 * be called at DISPATCH_LEVEL */
	irql = kspin_lock_irql(&timer_lock, DISPATCH_LEVEL);
	DBGTRACE5("deleting timer %p(%p)", wrap_timer, ktimer);
	/* disable timer before deleting so it won't be re-armed after
	 * deleting */
	wrap_timer->repeat = 0;
	if (del_timer(&wrap_timer->timer))
		*canceled = TRUE;
	else
		*canceled = FALSE;
	kspin_unlock_irql(&timer_lock, irql);
	DBGTRACE5("canceled (%p): %d", wrap_timer, *canceled);
	TRACEEXIT5(return);
}

NOREGPARM INT WRAP_EXPORT(_win_sprintf)
	(char *buf, const char *format, ...)
{
	va_list args;
	int res;
	va_start(args, format);
	res = vsprintf(buf, format, args);
	va_end(args);
	return res;
}

NOREGPARM INT WRAP_EXPORT(_win_vsprintf)
	(char *str, const char *format, va_list ap)
{
	return vsprintf(str, format, ap);
}

NOREGPARM INT WRAP_EXPORT(_win_snprintf)
	(char *buf, SIZE_T count, const char *format, ...)
{
	va_list args;
	int res;

	va_start(args, format);
	res = vsnprintf(buf, count, format, args);
	va_end(args);
	return res;
}

NOREGPARM INT WRAP_EXPORT(_win__snprintf)
	(char *buf, SIZE_T count, const char *format, ...)
{
	va_list args;
	int res;

	va_start(args, format);
	res = vsnprintf(buf, count, format, args);
	va_end(args);
	return res;
}

NOREGPARM INT WRAP_EXPORT(_win_vsnprintf)
	(char *str, SIZE_T size, const char *format, va_list ap)
{
	return vsnprintf(str, size, format, ap);
}

NOREGPARM INT WRAP_EXPORT(_win__vsnprintf)
	(char *str, SIZE_T size, const char *format, va_list ap)
{
	return vsnprintf(str, size, format, ap);
}

NOREGPARM char *WRAP_EXPORT(_win_strncpy)
	(char *dst, char *src, SIZE_T n)
{
	return strncpy(dst, src, n);
}

NOREGPARM SIZE_T WRAP_EXPORT(_win_strlen)
	(const char *s)
{
       return strlen(s);
}

NOREGPARM INT WRAP_EXPORT(_win_strncmp)
	(const char *s1, const char *s2, SIZE_T n)
{
	return strncmp(s1, s2, n);
}

NOREGPARM INT WRAP_EXPORT(_win_strcmp)
	(const char *s1, const char *s2)
{
	return strcmp(s1, s2);
}

NOREGPARM INT WRAP_EXPORT(_win_stricmp)
	(const char *s1, const char *s2)
{
	return stricmp(s1, s2);
}

NOREGPARM char *WRAP_EXPORT(_win_strncat)
	(char *dest, const char *src, SIZE_T n)
{
	return strncat(dest, src, n);
}

NOREGPARM INT WRAP_EXPORT(_win_wcscmp)
	(const wchar_t *s1, const wchar_t *s2)
{
	while (*s1 && *s2 && *s1 == *s2) {
		s1++;
		s2++;
	}
	return *s1 - *s2;
}

NOREGPARM INT WRAP_EXPORT(_win_wcsicmp)
	(const wchar_t *s1, const wchar_t *s2)
{
	while (*s1 && *s2 && tolower((char)*s1) == tolower((char)*s2)) {
		s1++;
		s2++;
	}
	return *s1 - *s2;
}

NOREGPARM SIZE_T WRAP_EXPORT(_win_wcslen)
	(const wchar_t *s)
{
	SIZE_T i = 0;
	while (s[i])
		i++;
	return i;
}

NOREGPARM wchar_t *WRAP_EXPORT(_win_wcsncpy)
	(wchar_t *dest, const wchar_t *src, SIZE_T n)
{
	SIZE_T i = 0;
	while (i < n && src[i]) {
		dest[i] = src[i];
		i++;
	}
	if (i < n)
		dest[i] = 0;
	return dest;
}

NOREGPARM INT WRAP_EXPORT(_win_tolower)
	(INT c)
{
	return tolower(c);
}

NOREGPARM INT WRAP_EXPORT(_win_toupper)
	(INT c)
{
	return toupper(c);
}

NOREGPARM void *WRAP_EXPORT(_win_strcpy)
	(void *to, const void *from)
{
	return strcpy(to, from);
}

NOREGPARM char *WRAP_EXPORT(_win_strstr)
	(const char *s1, const char *s2)
{
	return strstr(s1, s2);
}

NOREGPARM char *WRAP_EXPORT(_win_strchr)
	(const char *s, int c)
{
	return strchr(s, c);
}

NOREGPARM void *WRAP_EXPORT(_win_memmove)
	(void *to, void *from, SIZE_T count)
{
	return memmove(to, from, count);
}

NOREGPARM void *WRAP_EXPORT(_win_memchr)
	(const void *s, INT c, SIZE_T n)
{
	return memchr(s, c, n);
}

/* memcpy and memset are macros so we can't map them */
NOREGPARM void *WRAP_EXPORT(_win_memcpy)
	(void *to, const void *from, SIZE_T n)
{
	return memcpy(to, from, n);
}

NOREGPARM void *WRAP_EXPORT(_win_memset)
	(void *s, char c, SIZE_T count)
{
	return memset(s, c, count);
}

NOREGPARM void WRAP_EXPORT(_win_srand)
	(UINT seed)
{
	net_srandom(seed);
}

NOREGPARM int WRAP_EXPORT(_win_atoi)
	(const char *ptr)
{
	int i = simple_strtol(ptr, NULL, 10);
	return i;
}

STDCALL int WRAP_EXPORT(_win_isprint)
	(int c)
{
	return isprint(c);
}

STDCALL s64 WRAP_EXPORT(_alldiv)
	(s64 a, s64 b)
{
	return (a / b);
}

STDCALL u64 WRAP_EXPORT(_aulldiv)
	(u64 a, u64 b)
{
	return (a / b);
}

STDCALL s64 WRAP_EXPORT(_allmul)
	(s64 a, s64 b)
{
	return (a * b);
}

STDCALL u64 WRAP_EXPORT(_aullmul)
	(u64 a, u64 b)
{
	return (a * b);
}

STDCALL s64 WRAP_EXPORT(_allrem)
	(s64 a, s64 b)
{
	return (a % b);
}

STDCALL u64 WRAP_EXPORT(_aullrem)
	(u64 a, u64 b)
{
	return (a % b);
}

__attribute__ ((regparm(3))) s64 WRAP_EXPORT(_allshl)
	(s64 a, u8 b)
{
	return (a << b);
}

__attribute__ ((regparm(3))) u64 WRAP_EXPORT(_aullshl)
	(u64 a, u8 b)
{
	return (a << b);
}

__attribute__ ((regparm(3))) s64 WRAP_EXPORT(_allshr)
	(s64 a, u8 b)
{
	return (a >> b);
}

__attribute__ ((regparm(3))) u64 WRAP_EXPORT(_aullshr)
	(u64 a, u8 b)
{
	return (a >> b);
}

STDCALL SIZE_T WRAP_EXPORT(RtlCompareMemory)
	(const void *a, const void *b, SIZE_T len)
{
	size_t i;
	char *x, *y;

	TRACEENTER1("%s", "");

	x = (char *)a;
	y = (char *)b;
	/* MSDN says this should return number of bytes that compare as
	 * equal. This can be interpretted as either all bytes that are
	 * equal in 'len' bytes or that only until the bytes compare as
	 * not equal. Initially we had it the former way, but Realtek driver
	 * doesn't like it that way - it takes many attempts to associate
	 * with WPA. ReactOS returns the number of bytes that are equal
	 * upto when they compare as not equal.
	 * According to lords at #reactos, that is the way it should be
	 * and that msdn is wrong about it!
	 */
	for (i = 0; i < len && x[i] == y[i]; i++)
		;
	return i;
}

STDCALL void WRAP_EXPORT(RtlCopyMemory)
	(void *dst, const void *src, SIZE_T length)
{
	memcpy(dst, src, length);
}

STDCALL void WRAP_EXPORT(RtlZeroMemory)
	(void *dst, SIZE_T length)
{
	memset(dst, 0, length);
}

STDCALL void WRAP_EXPORT(RtlSecureZeroMemory)
	(void *dst, SIZE_T length)
{
	memset(dst, 0, length);
}

STDCALL LONG WRAP_EXPORT(RtlCompareString)
	(const struct ansi_string *s1, const struct ansi_string *s2,
	 BOOLEAN case_insensitive)
{
	unsigned int len;
	LONG ret = 0;
	const char *p1, *p2;

	TRACEENTER1("%s", "");
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

STDCALL LONG WRAP_EXPORT(RtlCompareUnicodeString)
	(const struct unicode_string *s1, const struct unicode_string *s2,
	 BOOLEAN case_insensitive)
{
	unsigned int len;
	LONG ret = 0;
	const wchar_t *p1, *p2;

	TRACEENTER1("%s", "");
	len = min(s1->len, s2->len);
	p1 = s1->buf;
	p2 = s2->buf;

	if (case_insensitive)
		while (!ret && len--)
			ret = toupper((u8)*p1++) - toupper((u8)*p2++);
	else
		while (!ret && len--)
			ret = *p1++ - *p2++;
	if (!ret)
		ret = s1->len - s2->len;
	return ret;
}

STDCALL BOOLEAN WRAP_EXPORT(RtlEqualString)
	(const struct ansi_string *s1, const struct ansi_string *s2,
	 BOOLEAN case_insensitive)
{
	TRACEENTER1("%s", "");
	if (s1->len != s2->len)
		return 0;
	return !RtlCompareString(s1, s2, case_insensitive);
}

STDCALL BOOLEAN WRAP_EXPORT(RtlEqualUnicodeString)
	(const struct unicode_string *s1, const struct unicode_string *s2,
	 BOOLEAN case_insensitive)
{
	if (s1->len != s2->len)
		return 0;
	return !RtlCompareUnicodeString(s1, s2, case_insensitive);
}

STDCALL void WRAP_EXPORT(RtlCopyUnicodeString)
	(struct unicode_string *dst, struct unicode_string *src)
{
	TRACEENTER1("%s", "");
	if (src) {
		unsigned int len = min(src->len, dst->buflen);
		memcpy(dst->buf, src->buf, len);
		dst->len = len;
		/* append terminating '\0' if enough space */
		if (len < dst->buflen)
			dst->buf[len] = 0;
	} else
		dst->len = 0;
	TRACEEXIT1(return);
}

STDCALL NTSTATUS WRAP_EXPORT(RtlAppendUnicodeToString)
	(struct unicode_string *dst, wchar_t *src)
{
	int i;

	for (i = 0; src[i] != 0 && dst->len + i < dst->buflen; i++)
		dst->buf[dst->len + i] = src[i];
	if (src[i] != 0)
		return STATUS_BUFFER_TOO_SMALL;
	dst->len += i;
	return STATUS_SUCCESS;
}

STDCALL NTSTATUS WRAP_EXPORT(RtlAppendUnicodeStringToString)
	(struct unicode_string *dst, struct unicode_string *src)
{
	int i;

	if (dst->buflen < dst->len + src->len)
		return STATUS_BUFFER_TOO_SMALL;

	for (i = 0; i < src->len; i++)
		dst->buf[dst->len + i] = src->buf[i];
	dst->len += i;
	return STATUS_SUCCESS;
}

STDCALL NTSTATUS WRAP_EXPORT(RtlAnsiStringToUnicodeString)
	(struct unicode_string *dst, struct ansi_string *src, BOOLEAN dup)
{
	int i;
	wchar_t *d;
	char *s;

	TRACEENTER2("dup: %d src: %s", dup, src->buf);
	if (dup) {
		wchar_t *buf = kmalloc((src->buflen+1) * sizeof(wchar_t),
				       GFP_KERNEL);
		if (!buf)
			TRACEEXIT1(return STATUS_FAILURE);
		dst->buf = buf;
		dst->buflen = (src->buflen+1) * sizeof(wchar_t);
	}
	else if (dst->buflen < (src->len+1) * sizeof(wchar_t))
		TRACEEXIT1(return STATUS_FAILURE);

	dst->len = src->len * sizeof(wchar_t);
	d = dst->buf;
	s = src->buf;
	for(i = 0; i < src->len; i++)
		d[i] = s[i];

	d[i] = 0;

	DBGTRACE2("len = %d", dst->len);
	TRACEEXIT2(return STATUS_SUCCESS);
}

STDCALL NTSTATUS WRAP_EXPORT(RtlUnicodeStringToAnsiString)
	(struct ansi_string *dst, struct unicode_string *src, BOOLEAN dup)
{
	int i;
	wchar_t *s;
	char *d;

	TRACEENTER2("dup: %d src->len: %d src->buflen: %d, src->buf: %p,"
		    "dst: %p", dup, src->len, src->buflen, src->buf, dst);

	if (dup) {
		char *buf = kmalloc((src->buflen+1) / sizeof(wchar_t),
				    GFP_KERNEL);
		if (!buf)
			return STATUS_FAILURE;
		dst->buf = buf;
		dst->buflen = (src->buflen+1) / sizeof(wchar_t);
	} else if (dst->buflen < (src->len+1) / sizeof(wchar_t))
		return STATUS_FAILURE;

	dst->len = src->len / sizeof(wchar_t);
	s = src->buf;
	d = dst->buf;
	for(i = 0; i < dst->len; i++)
		d[i] = s[i];
	d[i] = 0;

	DBGTRACE2("len = %d", dst->len);
	DBGTRACE2("string: %s", dst->buf);
	TRACEEXIT2(return STATUS_SUCCESS);
}

STDCALL NTSTATUS WRAP_EXPORT(RtlUnicodeStringToInteger)
	(struct unicode_string *ustring, ULONG base, ULONG *value)
{
	int negsign;
	wchar_t *str;

	*value = 0;
	if (ustring->buflen <= 0)
		return STATUS_INVALID_PARAMETER;

	str = ustring->buf;

	negsign = 0;
	switch ((char)*str) {
	case '-':
		negsign = 1;
		/* fall through */
	case '+':
		str++;
		break;
	}
		       
	if (base == 0 &&
	    (void *)str < (void *)&ustring->buf[ustring->buflen]) {
		switch(tolower((char)*str)) {
		case 'x':
			base = 16;
			str++;
			break;
		case 'o':
			base = 8;
			str++;
			break;
		case 'b':
			base = 2;
			str++;
			break;
		default:
			base = 10;
			break;
		}
	}
	if (!(base == 2 || base == 8 || base == 10 || base == 16))
		return STATUS_INVALID_PARAMETER;

	for (; (void *)str < (void *)&ustring->buf[ustring->buflen]; str++) {
		int r;
		char c = tolower((char)*str);

		if (c >= '0' && c <= '9')
			r = c - '0';
		else if (c >= 'a' && c <= 'f')
			r = c - 'a' + 10;
		else
			break;
		if (r >= base)
			break;
		*value = *value * base + r;
	}
	if (negsign)
		*value *= -1;

	return STATUS_SUCCESS;
}

STDCALL NTSTATUS WRAP_EXPORT(RtlIntegerToUnicodeString)
	(ULONG value, ULONG base, struct unicode_string *ustring)
{
	char string[sizeof(wchar_t) * 8 + 1];
	struct ansi_string ansi;
	int i;

	TRACEENTER1("%s", "");
	if (base == 0)
		base = 10;
	if (!(base == 2 || base == 8 || base == 10 || base == 16))
		return STATUS_INVALID_PARAMETER;
	for (i = 0; value && i < sizeof(string); i++) {
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
		return STATUS_BUFFER_TOO_SMALL;

	ansi.buf = string;
	ansi.len = strlen(string);
	ansi.buflen = sizeof(string);
	return RtlAnsiStringToUnicodeString(ustring, &ansi, 0);
}

STDCALL void WRAP_EXPORT(RtlInitUnicodeString)
	(struct unicode_string *dest, const wchar_t *src)
{
	TRACEENTER1("%s", "");
	if (dest == NULL)
		TRACEEXIT1(return);
	if (src == NULL) {
		dest->len = dest->buflen = 0;
		dest->buf = NULL;
	} else {
		int i = 0;
		while (src[i])
			i++;
		dest->buf = (wchar_t *)src;
		dest->len = dest->buflen = i * 2;
	}
	TRACEEXIT1(return);
}

STDCALL void WRAP_EXPORT(RtlInitAnsiString)
	(struct ansi_string *dst, CHAR *src)
{
	TRACEENTER2("%s", "");
	if (dst == NULL)
		TRACEEXIT2(return);
	if (src == NULL) {
		dst->len = dst->buflen = 0;
		dst->buf = NULL;
		TRACEEXIT2(return);
	}
	dst->len = dst->buflen = strlen(src);
	dst->buf = (char *)src;
	TRACEEXIT2(return);
}

STDCALL void WRAP_EXPORT(RtlInitString)
	(struct ansi_string *dst, CHAR *src)
{
	TRACEENTER2("%s", "");
	RtlInitAnsiString(dst, src);
	TRACEEXIT2(return);
}

STDCALL void WRAP_EXPORT(RtlFreeUnicodeString)
	(struct unicode_string *string)
{
	if (string == NULL || string->buf == NULL)
		return;

	kfree(string->buf);
	string->buflen = string->len = 0;
	string->buf = NULL;
	return;
}

STDCALL void WRAP_EXPORT(RtlFreeAnsiString)
	(struct ansi_string *string)
{
	if (string == NULL || string->buf == NULL)
		return;

	kfree(string->buf);
	string->buflen = string->len = 0;
	string->buf = NULL;
	return;
}

STDCALL NTSTATUS WRAP_EXPORT(RtlQueryRegistryValues)
	(ULONG relative, wchar_t *path, void *tbl, void *context,
	 void *env)
{
	struct ansi_string ansi;
	struct unicode_string unicode;
	char buf[32];

	TRACEENTER3("%d, %p", relative, tbl);
	UNIMPL();
	TRACEEXIT3(return STATUS_SUCCESS);

	ansi.buf = buf;
	ansi.buflen = sizeof(buf);
	unicode.buf = path;
	unicode.len = unicode.buflen = _win_wcslen(path);
	RtlUnicodeStringToAnsiString(&ansi, &unicode, FALSE);
	TRACEENTER3("%d, %s, %p", relative, buf, tbl);
	UNIMPL();
	TRACEEXIT3(return STATUS_SUCCESS);
}

STDCALL NTSTATUS WRAP_EXPORT(RtlWriteRegistryValue)
	(ULONG relative, wchar_t *path, wchar_t *name, ULONG type,
	 void *data, ULONG length)
{
	struct ansi_string ansi;
	struct unicode_string unicode;
	char buf[32];

	TRACEENTER3("%d", relative);
	UNIMPL();
	TRACEEXIT3(return STATUS_SUCCESS);

	ansi.buf = buf;
	ansi.buflen = sizeof(buf);
	unicode.buf = path;
	unicode.len = unicode.buflen = _win_wcslen(path);
	RtlUnicodeStringToAnsiString(&ansi, &unicode, FALSE);
	TRACEENTER3("%d, %s", relative, buf);
	unicode.buf = name;
	unicode.len = unicode.buflen = _win_wcslen(name);
	RtlUnicodeStringToAnsiString(&ansi, &unicode, FALSE);
	DBGTRACE3("name: %s", buf);
	TRACEEXIT5(return STATUS_SUCCESS);
}

STDCALL NTSTATUS WRAP_EXPORT(RtlDeleteRegistryValue)
	(ULONG relative, wchar_t *path, wchar_t *name)
{
	return STATUS_SUCCESS;
}

STDCALL void WRAP_EXPORT(RtlAssert)
	(char *failed_assertion, char *file_name, ULONG line_num,
	 char *message)
{
	ERROR("assertion '%s' failed at %s line %d%s",
	      failed_assertion, file_name, line_num, message ? message : "");
	return;
}

STDCALL int WRAP_EXPORT(rand)
	(void)
{
	char buf[6];
	int i, r;

	get_random_bytes(buf, sizeof(buf));
	for (r = i = 0; i < sizeof(buf) ; i++)
		r += buf[i];
	return r;
}

void WRAP_EXPORT(RtlUnwind)(void){UNIMPL();}

int stricmp(const char *s1, const char *s2)
{
	while (*s1 && *s2 && tolower(*s1) == tolower(*s2)) {
		s1++;
		s2++;
	}
	return (int)*s1 - (int)*s2;
}

void *get_sp(void)
{
	ULONG_PTR i;

#ifdef CONFIG_X86_64
	__asm__ __volatile__("movq %%rsp, %0\n" : "=g"(i));
#else
	__asm__ __volatile__("movl %%esp, %0\n" : "=g"(i));
#endif
	return (void *)i;
}

void dump_stack(void)
{
	ULONG_PTR *sp = get_sp();
	int i;
	for (i = 0; i < 20; i++)
		printk(KERN_DEBUG "sp[%d] = %p\n", i, (void *)sp[i]);
}

void dump_bytes(const char *name, const u8 *from, int len)
{
	int i, j;
	u8 code[100];

	memset(code, 0, sizeof(code));
	for (i = j = 0; i < len; i++, j += 3) {
		if (j+3 > sizeof(code)) {
			ERROR("not enough space: %u > %u", j+3,
			      (unsigned int)sizeof(code));
			break;
		} else
			sprintf(&code[j], "%02x ", from[i]);
	}
	code[sizeof(code)-1] = 0;
	printk(KERN_DEBUG "%s: %p: %s\n", name, from, code);
}

#include "misc_funcs_exports.h"
