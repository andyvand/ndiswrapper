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

static struct list_head wrap_allocs;
static KSPIN_LOCK wrap_allocs_lock;
static struct nt_list_entry wrapper_timer_list;

extern KSPIN_LOCK ntoskernel_lock;

int misc_funcs_init(void)
{
	INIT_LIST_HEAD(&wrap_allocs);
	kspin_lock_init(&wrap_allocs_lock);
	InitializeListHead(&wrapper_timer_list);
	return 0;
}

/* called when a handle is being removed */
void misc_funcs_exit_handle(struct ndis_handle *handle)
{
	char canceled;

	/* cancel any timers left by bugyy windows driver
	 * Also free the memory for timers
	 */
	while (1) {
		struct nt_list_entry *ent;
		struct wrapper_timer *wrapper_timer;

		kspin_lock(&handle->timer_lock);
		ent = RemoveHeadList(&handle->wrapper_timer_list);
		kspin_unlock(&handle->timer_lock);
		if (!ent)
			break;
		wrapper_timer = container_of(ent, struct wrapper_timer, list);
		wrapper_cancel_timer(wrapper_timer, &canceled);
		wrap_kfree(wrapper_timer);
	}
}

/* called when module is being removed */
void misc_funcs_exit(void)
{
	/* free kernel (Ke) timers */
	while (1) {
		struct nt_list_entry *ent;
		struct wrapper_timer *wrapper_timer;
		char canceled;

		kspin_lock(&ntoskernel_lock);
		ent = RemoveTailList(&wrapper_timer_list);
		kspin_unlock(&ntoskernel_lock);
		if (!ent)
			break;
		wrapper_timer = container_of(ent, struct wrapper_timer, list);
		wrapper_cancel_timer(wrapper_timer, &canceled);
		wrap_kfree(wrapper_timer);
	}
	/* free all pointers on the allocated list */
	kspin_lock(&wrap_allocs_lock);
	while (!list_empty(&wrap_allocs)) {
		struct wrap_alloc *alloc;

		alloc = list_entry(wrap_allocs.next, struct wrap_alloc, list);
		list_del(&alloc->list);
		kfree(alloc->ptr);
		kfree(alloc);
	}
	kspin_unlock(&wrap_allocs_lock);

	TRACEEXIT4(return);
}

/* allocate memory with given flags and add it to list of allocated pointers;
 * if a driver doesn't free this memory for any reason (buggy driver or we
 * allocate space behind driver's back since we need more space than
 * corresponding Windows structure provides etc.), this gets freed
 * automatically during module unloading
 */
void *wrap_kmalloc(size_t size, int flags)
{
	struct wrap_alloc *alloc;

	TRACEENTER4("size = %lu, flags = %d", (unsigned long)size, flags);

	if ((flags & GFP_ATOMIC) || irqs_disabled())
		alloc = kmalloc(sizeof(*alloc), GFP_ATOMIC);
	else
		alloc = kmalloc(sizeof(*alloc), GFP_KERNEL);
	if (!alloc)
		return NULL;
	alloc->ptr = kmalloc(size, flags);
	if (!alloc->ptr) {
		kfree(alloc);
		return NULL;
	}
	kspin_lock(&wrap_allocs_lock);
	list_add(&alloc->list, &wrap_allocs);
	kspin_unlock(&wrap_allocs_lock);
	DBGTRACE4("%p, %p", alloc, alloc->ptr);
	TRACEEXIT4(return alloc->ptr);
}

/* free pointer and remove from list of allocated pointers */
void wrap_kfree(void *ptr)
{
	struct list_head *cur, *tmp;

	TRACEENTER4("%p", ptr);
	kspin_lock(&wrap_allocs_lock);
	list_for_each_safe(cur, tmp, &wrap_allocs) {
		struct wrap_alloc *alloc;

		alloc = list_entry(cur, struct wrap_alloc, list);
		if (alloc->ptr == ptr) {
			list_del(&alloc->list);
			kfree(alloc->ptr);
			kfree(alloc);
			break;
		}
	}
	kspin_unlock(&wrap_allocs_lock);
	TRACEEXIT4(return);
}

void wrapper_timer_handler(unsigned long data)
{
	struct ktimer *ktimer = (struct ktimer *)data;
	struct wrapper_timer *wrapper_timer;
	struct kdpc *kdpc;
	DPC timer_func;
	KIRQL irql;

	TRACEENTER5("%p", ktimer);
	wrapper_timer = ktimer->wrapper_timer;

#ifdef DEBUG_TIMER
	BUG_ON(wrapper_timer == NULL);
	BUG_ON(wrapper_timer->wrapper_timer_magic != WRAPPER_TIMER_MAGIC);
	BUG_ON(wrapper_timer->kdpc == NULL);
#endif

	/* Dpcs run at DISPATCH_LEVEL */
	irql = raise_irql(DISPATCH_LEVEL);

	/* don't add the timer if aperiodic; see wrapper_cancel_timer
	 * protect access to kdpc, repeat, and active via spinlock */
	kspin_lock(&wrapper_timer->lock);
	kdpc = wrapper_timer->kdpc;
	if (kdpc && kdpc->func)
		timer_func = kdpc->func;
	else
		timer_func = NULL;
	if (wrapper_timer->repeat) {
		wrapper_timer->timer.expires = jiffies + wrapper_timer->repeat;
		add_timer(&wrapper_timer->timer);
	} else {
		wrapper_timer->active = 0;
	}
	kspin_unlock(&wrapper_timer->lock);

	KeSetEvent((struct kevent *)ktimer, 0, FALSE);

	/* call timer function after restarting in case it cancels itself */
	if (timer_func)
		LIN2WIN4(timer_func, kdpc, kdpc->ctx, kdpc->arg1,
			 kdpc->arg2);
	lower_irql(irql);

	TRACEEXIT5(return);
}

/* we don't initialize ktimer event's signal here; that is caller's
 * responsibility */

/* NDIS (miniport) timers set kdpc during timer initialization and Ke
 * timers set it during timer setup, so it is passed to both
 * wrapper_init_timer and wrapper_set_timer */
void wrapper_init_timer(struct ktimer *ktimer, void *handle, struct kdpc *kdpc)
{
	struct wrapper_timer *wrapper_timer;
	struct ndis_handle *ndis_handle = (struct ndis_handle *)handle;

	TRACEENTER5("%s", "");
	/* we allocate memory for wrapper_timer behind driver's back
	 * and there is no NDIS/DDK function where this memory can be
	 * freed, so we use wrap_kmalloc so it gets freed when driver
	 * is unloaded */
	wrapper_timer = wrap_kmalloc(sizeof(*wrapper_timer), GFP_ATOMIC);
	if (!wrapper_timer) {
		ERROR("couldn't allocate memory for timer");
		return;
	}

	memset(wrapper_timer, 0, sizeof(*wrapper_timer));
	init_timer(&wrapper_timer->timer);
	wrapper_timer->timer.data = (unsigned long)ktimer;
	wrapper_timer->timer.function = &wrapper_timer_handler;
#ifdef DEBUG_TIMER
	wrapper_timer->wrapper_timer_magic = WRAPPER_TIMER_MAGIC;
#endif
	wrapper_timer->kdpc = kdpc;
	wrapper_timer->ktimer = ktimer;
	ktimer->wrapper_timer = wrapper_timer;
	kspin_lock_init(&wrapper_timer->lock);
	if (ndis_handle) {
		kspin_lock(&ndis_handle->timer_lock);
		InsertHeadList(&ndis_handle->wrapper_timer_list,
			       &wrapper_timer->list);
		kspin_unlock(&ndis_handle->timer_lock);
	} else {
		kspin_unlock(&ntoskernel_lock);
		InsertHeadList(&wrapper_timer_list, &wrapper_timer->list);
		kspin_unlock(&ntoskernel_lock);
	}

	DBGTRACE4("added timer %p, wrapper_timer->list %p\n",
		  wrapper_timer, &wrapper_timer->list);
	TRACEEXIT5(return);
}

/* 'expires' is relative to jiffies, so when setting timer, add
 * jiffies to it */
int wrapper_set_timer(struct wrapper_timer *wrapper_timer, unsigned long expires,
		      unsigned long repeat, struct kdpc *kdpc)
{
	KIRQL irql;
	struct ktimer *ktimer = wrapper_timer->ktimer;

	TRACEENTER5("%p", wrapper_timer);
	if (!wrapper_timer) {
		ERROR("invalid timer");
		return FALSE;
	}

#ifdef DEBUG_TIMER
	if (wrapper_timer->wrapper_timer_magic != WRAPPER_TIMER_MAGIC) {
		WARNING("timer %p is not initialized (%lu)",
			wrapper_timer, wrapper_timer->wrapper_timer_magic);
		wrapper_timer->wrapper_timer_magic = WRAPPER_TIMER_MAGIC;
	}
#endif

	/* timer handler also uses timer->repeat, active, and kdpc, so
	 * protect in case of SMP */
	KeClearEvent((struct kevent *)ktimer);
	irql = kspin_lock_irql(&wrapper_timer->lock, DISPATCH_LEVEL);
	if (kdpc)
		wrapper_timer->kdpc = kdpc;
	wrapper_timer->repeat = repeat;
	if (wrapper_timer->active) {
		DBGTRACE4("modifying timer %p to %lu, %lu",
			  wrapper_timer, expires, repeat);
		mod_timer(&wrapper_timer->timer, jiffies + expires);
		kspin_unlock_irql(&wrapper_timer->lock, irql);
		TRACEEXIT5(return TRUE);
	} else {
		DBGTRACE4("setting timer %p to %lu, %lu",
			  wrapper_timer, expires, repeat);
		wrapper_timer->timer.expires = jiffies + expires;
		wrapper_timer->active = 1;
		add_timer(&wrapper_timer->timer);
		kspin_unlock_irql(&wrapper_timer->lock, irql);
		TRACEEXIT5(return FALSE);
	}
}

void wrapper_cancel_timer(struct wrapper_timer *wrapper_timer, char *canceled)
{
	KIRQL irql;

	TRACEENTER4("timer = %p, canceled = %p", wrapper_timer, canceled);
	if (!wrapper_timer) {
		ERROR("%s", "invalid wrapper_timer");
		return;
	}

#ifdef DEBUG_TIMER
	DBGTRACE4("canceling timer %p", wrapper_timer);
	BUG_ON(wrapper_timer->wrapper_timer_magic != WRAPPER_TIMER_MAGIC);
#endif
	/* timer handler also uses timer->repeat, so protect it in
	 * case of SMP */

	/* Oh, and del_timer_sync is not required ('canceled' argument
	 * tells the driver if the timer was deleted or not) here; nor
	 * is del_timer_sync correct, as this function may be called
	 * at DISPATCH_LEVEL */
	irql = kspin_lock_irql(&wrapper_timer->lock, DISPATCH_LEVEL);
	if (wrapper_timer->active) {
		if (wrapper_timer->repeat) {
			/* first mark as aperiodic, so timer function
			 * doesn't call add_timer after del_timer
			 * returned */
			wrapper_timer->repeat = 0;
			del_timer(&wrapper_timer->timer);
			/* periodic timers always return TRUE */
			*canceled = TRUE;
		} else
			*canceled = del_timer(&wrapper_timer->timer);
		wrapper_timer->active = 0;
	} else
		*canceled = FALSE;
	kspin_unlock_irql(&wrapper_timer->lock, irql);
	if (*canceled == TRUE)
		KeClearEvent((struct kevent *)wrapper_timer->ktimer);
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
	}
	else dst->len = 0;
	TRACEEXIT1(return);
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
	(struct unicode_string *dest, wchar_t *src)
{
	struct unicode_string *uc;

	TRACEENTER1("%s", "");
	uc = dest;
	if (uc == NULL)
		TRACEEXIT1(return);
	if (src == NULL) {
		dest->len = dest->buflen = 0;
		dest->buf = NULL;
	} else {
		int i = 0;
		while (src[i])
			i++;
		dest->buf = src;
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
	(ULONG relative, const wchar_t *path, void *tbl, void *context,
	 void *env)
{
	TRACEENTER5("%s", "");
	UNIMPL();
	TRACEEXIT5(return STATUS_SUCCESS);
}

STDCALL NTSTATUS WRAP_EXPORT(RtlWriteRegistryValue)
	(ULONG relative, const wchar_t *path, const wchar_t *name, ULONG type,
	 void *data, ULONG length)
{
	TRACEEXIT5(return STATUS_SUCCESS);
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

ULONGLONG ticks_1601(void)
{
	struct timeval now;
	ULONGLONG ticks;

	do_gettimeofday(&now);
	ticks = (ULONGLONG) now.tv_sec * TICKSPERSEC;
	ticks += now.tv_usec * 10 + TICKS_1601_TO_1970;
	return ticks;
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

void dump_bytes(const char *where, const u8 *ip)
{
	int i, j;
	u8 code[50];

	memset(code, 0, sizeof(code));
	for (i = j = 0; i < 16; i++, j += 3) {
		if (j+3 > sizeof(code))
			ERROR("not enough space: %u > %u", j+3,
			      (unsigned int)sizeof(code));
		else
			sprintf(&code[j], "%02x ", ip[i]);
	}
	code[sizeof(code)-1] = 0;
	printk(KERN_DEBUG "%s: %p: %s\n", where, ip, code);
}

#include "misc_funcs_exports.h"
