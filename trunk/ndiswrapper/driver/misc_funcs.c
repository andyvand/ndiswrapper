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
#include <linux/bitmap.h>

#include "ndis.h"

static struct list_head wrap_allocs;
static struct wrap_spinlock wrap_allocs_lock;
static struct wrap_spinlock *wrap_spinlock_array[SPINLOCK_ROWS];
/* bitmap representing used/free spinlock */
static spinlock_bitmap_t wrap_spinlock_bitmap[SPINLOCK_ROWS];
static spinlock_t wrap_spinlock_spinlock; /* spinlock for spinlocks :-) */

int misc_funcs_init(void)
{
	int i;
	struct wrap_spinlock *lock;

	spin_lock_init(&wrap_spinlock_spinlock);
	INIT_LIST_HEAD(&wrap_allocs);
	wrap_spin_lock_init(&wrap_allocs_lock);
	for (i = 0; i < SPINLOCK_ROWS; i++) {
		wrap_spinlock_bitmap[i] = 0UL;
		wrap_spinlock_array[i] = NULL;
	}
	wrap_spinlock_array[0] =
		kmalloc(SPINLOCK_COLUMNS * sizeof(struct wrap_spinlock),
			GFP_KERNEL);
	if (!wrap_spinlock_array[0]) {
		ERROR("couldn't allocate memory");
		return -ENOMEM;
	}
	memset(wrap_spinlock_array[0], 0, 
	       SPINLOCK_COLUMNS * sizeof(struct wrap_spinlock));
	lock = wrap_spinlock_array[0];
	/* we reserve [0][0] lock to check if a buggy driver uses
	   unallocated spinlock */
	set_bit(0, &wrap_spinlock_bitmap[0]);
	for (i = 0; i < SPINLOCK_COLUMNS; i++)
		lock[i].index = i;
	return 0;
}

void misc_funcs_exit(void)
{
	int i;
	for (i = 0; i < SPINLOCK_ROWS; i++)
		if (wrap_spinlock_array[i])
			kfree(wrap_spinlock_array[i]);
	return;
}

void allocate_kspin_lock(KSPIN_LOCK *kspin_lock)
{
	unsigned int r, c, size;
	struct wrap_spinlock *lock;

	spin_lock(&wrap_spinlock_spinlock);
	for (r = 0; r < SPINLOCK_ROWS; r++)
		if (wrap_spinlock_bitmap[r] != ~0UL)
			break;
	if (r == SPINLOCK_ROWS) {
		ERROR("not enough spinlocks available - "
		      "increase SPINLOCK_ROWS");
		/* let kernel crash with useful info instead of having
		   unknown side effects */
		*kspin_lock = 0x12345678;
		spin_unlock(&wrap_spinlock_spinlock);
		return;
	}
	if (wrap_spinlock_array[r] == NULL) {
		int i;

		wrap_spinlock_array[r] =
			kmalloc(SPINLOCK_COLUMNS *
				sizeof(struct wrap_spinlock), GFP_ATOMIC);
		if (!wrap_spinlock_array[r]) {
			ERROR("couldn't allocate memory");
			*kspin_lock = 0x12345678;
			spin_unlock(&wrap_spinlock_spinlock);
			return;
		}
		memset(wrap_spinlock_array[r], 0,
		       SPINLOCK_COLUMNS * sizeof(struct wrap_spinlock));
		lock = wrap_spinlock_array[r];
		for (i = 0; i < SPINLOCK_COLUMNS; i++)
			lock[i].index = r * SPINLOCK_COLUMNS + i;
	}
	size = sizeof(wrap_spinlock_bitmap[r]) * 8;
	c = ffz(wrap_spinlock_bitmap[r]);
	if (test_and_set_bit(c, &wrap_spinlock_bitmap[r]))
		ERROR("bug: spinlock at [%d][%d] is already in use", r,  c );
	lock = wrap_spinlock_array[r];
	lock = &lock[c];

	spin_unlock(&wrap_spinlock_spinlock);
	lock->index = r * SPINLOCK_COLUMNS + c;
	wrap_spin_lock_init(lock);
	*kspin_lock = lock->index;
	DBGTRACE2("allocated spinlock at %d (row: %d, column: %d)",
		  lock->index, r, c);
	return;
}

void free_kspin_lock(KSPIN_LOCK kspin_lock)
{
	unsigned int r, c;

	if (!valid_kspin_lock(kspin_lock))
		ERROR("buggy Windows driver freeing invalid spinlock %d",
		      (u32)kspin_lock);
	else {
		r = kspin_lock / SPINLOCK_COLUMNS;
		c = kspin_lock % SPINLOCK_COLUMNS;
		if (test_bit(c, &wrap_spinlock_bitmap[r])) {
			clear_bit(c, &wrap_spinlock_bitmap[r]);
			DBGTRACE2("freed spinlock at %d (row: %d, column: %d)",
				  (u32)kspin_lock, r, c);
		} else
			ERROR("buggy Windows driver freeing invalid "
			      "spinlock %d", (u32)kspin_lock);
	}
}

int valid_kspin_lock(KSPIN_LOCK kspin_lock)
{
	unsigned int r, c;

	if (kspin_lock == 0)
		return FALSE;

	r = kspin_lock / SPINLOCK_COLUMNS;
	c = kspin_lock % SPINLOCK_COLUMNS;

	if (r >= SPINLOCK_ROWS || c >= SPINLOCK_COLUMNS)
		return FALSE;
	else if (!test_bit(c, &wrap_spinlock_bitmap[r]))
		return FALSE;
	return TRUE;
}

/* given kspin_lock, return wrap_spinlock mapped at that index */
struct wrap_spinlock *kspin_wrap_lock(KSPIN_LOCK kspin_lock)
{
	unsigned int r, c;

	r = kspin_lock / SPINLOCK_COLUMNS;
	c = kspin_lock % SPINLOCK_COLUMNS;
#ifdef DEBUG_SPINLOCK
	if (r == 0 && c == 0)
		ERROR("%d is not a valid spinlock", (u32)kspin_lock);
#endif
	if (!test_bit(c, &wrap_spinlock_bitmap[r])) {
		ERROR("spinlock %d at [%d][%d] is not allocated but"
		      "being used", (u32)kspin_lock, r, c);
		r = c = 0;
	}
	return &wrap_spinlock_array[r][c];
}

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
	wrap_spin_lock(&wrap_allocs_lock, PASSIVE_LEVEL);
	list_add(&alloc->list, &wrap_allocs);
	wrap_spin_unlock(&wrap_allocs_lock);
	DBGTRACE4("%p, %p", alloc, alloc->ptr);
	TRACEEXIT4(return alloc->ptr);
}

void wrap_kfree(void *ptr)
{
	struct list_head *cur, *tmp;

	TRACEENTER4("%p", ptr);
	wrap_spin_lock(&wrap_allocs_lock, PASSIVE_LEVEL);
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

	wrap_spin_unlock(&wrap_allocs_lock);
	TRACEEXIT4(return);
}

void wrap_kfree_all(void)
{
	TRACEENTER4("%s", "");
	wrap_spin_lock(&wrap_allocs_lock, PASSIVE_LEVEL);
	while (!list_empty(&wrap_allocs)) {
		struct wrap_alloc *alloc;

		alloc = list_entry(wrap_allocs.next, struct wrap_alloc, list);
		list_del(&alloc->list);
		kfree(alloc->ptr);
		kfree(alloc);
	}

	wrap_spin_unlock(&wrap_allocs_lock);
	TRACEEXIT4(return);
}

void wrapper_timer_handler(unsigned long data)
{
	struct wrapper_timer *timer = (struct wrapper_timer *)data;
	struct kdpc *kdpc;
	STDCALL void (*miniport_timer)(void *specific1, void *ctx,
				       void *specific2, void *specific3);

	TRACEENTER5("%p", timer);
#ifdef DEBUG_TIMER
	BUG_ON(timer == NULL);
	BUG_ON(timer->wrapper_timer_magic != WRAPPER_TIMER_MAGIC);
	BUG_ON(timer->kdpc == NULL);
#endif

	/* don't add the timer if aperiodic; see wrapper_cancel_timer
	 * protect access to kdpc, repeat, and active via spinlock */
	wrap_spin_lock(&timer->lock, DISPATCH_LEVEL);
	kdpc = timer->kdpc;
	if (timer->repeat) {
		timer->timer.expires = jiffies + timer->repeat;
		add_timer(&timer->timer);
	} else
		timer->active = 0;
	wrap_spin_unlock(&timer->lock);

	miniport_timer = kdpc->func;

	/* call the handler after restarting in case it cancels itself */
	if (miniport_timer) {
		KIRQL irql;
		irql = raise_irql(DISPATCH_LEVEL);
		LIN2WIN4(miniport_timer, kdpc, kdpc->ctx, kdpc->arg1,
			 kdpc->arg2);
		lower_irql(irql);
	}

	TRACEEXIT5(return);
}

void wrapper_init_timer(struct ktimer *ktimer, void *handle)
{
	struct wrapper_timer *wrapper_timer;
	struct ndis_handle *ndis_handle = (struct ndis_handle *)handle;

	TRACEENTER5("%s", "");
	wrapper_timer = wrap_kmalloc(sizeof(struct wrapper_timer), GFP_ATOMIC);
	if (!wrapper_timer) {
		ERROR("couldn't allocate memory for timer");
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
	wrap_spin_lock_init(&wrapper_timer->lock);
	if (handle) {
		wrap_spin_lock(&ndis_handle->timers_lock, DISPATCH_LEVEL);
		list_add(&wrapper_timer->list, &ndis_handle->timers);
		wrap_spin_unlock(&ndis_handle->timers_lock);
	}

	DBGTRACE4("added timer %p, wrapper_timer->list %p\n",
		  wrapper_timer, &wrapper_timer->list);
	TRACEEXIT5(return);
}

int wrapper_set_timer(struct wrapper_timer *timer,
                      unsigned long expires, unsigned long repeat,
		      struct kdpc *kdpc)
{
	TRACEENTER5("%p", timer);
	if (!timer) {
		ERROR("%s", "invalid timer");
		return 0;
	}

#ifdef DEBUG_TIMER
	if (timer->wrapper_timer_magic != WRAPPER_TIMER_MAGIC) {
		WARNING("timer %p is not initialized (%lu)",
			timer, timer->wrapper_timer_magic);
		timer->wrapper_timer_magic = WRAPPER_TIMER_MAGIC;
	}
#endif

	/* timer handler also uses timer->repeat, active, and kdpc, so
	 * protect in case of SMP */
	wrap_spin_lock(&timer->lock, DISPATCH_LEVEL);
	if (kdpc)
		timer->kdpc = kdpc;
	timer->repeat = repeat;
	if (timer->active) {
		DBGTRACE4("modifying timer %p to %lu, %lu",
			  timer, expires, repeat);
		mod_timer(&timer->timer, expires);
		wrap_spin_unlock(&timer->lock);
		TRACEEXIT5(return 1);
	} else {
		DBGTRACE4("setting timer %p to %lu, %lu",
			  timer, expires, repeat);
		timer->timer.expires = expires;
		timer->active = 1;
		add_timer(&timer->timer);
		wrap_spin_unlock(&timer->lock);
		TRACEEXIT5(return 0);
	}
}

void wrapper_cancel_timer(struct wrapper_timer *timer, char *canceled)
{
	TRACEENTER4("timer = %p, canceled = %p", timer, canceled);
	if (!timer) {
		ERROR("%s", "invalid timer");
		return;
	}

#ifdef DEBUG_TIMER
	DBGTRACE4("canceling timer %p", timer);
	BUG_ON(timer->wrapper_timer_magic != WRAPPER_TIMER_MAGIC);
#endif
	/* timer handler also uses timer->repeat, so protect it in
	 * case of SMP */

	/* Oh, and del_timer_sync is not required ('canceled' argument
	 * tells the driver if the timer was deleted or not) here; nor
	 * is del_timer_sync correct, as this function may be called
	 * at DISPATCH_LEVEL */
	wrap_spin_lock(&timer->lock, DISPATCH_LEVEL);
	if (timer->repeat) {
		/* first mark as aperiodic, so timer function doesn't call
		 * add_timer after del_timer returned */
		timer->repeat = 0;
		del_timer(&timer->timer);
		/* periodic timers always return TRUE */
		*canceled = TRUE;
	} else
		*canceled = del_timer(&timer->timer);
	wrap_spin_unlock(&timer->lock);
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

int stricmp(const char *s1, const char *s2)
{
	while (*s1 && *s2 && tolower(*s1) == tolower(*s2)) {
		s1++;
		s2++;
	}
	return (int)*s1 - (int)*s2;
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

NOREGPARM void *WRAP_EXPORT(_win_memcpy)
	(void *to, const void *from, SIZE_T n)
{
	return memcpy(to, from, n);
}

NOREGPARM void *WRAP_EXPORT(_win_strcpy)
	(void *to, const void *from)
{
	return strcpy(to, from);
}

NOREGPARM void *WRAP_EXPORT(_win_memset)
	(void *s, char c, SIZE_T count)
{
	return memset(s, c, count);
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

STDCALL __s64 WRAP_EXPORT(_alldiv)
	(__s64 a, __s64 b)
{
	return (a / b);
}

STDCALL __u64 WRAP_EXPORT(_aulldiv)
	(__u64 a, __u64 b)
{
	return (a / b);
}

STDCALL __s64 WRAP_EXPORT(_allmul)
	(__s64 a, __s64 b)
{
	return (a * b);
}

STDCALL __u64 WRAP_EXPORT(_aullmul)
	(__u64 a, __u64 b)
{
	return (a * b);
}

STDCALL __s64 WRAP_EXPORT(_allrem)
	(__s64 a, __s64 b)
{
	return (a % b);
}

STDCALL __u64 WRAP_EXPORT(_aullrem)
	(__u64 a, __u64 b)
{
	return (a % b);
}

__attribute__ ((regparm(3))) __s64 WRAP_EXPORT(_allshl)
	(__s64 a, __u8 b)
{
	return (a << b);
}

__attribute__ ((regparm(3))) __u64 WRAP_EXPORT(_aullshl)
	(__u64 a, __u8 b)
{
	return (a << b);
}

__attribute__ ((regparm(3))) __s64 WRAP_EXPORT(_allshr)
	(__s64 a, __u8 b)
{
	return (a >> b);
}

__attribute__ ((regparm(3))) __u64 WRAP_EXPORT(_aullshr)
	(__u64 a, __u8 b)
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
			ret = toupper((__u8)*p1++) - toupper((__u8)*p2++);
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

STDCALL NT_STATUS WRAP_EXPORT(RtlAnsiStringToUnicodeString)
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
			TRACEEXIT1(return NDIS_STATUS_FAILURE);
		dst->buf = buf;
		dst->buflen = (src->buflen+1) * sizeof(wchar_t);
	}
	else if (dst->buflen < (src->len+1) * sizeof(wchar_t))
		TRACEEXIT1(return NDIS_STATUS_FAILURE);

	dst->len = src->len * sizeof(wchar_t);
	d = dst->buf;
	s = src->buf;
	for(i = 0; i < src->len; i++)
		d[i] = s[i];

	d[i] = 0;

	DBGTRACE2("len = %d", dst->len);
	TRACEEXIT2(return NDIS_STATUS_SUCCESS);
}

STDCALL NT_STATUS WRAP_EXPORT(RtlUnicodeStringToAnsiString)
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
			return NDIS_STATUS_FAILURE;
		dst->buf = buf;
		dst->buflen = (src->buflen+1) / sizeof(wchar_t);
	} else if (dst->buflen < (src->len+1) / sizeof(wchar_t))
		return NDIS_STATUS_FAILURE;

	dst->len = src->len / sizeof(wchar_t);
	s = src->buf;
	d = dst->buf;
	for(i = 0; i < dst->len; i++)
		d[i] = s[i];
	d[i] = 0;

	DBGTRACE2("len = %d", dst->len);
	DBGTRACE2("string: %s", dst->buf);
	TRACEEXIT2(return NDIS_STATUS_SUCCESS);
}

STDCALL NT_STATUS WRAP_EXPORT(RtlUnicodeStringToInteger)
	(struct unicode_string *ustring, ULONG base, ULONG *value)
{
	int negsign;
	wchar_t *str;

	*value = 0;
	if (ustring->buflen <= 0)
		return STATUS_INVALID_PARAMETER;

	str = ustring->buf;

	negsign = 0;
	switch (((char)*str)) {
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

STDCALL NT_STATUS WRAP_EXPORT(RtlIntegerToUnicodeString)
	(ULONG value, ULONG base, struct unicode_string *ustring)
{
	char string[sizeof(wchar_t) * 8 + 1];
	struct ansi_string ansi;
	int i;

	TRACEENTER1("%s", "");
	if (base == 0)
		base = 10;
	if (!(base == 2 || base == 8 || base == 10 || base == 16))
		return NDIS_STATUS_INVALID_PARAMETER;
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
		return NDIS_STATUS_BUFFER_TOO_SHORT;

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

STDCALL NT_STATUS WRAP_EXPORT(RtlQueryRegistryValues)
	(ULONG relative, const wchar_t *path, void *tbl, void *context,
	 void *env)
{
	TRACEENTER5("%s", "");
	UNIMPL();
	TRACEEXIT5(return STATUS_SUCCESS);
}

STDCALL NT_STATUS WRAP_EXPORT(RtlWriteRegistryValue)
	(ULONG relative, const wchar_t *path, const wchar_t *name, ULONG type,
	 void *data, ULONG length)
{
	TRACEEXIT5(return STATUS_SUCCESS);
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

void *get_sp(void)
{
	ULONG_PTR i;

#ifdef CONFIG_X86_64
	asm("movq %%rsp, %0\n" : "=g"(i));
#else
	asm("movl %%esp, %0\n" : "=g"(i));
#endif

	return (void *)i;
}

void dump_stack(void)
{
	void *sp = get_sp();
	int i;
	for (i = 0; i < 20; i++)
		printk(KERN_DEBUG "sp[%d] = %p\n",
		       i, (void *)((ULONG_PTR *)sp)[i]);
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
