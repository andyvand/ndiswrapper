
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

int misc_funcs_init(void)
{
	InitializeListHead(&wrap_allocs);
	kspin_lock_init(&wrap_allocs_lock);
	return 0;
}

int misc_funcs_init_device(struct wrapper_dev *wd)
{
	return 0;
}

/* called when a handle is being removed */
void misc_funcs_exit_device(struct wrapper_dev *wd)
{
	return;
}

/* called when module is being removed */
void misc_funcs_exit(void)
{
	KIRQL irql;
	struct nt_list *ent;

	/* free all pointers on the allocated list */
	irql = kspin_lock_irql(&wrap_allocs_lock, DISPATCH_LEVEL);
	while ((ent = RemoveHeadList(&wrap_allocs))) {
		struct wrap_alloc *alloc;
		alloc = container_of(ent, struct wrap_alloc, list);
		kfree(alloc->ptr);
		kfree(alloc);
	}
	kspin_unlock_irql(&wrap_allocs_lock, irql);
	TRACEEXIT4(return);
}

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

NOREGPARM INT WRAP_EXPORT(_win_sprintf)
	(char *buf, const char *format, ...)
{
	va_list args;
	int res;
	va_start(args, format);
	res = vsprintf(buf, format, args);
	va_end(args);
	DBGTRACE2("buf: %p: %s", buf, buf);
	return res;
}

NOREGPARM INT WRAP_EXPORT(_win_vsprintf)
	(char *str, const char *format, va_list ap)
{
	INT i;
	i = vsprintf(str, format, ap);
	DBGTRACE2("str: %p: %s", str, str);
	TRACEEXIT2(return i);
}

NOREGPARM INT WRAP_EXPORT(_win_snprintf)
	(char *buf, SIZE_T count, const char *format, ...)
{
	va_list args;
	int res;

	va_start(args, format);
	res = vsnprintf(buf, count, format, args);
	va_end(args);
	DBGTRACE2("buf: %p: %s", buf, buf);
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
	DBGTRACE2("buf: %p: %s", buf, buf);
	return res;
}

NOREGPARM INT WRAP_EXPORT(_win_vsnprintf)
	(char *str, SIZE_T size, const char *format, va_list ap)
{
	INT i;
	i = vsnprintf(str, size, format, ap);
	DBGTRACE2("str: %p: %s", str, str);
	TRACEEXIT2(return i);
}

NOREGPARM INT WRAP_EXPORT(_win__vsnprintf)
	(char *str, SIZE_T size, const char *format, va_list ap)
{
	INT i;
	i = vsnprintf(str, size, format, ap);
	DBGTRACE2("str: %p: %s", str, str);
	TRACEEXIT2(return i);
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
	while (*s1 != L'\0' && *s1 == *s2) {
		s1++;
		s2++;
	}
	return *s1 - *s2;
}

NOREGPARM INT WRAP_EXPORT(_win_wcsicmp)
	(const wchar_t *s1, const wchar_t *s2)
{
	while (*s1 != L'\0' && tolower((char)*s1) == tolower((char)*s2)) {
		s1++;
		s2++;
	}
	return *s1 - *s2;
}

NOREGPARM SIZE_T WRAP_EXPORT(_win_wcslen)
	(const wchar_t *s)
{
	SIZE_T i = 0;
	while (s[i] != L'\0')
		i++;
	return i;
}

NOREGPARM wchar_t *WRAP_EXPORT(_win_wcsncpy)
	(wchar_t *dest, const wchar_t *src, SIZE_T n)
{
	SIZE_T i = 0;
	while (i < n && src[i] != L'\0') {
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

	TRACEENTER2("%s", "");
	len = min(s1->buflen, s2->buflen);
	p1 = s1->buf;
	p2 = s2->buf;
	if (case_insensitive)
		while (!ret && len--)
			ret = toupper(*p1++) - toupper(*p2++);
	else
		while (!ret && len--)
			ret = *p1++ - *p2++;
	if (!ret)
		ret = s1->buflen - s2->buflen;
	TRACEEXIT2(return ret);
}

STDCALL LONG WRAP_EXPORT(RtlCompareUnicodeString)
	(const struct unicode_string *s1, const struct unicode_string *s2,
	 BOOLEAN case_insensitive)
{
	unsigned int len;
	LONG ret = 0;
	const wchar_t *p1, *p2;

	TRACEENTER2("%s", "");

	len = min(s1->buflen, s2->buflen) / sizeof(wchar_t);
	p1 = s1->buf;
	p2 = s2->buf;
	if (case_insensitive)
		while (!ret && len--)
			ret = toupper((u8)*p1++) - toupper((u8)*p2++);
	else
		while (!ret && len--)
			ret = (u8)*p1++ - (u8)*p2++;
	if (!ret)
		ret = s1->buflen - s2->buflen;
	DBGTRACE2("len: %d, %p, %p", len, p1, p2);
	TRACEEXIT2(return ret);
}

STDCALL BOOLEAN WRAP_EXPORT(RtlEqualString)
	(const struct ansi_string *s1, const struct ansi_string *s2,
	 BOOLEAN case_insensitive)
{
	TRACEENTER1("%s", "");
	if (s1->buflen != s2->buflen)
		return FALSE;
	return !RtlCompareString(s1, s2, case_insensitive);
}

STDCALL BOOLEAN WRAP_EXPORT(RtlEqualUnicodeString)
	(const struct unicode_string *s1, const struct unicode_string *s2,
	 BOOLEAN case_insensitive)
{
	if (s1->buflen != s2->buflen)
		return FALSE;
	return !RtlCompareUnicodeString(s1, s2, case_insensitive);
}

STDCALL void WRAP_EXPORT(RtlCopyUnicodeString)
	(struct unicode_string *dst, struct unicode_string *src)
{
	TRACEENTER1("%s", "");
	if (src) {
		dst->buflen = min(src->buflen, dst->len);
		memcpy(dst->buf, src->buf, dst->buflen);
		if (dst->buflen < dst->len)
			dst->buf[dst->buflen / sizeof(wchar_t)] = 0;
	} else
		dst->len = 0;
	TRACEEXIT1(return);
}

STDCALL NTSTATUS WRAP_EXPORT(RtlAppendUnicodeToString)
	(struct unicode_string *dst, wchar_t *src)
{
	if (src) {
		int len;
		for (len = 0; src[len]; len++)
			;
		if (dst->buflen + (len * sizeof(wchar_t)) > dst->len)
			return STATUS_BUFFER_TOO_SMALL;
		memcpy(&dst->buf[dst->buflen], src, len * sizeof(wchar_t));
		dst->buflen += len * sizeof(wchar_t);
		if (dst->len > dst->buflen)
			dst->buf[dst->buflen / sizeof(wchar_t)] = 0;
	}
	return STATUS_SUCCESS;
}

STDCALL NTSTATUS WRAP_EXPORT(RtlAppendUnicodeStringToString)
	(struct unicode_string *dst, struct unicode_string *src)
{
	if (dst->len < src->buflen + dst->buflen)
		return STATUS_BUFFER_TOO_SMALL;
	if (src->buflen) {
		memcpy(&dst->buf[dst->buflen], src->buf, src->buflen);
		dst->buflen += src->buflen;
		if (dst->len > dst->buflen)
			dst->buf[dst->buflen / sizeof(wchar_t)] = 0;
	}
	return STATUS_SUCCESS;
}

STDCALL NTSTATUS WRAP_EXPORT(RtlAnsiStringToUnicodeString)
	(struct unicode_string *dst, const struct ansi_string *src,
	 BOOLEAN dup)
{
	int i;
	wchar_t *d;
	char *s;

	TRACEENTER2("dup: %d src: len: %d buflen: %d, buf: %s,"
		    "dst: %p", dup, src->len, src->buflen, src->buf, dst);

	if (!src->buf || src->buflen == 0 || src->len == 0) {
		dst->buflen = 0;
		if (dup) {
			dst->buf = NULL;
			dst->len = 0;
		} else
			dst->buf[0] = 0;
		TRACEEXIT2(return STATUS_SUCCESS);
	}
	if (dup == TRUE) {
		dst->buf = kmalloc((src->buflen + 1) * sizeof(wchar_t),
				   GFP_KERNEL);
		if (!dst->buf) {
			dst->len = dst->buflen = 0;
			return STATUS_NO_MEMORY;
		}
		dst->len = (src->buflen + 1) * sizeof(wchar_t);
	} else if (dst->len < (src->buflen * sizeof(wchar_t)))
		return STATUS_BUFFER_TOO_SMALL;

	dst->buflen = src->buflen * sizeof(wchar_t);
	d = dst->buf;
	s = src->buf;
	for (i = 0; i < src->buflen; i++)
		d[i] = s[i];
	if (dst->len > dst->buflen)
		d[i] = 0;
	TRACEEXIT2(return STATUS_SUCCESS);
}

STDCALL NTSTATUS WRAP_EXPORT(RtlUnicodeStringToAnsiString)
	(struct ansi_string *dst, const struct unicode_string *src,
	 BOOLEAN dup)
{
	int i;
	wchar_t *s;
	char *d;

	TRACEENTER2("dup: %d src: len: %d buflen: %d, buf: %p,"
		    "dst: %p", dup, src->len, src->buflen, src->buf, dst);

	if (!src->buf || src->buflen == 0 || src->len == 0) {
		dst->buflen = 0;
		if (dup) {
			dst->buf = NULL;
			dst->len = 0;
		} else
			dst->buf[0] = 0;
		TRACEEXIT2(return STATUS_SUCCESS);
	}
	if (dup == TRUE) {
		dst->buf = kmalloc(src->buflen / sizeof(wchar_t) + 1,
				   GFP_KERNEL);
		if (!dst->buf) {
			dst->len = dst->buflen = 0;
			return STATUS_NO_MEMORY;
		}
		dst->len = src->buflen / sizeof(wchar_t) + 1;
	} else if (dst->len < (src->buflen / sizeof(wchar_t)))
		return STATUS_BUFFER_TOO_SMALL;

	dst->buflen = src->buflen / sizeof(wchar_t);
	d = dst->buf;
	s = src->buf;
	for (i = 0; i < dst->buflen; i++)
		d[i] = s[i];
	if (dst->len > dst->buflen)
		d[i] = 0;
	TRACEEXIT2(return STATUS_SUCCESS);
}

STDCALL NTSTATUS WRAP_EXPORT(RtlUnicodeStringToInteger)
	(struct unicode_string *ustring, ULONG base, ULONG *value)
{
	int negsign;
	wchar_t *str;

	*value = 0;
	if (ustring->buflen == 0)
		return STATUS_SUCCESS;

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
	    ((void *)str - (void *)ustring->buf) < ustring->buflen) {
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

	for (; ((void *)str - (void *)ustring->buf) < ustring->buflen;
	     str++) {
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
	char string[sizeof(wchar_t) * (sizeof(ULONG) * 2 + 1)];
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
	(struct unicode_string *dst, const wchar_t *src)
{
	TRACEENTER1("%s", "");
	if (dst == NULL)
		TRACEEXIT1(return);
	if (src == NULL) {
		dst->len = dst->buflen = 0;
		dst->buf = NULL;
	} else {
		int i = 0;
		/* include terminating NULL in length */
		while (src[i++])
			;
		dst->buf = (wchar_t *)src;
		dst->buflen = dst->len = i * sizeof(wchar_t);
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
	} else {
		int i = 0;
		/* include terminating NULL in length */
		while (src[i++])
			;
		dst->buf = src;
		dst->buflen = dst->len = i;
	}
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
	(ULONG relative, wchar_t *path, struct rtl_query_registry_table *tbl,
	 void *context, void *env)
{
	struct ansi_string ansi;
	struct unicode_string unicode;
	NTSTATUS status, ret;

	TRACEENTER3("%x, %p", relative, tbl);
	UNIMPL();

	unicode.buf = path;
	unicode.len = unicode.buflen = _win_wcslen(path);
	if (RtlUnicodeStringToAnsiString(&ansi, &unicode, TRUE) ==
	    STATUS_SUCCESS) {
		DBGTRACE2("%s", ansi.buf);
		RtlFreeAnsiString(&ansi);
	}
	ret = STATUS_SUCCESS;
	for (; tbl->name; tbl++) {
		unicode.buf = tbl->name;
		unicode.len = unicode.buflen = _win_wcslen(tbl->name);
		if (RtlUnicodeStringToAnsiString(&ansi, &unicode, TRUE) ==
		    STATUS_SUCCESS) {
			DBGTRACE2("name: %s", ansi.buf);
			RtlFreeAnsiString(&ansi);
		}
		DBGTRACE2("flags: %08X", tbl->flags);
		if (tbl->flags == RTL_QUERY_REGISTRY_DIRECT) {
			DBGTRACE2("type: %08X", tbl->def_type);
			if (tbl->def_type == REG_DWORD) {
				/* Atheros USB driver needs this, but
				 * don't know where and how to get its
				 * value */
				if (tbl->def_data) {
					DBGTRACE2("def_data: %x",
						  *(int *)tbl->def_data);
					*(DWORD *)tbl->context =
						*(DWORD *)tbl->def_data;
				} else
					*(DWORD *)tbl->context = 0x2345dbe;
			}
		} else {
			void *data;
			ULONG type, length;

			if (!tbl->query_func) {
				ERROR("oops: no query_func");
				ret = STATUS_INVALID_PARAMETER;
				break;
			}
			if (tbl->flags & RTL_QUERY_REGISTRY_NOVALUE) {
				data = NULL;
				type = REG_NONE;
				length = 0;
			} else {
				data = tbl->def_data;
				type = tbl->def_type;
				length = tbl->def_length;;
			}
			DBGTRACE2("calling query_func: %p", tbl->query_func);
			status = LIN2WIN6(tbl->query_func, tbl->name, type,
					  data, length, context, env);
			DBGTRACE2("status: %08X", status);
			if (status) {
				if (status == STATUS_BUFFER_TOO_SMALL)
					ret = STATUS_BUFFER_TOO_SMALL;
				else
					TRACEEXIT2(return STATUS_INVALID_PARAMETER);
			}
		}
	}
	TRACEEXIT3(return ret);
}

STDCALL NTSTATUS WRAP_EXPORT(RtlWriteRegistryValue)
	(ULONG relative, wchar_t *path, wchar_t *name, ULONG type,
	 void *data, ULONG length)
{
	struct ansi_string ansi;
	struct unicode_string unicode;

	TRACEENTER3("%d", relative);
	UNIMPL();

	unicode.buf = path;
	unicode.len = unicode.buflen = _win_wcslen(path);
	if (RtlUnicodeStringToAnsiString(&ansi, &unicode, TRUE) ==
	    STATUS_SUCCESS) {
		DBGTRACE2("%s", ansi.buf);
		RtlFreeAnsiString(&ansi);
	}
	unicode.buf = name;
	unicode.len = unicode.buflen = _win_wcslen(name);
	if (RtlUnicodeStringToAnsiString(&ansi, &unicode, TRUE) ==
	    STATUS_SUCCESS) {
		DBGTRACE2("%s", ansi.buf);
		RtlFreeAnsiString(&ansi);
	}
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
