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

#include "ntoskernel.h"

int crt_init(void)
{
	return 0;
}

/* called when module is being removed */
void crt_exit(void)
{
	EXIT4(return);
}

noregparm INT WIN_FUNC(_win_sprintf,12)
	(char *buf, const char *format, ...)
{
	va_list args;
	int res;
	va_start(args, format);
	res = vsprintf(buf, format, args);
	va_end(args);
	TRACE2("buf: %p: %s", buf, buf);
	return res;
}

noregparm INT WIN_FUNC(swprintf,12)
	(wchar_t *buf, const wchar_t *format, ...)
{
	TODO();
	EXIT2(return 0);
}

noregparm INT WIN_FUNC(_win_vsprintf,3)
	(char *str, const char *format, va_list ap)
{
	INT i;
	i = vsprintf(str, format, ap);
	TRACE2("str: %p: %s", str, str);
	EXIT2(return i);
}

noregparm INT WIN_FUNC(_win_snprintf,12)
	(char *buf, SIZE_T count, const char *format, ...)
{
	va_list args;
	int res, n;

	n = count > 9 ? 9 : count;
	va_start(args, format);
	res = vsnprintf(buf, n, format, args);
	va_end(args);
	TRACE2("buf: %p: %s", buf, buf);
	return res;
}

noregparm INT WIN_FUNC(_win__snprintf,12)
	(char *buf, SIZE_T count, const char *format, ...)
{
	va_list args;
	int res, n;

	n = count > 9 ? 9 : count;
	va_start(args, format);
	res = vsnprintf(buf, n, format, args);
	va_end(args);
	TRACE2("buf: %p: %s", buf, buf);
	return res;
}

noregparm INT WIN_FUNC(_win_vsnprintf,4)
	(char *str, SIZE_T size, const char *format, va_list ap)
{
	INT i;
	i = vsnprintf(str, size, format, ap);
	TRACE2("str: %p: %s", str, str);
	EXIT2(return i);
}

noregparm INT WIN_FUNC(_win__vsnprintf,4)
	(char *str, SIZE_T size, const char *format, va_list ap)
{
	INT i;
	i = vsnprintf(str, size, format, ap);
	TRACE2("str: %p: %s", str, str);
	EXIT2(return i);
}

noregparm char *WIN_FUNC(_win_strncpy,3)
	(char *dst, char *src, SIZE_T n)
{
	return strncpy(dst, src, n);
}

noregparm SIZE_T WIN_FUNC(_win_strlen,1)
	(const char *s)
{
	return strlen(s);
}

noregparm INT WIN_FUNC(_win_strncmp,3)
	(const char *s1, const char *s2, SIZE_T n)
{
	return strncmp(s1, s2, n);
}

noregparm INT WIN_FUNC(_win_strcmp,2)
	(const char *s1, const char *s2)
{
	return strcmp(s1, s2);
}

noregparm INT WIN_FUNC(_win_stricmp,2)
	(const char *s1, const char *s2)
{
	return stricmp(s1, s2);
}

noregparm char *WIN_FUNC(_win_strncat,3)
	(char *dest, const char *src, SIZE_T n)
{
	return strncat(dest, src, n);
}

noregparm INT WIN_FUNC(_win_wcscmp,2)
	(const wchar_t *s1, const wchar_t *s2)
{
	while (*s1 && *s1 == *s2) {
		s1++;
		s2++;
	}
	return *s1 - *s2;
}

noregparm INT WIN_FUNC(_win_wcsicmp,2)
	(const wchar_t *s1, const wchar_t *s2)
{
	while (*s1 && tolower((char)*s1) == tolower((char)*s2)) {
		s1++;
		s2++;
	}
	return tolower((char)*s1) - tolower((char)*s2);
}

noregparm SIZE_T WIN_FUNC(_win_wcslen,1)
	(const wchar_t *s)
{
	const wchar_t *t = s;
	while (*t)
		t++;
	return t - s;
}

noregparm wchar_t *WIN_FUNC(_win_wcsncpy,3)
	(wchar_t *dest, const wchar_t *src, SIZE_T n)
{
	const wchar_t *s;
	wchar_t *d;
	s = src + n;
	d = dest;
	while (src < s && (*d++ = *src++))
		;
	if (s > src)
		memset(d, 0, (s - src) * sizeof(wchar_t));
	return dest;
}

noregparm wchar_t *WIN_FUNC(_win_wcscpy,2)
	(wchar_t *dest, const wchar_t *src)
{
	wchar_t *d = dest;
	while ((*d++ = *src++))
	       ;
	return dest;
}

noregparm wchar_t *WIN_FUNC(_win_wcscat,2)
	(wchar_t *dest, const wchar_t *src)
{
	wchar_t *d;
	d = dest;
	while (*d)
		d++;
	while ((*d++ = *src++))
		;
	return dest;
}

noregparm INT WIN_FUNC(_win_towupper,1)
	(wchar_t c)
{
	return toupper(c);
}

noregparm INT WIN_FUNC(_win_towlower,1)
	(wchar_t c)
{
	return tolower(c);
}

noregparm INT WIN_FUNC(_win_tolower,1)
	(INT c)
{
	return tolower(c);
}

noregparm INT WIN_FUNC(_win_toupper,1)
	(INT c)
{
	return toupper(c);
}

noregparm void *WIN_FUNC(_win_strcpy,2)
	(void *to, const void *from)
{
	return strcpy(to, from);
}

noregparm char *WIN_FUNC(_win_strstr,2)
	(const char *s1, const char *s2)
{
	return strstr(s1, s2);
}

noregparm char *WIN_FUNC(_win_strchr,2)
	(const char *s, int c)
{
	return strchr(s, c);
}

noregparm char *WIN_FUNC(_win_strrchr,2)
	(const char *s, int c)
{
	return strrchr(s, c);
}

noregparm void *WIN_FUNC(_win_memmove,3)
	(void *to, void *from, SIZE_T count)
{
	return memmove(to, from, count);
}

noregparm void *WIN_FUNC(_win_memchr,3)
	(const void *s, INT c, SIZE_T n)
{
	return memchr(s, c, n);
}

noregparm void *WIN_FUNC(_win_memcpy,3)
	(void *to, const void *from, SIZE_T n)
{
	return memcpy(to, from, n);
}

noregparm void *WIN_FUNC(_win_memset,3)
	(void *s, char c, SIZE_T count)
{
	return memset(s, c, count);
}

noregparm void WIN_FUNC(_win_srand,1)
	(UINT seed)
{
	net_srandom(seed);
}

noregparm int WIN_FUNC(rand,0)
	(void)
{
	char buf[6];
	int i, n;

	get_random_bytes(buf, sizeof(buf));
	for (n = i = 0; i < sizeof(buf) ; i++)
		n += buf[i];
	return n;
}

noregparm int WIN_FUNC(_win_atoi,1)
	(const char *ptr)
{
	int i = simple_strtol(ptr, NULL, 10);
	return i;
}

noregparm int WIN_FUNC(_win_isprint,1)
	(int c)
{
	return isprint(c);
}

wstdcall s64 WIN_FUNC(_alldiv,2)
	(s64 a, s64 b)
{
	return (a / b);
}

wstdcall u64 WIN_FUNC(_aulldiv,2)
	(u64 a, u64 b)
{
	return (a / b);
}

wstdcall s64 WIN_FUNC(_allmul,2)
	(s64 a, s64 b)
{
	return (a * b);
}

wstdcall u64 WIN_FUNC(_aullmul,2)
	(u64 a, u64 b)
{
	return (a * b);
}

wstdcall s64 WIN_FUNC(_allrem,2)
	(s64 a, s64 b)
{
	return (a % b);
}

wstdcall u64 WIN_FUNC(_aullrem,2)
	(u64 a, u64 b)
{
	return (a % b);
}

__attribute__((regparm(3))) s64 WIN_FUNC(_allshl,2)
	(s64 a, u8 b)
{
	return (a << b);
}

__attribute__((regparm(3))) u64 WIN_FUNC(_aullshl,2)
	(u64 a, u8 b)
{
	return (a << b);
}

__attribute__((regparm(3))) s64 WIN_FUNC(_allshr,2)
	(s64 a, u8 b)
{
	return (a >> b);
}

__attribute__((regparm(3))) u64 WIN_FUNC(_aullshr,2)
	(u64 a, u8 b)
{
	return (a >> b);
}

int stricmp(const char *s1, const char *s2)
{
	while (*s1 && tolower(*s1) == tolower(*s2)) {
		s1++;
		s2++;
	}
	return *s1 - *s2;
}

void dump_stack(void)
{
	ULONG_PTR *sp;
	int i;
	get_sp(sp);
	for (i = 0; i < 20; i++)
		printk(KERN_DEBUG "sp[%d] = %p\n", i, (void *)sp[i]);
}

void dump_bytes(const char *ctx, const u8 *from, int len)
{
	int i, j;
	u8 *buf;

	buf = kmalloc(len * 3 + 1, gfp_irql());
	if (!buf) {
		ERROR("couldn't allocate memory");
		return;
	}
	for (i = j = 0; i < len; i++, j += 3) {
		sprintf(&buf[j], "%02x ", from[i]);
	}
	buf[j] = 0;
	printk(KERN_DEBUG "%s: %p: %s\n", ctx, from, buf);
	kfree(buf);
}

#include "crt_exports.h"
