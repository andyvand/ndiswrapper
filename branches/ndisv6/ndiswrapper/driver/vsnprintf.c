/*
 *  Copyright (C) 2008 Pavel Roskin
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
#include "vsnprintf.h"

struct x86_64_va_list {
	int gp_offset;
	int fp_offset;
	void *overflow_arg_area;
	void *reg_save_area;
};

/* Windows long is 32-bit, so strip single 'l' in integer formats */
static void strip_l_modifier(char *str)
{
	char *ptr = str;
	int in_format = 0;
	char *lptr = NULL;
	char last = 0;
	char *end_ptr;
	char *wptr;

	/* Replace single 'l' inside integer formats with '\0' */
	for (ptr = str; *ptr; ptr++) {
		if (!in_format) {
			if (*ptr == '%')
				in_format = 1;
			last = *ptr;
			continue;
		}
		switch (*ptr) {
		case 'd':
		case 'i':
		case 'o':
		case 'u':
		case 'x':
		case 'X':
		case 'p':
		case 'n':
		case 'm':
			if (lptr) {
				*lptr = '\0';
				lptr = NULL;
			}
			in_format = 0;
			break;
		case 'c':
		case 'C':
		case 's':
		case 'S':
		case 'f':
		case 'e':
		case 'E':
		case 'g':
		case 'G':
		case 'a':
		case 'A':
			lptr = NULL;
			in_format = 0;
			break;
		case '%':
			lptr = NULL;
			if (last == '%')
				in_format = 0;
			else
				in_format = 1;	/* ignore previous junk */
			break;
		case 'l':
			if (last == 'l')
				lptr = NULL;
			else
				lptr = ptr;
			break;
		default:
			break;
		}
		last = *ptr;
	}

	/* Purge zeroes from the resulting string */
	end_ptr = ptr;
	wptr = str;
	for (ptr = str; ptr < end_ptr; ptr++)
		if (*ptr != 0)
			*(wptr++) = *ptr;
	*wptr = 0;
}

int wrap_vsnprintf(char *buf, size_t size, const char *fmt, va_list args)
{
	va_list ap;
	struct x86_64_va_list *list;
	int ret;
	char *fmtcopy;
	int fmtlen;

	list = (struct x86_64_va_list *)&ap;
	list->gp_offset = 48;	/* no GP registers used */
	list->fp_offset = 304;	/* no FP registers used */
	list->overflow_arg_area = (void *)args;
	list->reg_save_area = NULL;

	fmtlen = strlen(fmt) + 1;
	fmtcopy = kmalloc(fmtlen, GFP_KERNEL);
	if (!fmtcopy)
		return 0;

	memcpy(fmtcopy, fmt, fmtlen);
	strip_l_modifier(fmtcopy);
	ret = vsnprintf(buf, size, fmtcopy, ap);
	kfree(fmtcopy);
	return ret;
}

int wrap_vsprintf(char *buf, const char *fmt, va_list args)
{
	va_list ap;
	struct x86_64_va_list *list;
	int ret;
	char *fmtcopy;
	int fmtlen;

	list = (struct x86_64_va_list *)&ap;
	list->gp_offset = 48;	/* no GP registers used */
	list->fp_offset = 304;	/* no FP registers used */
	list->overflow_arg_area = (void *)args;
	list->reg_save_area = NULL;

	fmtlen = strlen(fmt) + 1;
	fmtcopy = kmalloc(fmtlen, GFP_KERNEL);
	if (!fmtcopy)
		return 0;

	memcpy(fmtcopy, fmt, fmtlen);
	strip_l_modifier(fmtcopy);
	ret = vsprintf(buf, fmtcopy, ap);
	kfree(fmtcopy);
	return ret;
}
