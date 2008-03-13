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

/*
 * Windows va_list has no header, only a bare data area.  Linux va_list has
 * a header in front of the data on x86_64.  Because of that, we cannot pass
 * Windows va_list for Linux functions.  Converting Windows va_list to its
 * Linux equivalent would need to add the header, which could break easily.
 *
 * So, the Linux functions we need to pass Windows to should be duplicated
 * with va_list and va_arg replaced with Windows compatible equivalents.
 * Fortunately, the only function that needs that is vsnprintf().
 *
 * The code is kept i386-compatible to facilitate testing.
 */

#ifndef _VSNPRINTF_H_
#define _VSNPRINTF_H_

#ifdef CONFIG_X86_64

/* Replacement for va_list */
typedef char *VA_LIST;

/* Field length - always 8 on x86_64, 4 or 8 on i386 to fit data */
#define _VA_FIELD_LEN(type) \
	(sizeof(type) <= sizeof(void *) ? sizeof(void *) : sizeof(long long))

/* Get argument of the given type, advance to the next field */
#define VA_ARG(list, type) \
	(*(type *)((list += _VA_FIELD_LEN(type)) - _VA_FIELD_LEN(type)))

int wrap_vsnprintf(char *buf, size_t size, const char *fmt, VA_LIST args);

#else			/* !CONFIG_X86_64 */

#define wrap_vsnprintf(buf, size, fmt, args) vsnprintf(buf, size, fmt, args)
#define VA_LIST va_list

#endif			/* !CONFIG_X86_64 */

#endif			/* _VSNPRINTF_H_ */
