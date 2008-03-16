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

#ifndef _VSNPRINTF_H_
#define _VSNPRINTF_H_

#ifdef CONFIG_X86_64
int wrap_vsnprintf(char *buf, size_t size, const char *fmt, va_list args);
int wrap_vsprintf(char *buf, const char *fmt, va_list args);
#else
#define wrap_vsnprintf(buf, size, fmt, args) vsnprintf(buf, size, fmt, args)
#define wrap_vsprintf(buf, fmt, args) vsprintf(buf, fmt, args)
#endif

#endif				/* _VSNPRINTF_H_ */
