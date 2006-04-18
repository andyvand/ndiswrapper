/*
 *  Copyright (C) 2006 Giridhar Pemmasani
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

#ifndef _WRAPMEM_H_

/* define ALLOC_INFO below to get information about memory used by
 * both ndiswrapper and Windows driver by reading
 * /proc/net/ndiswrapper/debug; this will also show allocation
 * information in KERN_DEBUG when ndiswrapper module is unloaded,
 * which indicates if memory is being leaked */

#define ALLOC_INFO 1
#ifdef DEBUG
#define ALLOC_INFO 1
#endif

enum alloc_type { ALLOC_TYPE_ATOMIC, ALLOC_TYPE_NON_ATOMIC,
		  ALLOC_TYPE_VMALLOC, ALLOC_TYPE_SLACK, ALLOC_TYPE_MAX };

int wrapmem_init(void);
void wrapmem_exit(void);
void *slack_kmalloc(size_t size);
void slack_kfree(void *ptr);
void wrapmem_info(void);

#ifdef ALLOC_INFO
void *wrap_kmalloc(size_t size, gfp_t flags);
void wrap_kfree(const void *ptr);
void *wrap_vmalloc(unsigned long size);
void wrap_vfree(void *ptr);
int alloc_size(enum alloc_type type);

#ifndef _WRAPMEM_C_
#define kmalloc(size, flags) wrap_kmalloc(size, flags)
#define kfree(ptr) wrap_kfree(ptr)
#define vmalloc(size) wrap_vmalloc(size)
#define vfree(ptr) wrap_vfree(ptr)
#endif
#endif

#endif
