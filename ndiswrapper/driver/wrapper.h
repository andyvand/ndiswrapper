/*
 *  Copyright (C) 2003 Pontus Fuchs
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
#ifndef WRAPPER_H
#define WRAPPER_H


#include <linux/ioctl.h>

struct put_driver {
	size_t size;
};
                                                                                                                                                                                                                                   
#define WDIOC_PUTDRIVER	_IOWR('N', 0, struct put_driver)
#define WDIOC_TEST	_IOWR('N', 1, int)

#endif /* WRAPPER_H */
