/*
 *  Copyright (C) 2003 Joseph Dunn
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
#ifndef _LOAD_DRIVER_
#define _LOAD_DRIVER_

/* possible return values for found_heading */
#define IGNORE_SECTION 0
#define FOUND_DEVICES  1

/* prototypes for the flex parser to call when certain tokens are found */
void found_setting(char *name, char *value);
unsigned int found_heading(char *text);
void found_pci_id(unsigned short vendor, unsigned short device);

#endif
