/*
 *  Copyright (C) 2003-2004 Pontus Fuchs, Giridhar Pemmasani
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
#include <linux/module.h>
#include <linux/mm.h>
#include <asm/pgalloc.h>

#include "coffpe.h"
#include "ndis.h"

#define RADR(base, rva, type) (type) ((char*)base + rva)

extern struct wrap_func ntos_wrap_funcs[], ndis_wrap_funcs[],
	misc_wrap_funcs[], hal_wrap_funcs[], usb_wrap_funcs[];

WRAP_FUNC *get_wrap_func(char *name)
{
	int i;

	for (i = 0 ; ntos_wrap_funcs[i].name != NULL; i++)
		if (strcmp(ntos_wrap_funcs[i].name, name) == 0)
			return ntos_wrap_funcs[i].func;

	for (i = 0 ; ndis_wrap_funcs[i].name != NULL; i++)
		if (strcmp(ndis_wrap_funcs[i].name, name) == 0)
			return ndis_wrap_funcs[i].func;

	for (i = 0 ; misc_wrap_funcs[i].name != NULL; i++)
		if (strcmp(misc_wrap_funcs[i].name, name) == 0)
			return misc_wrap_funcs[i].func;

	for (i = 0 ; hal_wrap_funcs[i].name != NULL; i++)
		if (strcmp(hal_wrap_funcs[i].name, name) == 0)
			return hal_wrap_funcs[i].func;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	for (i = 0 ; usb_wrap_funcs[i].name != NULL; i++)
		if (strcmp(usb_wrap_funcs[i].name, name) == 0)
			return usb_wrap_funcs[i].func;
#endif /* support on 2.4 not implemented */

	return NULL;
}

/*
 * Find and validate the coff header
 *
 */
static struct mscoff_hdr *check_coff_hdr(void *image, int size, int offset)
{
	const char pe_sign[4] = {'P', 'E', 0, 0};
	long char_must;

	struct mscoff_hdr * hdr;

	/* Make sure we have enough data */
	if(offset + sizeof(struct mscoff_hdr) + 4 > size)
		return 0;

	/* Validate the pe signature */
	if(memcmp(pe_sign, image + offset, 4) != 0)
		return 0;

	/* Right after the signature comes the header */
	hdr = (struct mscoff_hdr*) (image + offset + 4);

	/* Make sure Image is PE32 */
	if(hdr->magic != COFF_MAGIC_PE32)
		return 0;
	
	if(hdr->stdhdr.machine != COFF_MACHINE_I386)
	{
		ERROR("%s", "Driver is not for i386");
		return 0;
	}

	/* Make sure this is a relocatable 32 bit dll */
	char_must = COFF_CHAR_IMAGE | COFF_CHAR_32BIT;
	if((hdr->stdhdr.characteristics & char_must) != char_must)
		return 0;

	/* Must be a relocatable dll */
	if((hdr->stdhdr.characteristics & COFF_CHAR_RELOCS_STRIPPED))
		return 0;

	/* Make sure we have at least one section */
	if(hdr->stdhdr.num_sections == 0)
		return 0;

	if(hdr->section_alignment != hdr->file_alignment)
	{
		ERROR("Alignment mismatch: secion: 0x%lx, file: 0x%lx",
		      hdr->section_alignment, hdr->file_alignment);
		return 0;
	}

	return hdr;
}


static int import(void *image, struct coffpe_import_dirent *dirent, char *dll)
{
	cu32 *lookup_tbl, *address_tbl;
	char *symname = 0;
	int i;
	WRAP_FUNC *adr;
	int ret = 0;

	lookup_tbl  = RADR(image, dirent->import_lookup_tbl,    cu32*);
	address_tbl = RADR(image, dirent->import_address_table, cu32*);

	for(i = 0; lookup_tbl[i]; i++) {
		if(lookup_tbl[i] & 0x80000000) {
			ERROR("ordinal import not supported: %d",
			      (int) lookup_tbl[i]);
			return -1;
		}
		else {
			symname = RADR(image, ((lookup_tbl[i] & 0x7fffffff) + 2), char*);
		}

		adr = get_wrap_func(symname);
		if(adr == 0)
		{
			ERROR("Unknown symbol: %s:%s", dll, symname);
			ret = -1;
		}
		DBGTRACE1("Importing rva %08x: %s : %s",
			  (int)(&address_tbl[i]) - (int)image, dll, symname); 
		address_tbl[i] = (cu32)adr;
	}
	return ret;
}

static int load_imports(void *image, struct coffpe_import_dirent *dirent)
{
	int i;
	char *name;
	int ret = 0, res;
	for(i = 0; dirent[i].name_rva; i++) {
		name = RADR(image, dirent[i].name_rva, char*);

		//printk("Imports from dll: %s\n", name);
		res = import(image, &dirent[i], name);
		if(res)
			ret = res;			
	}
	return ret;
}


/*
 * Perform relocations described by <fixups> of a block at <blockbase> 
 * of size <size>.
 */
static void reloc_block(void *image, cu32 blockbase, cu16 *fixups, int size, int delta)
{
	cu32 fixup_adr;
	int type, offset, i;

	for(i = 0; i < size; i++) {
		type = (fixups[i] >> 12) & 0xf;
		offset = fixups[i] & 0xfff;
		fixup_adr = (cu32)image + blockbase + offset;

		switch(type) {
		case COFF_FIXUP_HIGHLOW:
			*(cu32*) fixup_adr += delta;
			break;
		case COFF_FIXUP_ABSOLUTE:
			break;
		default:
			ERROR("Unsupported fixup type 0x%x at offset %04x",
			      type, offset); 
			break;
		}
	}
}

/*
 * Perform relocations
 */
static int do_reloc(void *image, int relocs_offset, int size, int delta)
{
	struct coffpe_relocs *curr;
	int processed = 0;
	while(processed < size) {
		curr = RADR(image, (long)relocs_offset + processed, struct coffpe_relocs*);

		reloc_block(image, 
			    curr->page_rva,
			    (cu16*) (curr+1), 
			    (int) ((curr->block_size - sizeof(struct coffpe_relocs)) >> 1),
		            delta);
		processed += curr->block_size;
	}

	return 0;
}

/* This one can be used to calc RVA's from virtual addressed so it's nice to have as a global */
int image_offset;

int prepare_coffpe_image(void **entry, void *image, int size)
{
	int header_offset;
	struct mscoff_hdr *hdr;
	/* The PE header is found at the RVA specified at offset 3c. */
	if(size < 0x3c + 4)
		return -1;
	header_offset =  *(long*)(image+0x3c);
//	DBGTRACE("PE Header at offset %08x", (int) header_offset);

	hdr = check_coff_hdr(image, size, header_offset);
	if(hdr == 0)
		return -1;

	if(load_imports(image, RADR(image, hdr->import_tbl.rva, struct coffpe_import_dirent*)))
		return -1;
		
	do_reloc(image, hdr->basereloc_tbl.rva, hdr->basereloc_tbl.size, (int)image - hdr->image_base);
	flush_icache_range(image, size);

	image_offset = (int)image - hdr->image_base;
	*entry = RADR(image, hdr->entry_rva, void*);
	return 0;
}
