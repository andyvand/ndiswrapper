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

#include <linux/types.h>
#include <asm/errno.h>

#include "pe_loader.h"
#include "ndiswrapper.h"

#define RVA2VA(image, rva, type) (type)rva_to_va(image, rva)

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

	for (i = 0 ; usb_wrap_funcs[i].name != NULL; i++)
		if (strcmp(usb_wrap_funcs[i].name, name) == 0)
			return usb_wrap_funcs[i].func;

	return NULL;
}

/* rva_to_va, get_section and fixup_relocs are heavily based on
 * Bill Paul's PE loader for ndisulator (Project Evil).
 */

static size_t rva_to_va(void *image, uint32_t rva)
{
	struct optional_header *opt_hdr;
	struct section_header *sect_hdr;
	struct nt_header *nt_hdr;
	int i, sections;
	unsigned int nt_hdr_offset;
	size_t ret;

	nt_hdr_offset =  *(unsigned int *)(image+0x3c);
	nt_hdr = (struct nt_header *)((char *)image + nt_hdr_offset);

	sections = nt_hdr->file_hdr.num_sections;
	opt_hdr = &nt_hdr->opt_hdr;
	sect_hdr = (struct section_header *)((void *)nt_hdr +
					     sizeof(struct nt_header));

	for (i = 0; i < sections; i++, sect_hdr++)
	{
		int fixedlen = sect_hdr->virt_size;
		fixedlen += ((opt_hdr->opt_nt_hdr.section_alignment - 1) -
			     sect_hdr->virt_size) &
			(opt_hdr->opt_nt_hdr.section_alignment - 1);

		if (sect_hdr->virt_addr <= (uint32_t)rva &&
		    (sect_hdr->virt_addr + fixedlen) > (uint32_t)rva)
			break;
	}

	if (i > sections)
		return 0;

	ret = ((size_t)(image + rva - sect_hdr->virt_addr +
			sect_hdr->rawdata_addr));
	return ret;
}

static struct section_header *get_section(struct nt_header *nt_hdr,
					  const char *name)
{
	int i, sections;
	struct section_header *sect_hdr;

	sections = nt_hdr->file_hdr.num_sections;
	sect_hdr = (struct section_header *)((size_t)nt_hdr +
					     sizeof(struct nt_header));
	for (i = 0; i < sections; i++)
		if (!strcmp(sect_hdr->name, name))
			return sect_hdr;
		else
			sect_hdr++;

	return NULL;
}

/*
 * Find and validate the coff header
 *
 */
static int check_nt_hdr(struct nt_header *nt_hdr)
{
	const char pe_sign[4] = {'P', 'E', 0, 0};
	long char_must;

	/* Validate the pe signature */
	if(memcmp(pe_sign, nt_hdr->magic, sizeof(pe_sign)) != 0)
		return -EINVAL;

	/* Make sure Image is PE32 */
	if(nt_hdr->opt_hdr.opt_std_hdr.magic != COFF_MAGIC_PE32)
		return -EINVAL;
	
	if(nt_hdr->file_hdr.machine != COFF_MACHINE_I386)
	{
		ERROR("%s", "Driver is not for i386");
		return -EINVAL;
	}

	/* Make sure this is a relocatable 32 bit dll */
	char_must = COFF_CHAR_IMAGE | COFF_CHAR_32BIT;
	if((nt_hdr->file_hdr.characteristics & char_must) != char_must)
		return -EINVAL;

	/* Must be a relocatable dll */
	if((nt_hdr->file_hdr.characteristics & COFF_CHAR_RELOCS_STRIPPED))
		return -EINVAL;

	/* Make sure we have at least one section */
	if(nt_hdr->file_hdr.num_sections == 0)
		return -EINVAL;

	if(nt_hdr->opt_hdr.opt_nt_hdr.section_alignment <
	   nt_hdr->opt_hdr.opt_nt_hdr.file_alignment)
	{
		ERROR("Alignment mismatch: secion: 0x%lx, file: 0x%lx",
		      nt_hdr->opt_hdr.opt_nt_hdr.section_alignment,
		      nt_hdr->opt_hdr.opt_nt_hdr.file_alignment);
		return -EINVAL;
	}
	return 0;
}

static int import(void *image, struct coffpe_import_dirent *dirent, char *dll)
{
	cu32 *lookup_tbl, *address_tbl;
	char *symname = 0;
	int i;
	int ret = 0;
	WRAP_FUNC *adr;

	lookup_tbl  = RVA2VA(image, dirent->import_lookup_tbl, cu32 *);
	address_tbl = RVA2VA(image, dirent->import_address_table, cu32 *);

	for (i = 0; lookup_tbl[i]; i++) {
		if (lookup_tbl[i] & 0x80000000) {
			ERROR("ordinal import not supported: %d",
			      (int) lookup_tbl[i]);
			return -1;
		}
		else {
			symname = RVA2VA(image,
					 ((lookup_tbl[i] & 0x7fffffff) + 2),
					 char*);
		}

		DBGTRACE("found function: %s", symname);
		adr = get_wrap_func(symname);
		if (adr == NULL) {
			ERROR("Unknown symbol: %s:%s", dll, symname);
			ret = -1;
		}
		DBGTRACE1("Importing rva %08x: %s : %s",
			  (int)(&address_tbl[i]) - (int)image, dll, symname); 
		address_tbl[i] = (cu32)adr;
	}
	return ret;
}

static int fixup_imports(void *image, struct nt_header *nt_hdr)
{
	int i;
	char *name;
	int ret = 0;
	struct coffpe_import_dirent *dirent;

	dirent = RVA2VA(image, nt_hdr->opt_hdr.import_tbl.rva,
			  struct coffpe_import_dirent *);

	for(i = 0; dirent[i].name_rva; i++) {
		name = RVA2VA(image, dirent[i].name_rva, char*);

		//printk("Imports from dll: %s\n", name);
		ret += import(image, &dirent[i], name);
	}
	return ret;
}

static int fixup_reloc(void *image, struct nt_header *nt_hdr)
{
	struct section_header *sect_hdr;
	int base = nt_hdr->opt_hdr.opt_nt_hdr.image_base;
	int size;
	struct coffpe_relocs *fixup_block;

	sect_hdr = get_section(nt_hdr, ".reloc");
	if (sect_hdr == NULL)
		return -EINVAL;
	fixup_block = (struct coffpe_relocs *)(image + sect_hdr->rawdata_addr);

	do
	{
		int i;
		uint16_t fixup, offset;

		size = (fixup_block->block_size - (2 * sizeof(uint32_t))) /
			sizeof(uint16_t);
		for (i = 0; i < size; i++)
		{
			uint32_t *loc;
			uint32_t addr;
			fixup = fixup_block->fixup[i];
			offset = fixup & 0xfff;
			loc = RVA2VA(image, fixup_block->page_rva + offset,
				   uint32_t *);

			switch ((fixup >> 12) & 0x0f)
			{
			case COFF_FIXUP_ABSOLUTE:
				break;
			case COFF_FIXUP_HIGHLOW:
				addr = RVA2VA(image, (*loc - base), uint32_t);
				*loc = addr;
//				DBGTRACE2("fixing up %08X with %08X", loc, *loc);
				break;
			default:
				ERROR("unknown fixup: %08X", fixup);
				return -ENOTSUPP;
				break;
			}
		}
		fixup_block = (struct coffpe_relocs *)
			((size_t)fixup_block + fixup_block->block_size);
	} while (fixup_block->block_size);

	return 0;
}

/* This one can be used to calc RVA's from virtual addressed so it's
 * nice to have as a global */
int image_offset;

int load_pe_image(void **entry, void *image, int size)
{
	struct nt_header *nt_hdr;
	unsigned int nt_hdr_offset;

	/* The PE header is found at the RVA specified at offset 3c. */
	if (size < 0x3c + 4)
		return -EINVAL;
	nt_hdr_offset =  *(unsigned int *)(image+0x3c);
//	DBGTRACE("PE Header at offset %08x", (int) header_offset);

	nt_hdr = (struct nt_header *)((char *)image + nt_hdr_offset);
	if (check_nt_hdr(nt_hdr))
		return -EINVAL;

	if (fixup_reloc(image, nt_hdr))
		return -EINVAL;
	if (fixup_imports(image, nt_hdr))
		return -EINVAL;
	flush_icache_range(image, size);

	image_offset = (int)image - nt_hdr->opt_hdr.opt_nt_hdr.image_base;
	*entry = RVA2VA(image, nt_hdr->opt_hdr.opt_std_hdr.entry_rva, void*);
	return 0;
}
