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

#ifdef TEST_LOADER

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <linux/types.h>
#include <asm/errno.h>

#include "pe_linker.h"

#else

#include <linux/types.h>
#include <asm/errno.h>

#include "pe_linker.h"

#endif

static struct exports exports[40];
static int num_exports;

#define RVA2VA(image, rva, type) (type)rva_to_va(image, rva)

#ifdef TEST_LOADER
#define WRAP_EXPORT_FUNC void
static WRAP_EXPORT_FUNC get_export(char *name)
{
	return name;
}
#else
extern struct wrap_export ntoskernel_exports[], ndis_exports[],
	misc_funcs_exports[], hal_exports[], usb_exports[];

static WRAP_EXPORT_FUNC get_export(char *name)
{
	int i;

	for (i = 0 ; ntoskernel_exports[i].name != NULL; i++)
		if (strcmp(ntoskernel_exports[i].name, name) == 0)
			return ntoskernel_exports[i].func;

	for (i = 0 ; ndis_exports[i].name != NULL; i++)
		if (strcmp(ndis_exports[i].name, name) == 0)
			return ndis_exports[i].func;

	for (i = 0 ; misc_funcs_exports[i].name != NULL; i++)
		if (strcmp(misc_funcs_exports[i].name, name) == 0)
			return misc_funcs_exports[i].func;

	for (i = 0 ; hal_exports[i].name != NULL; i++)
		if (strcmp(hal_exports[i].name, name) == 0)
			return hal_exports[i].func;

#ifdef CONFIG_USB
	for (i = 0 ; usb_exports[i].name != NULL; i++)
		if (strcmp(usb_exports[i].name, name) == 0)
			return usb_exports[i].func;
#endif

	for (i = 0; i < num_exports; i++)
		if (strcmp(exports[i].name, name) == 0)
			return (void *)exports[i].addr;

	return NULL;
}
#endif // TEST_LOADER

static void *get_dll_init(char *name)
{
	int i;
	for (i = 0; i < num_exports; i++)
		if ((strcmp(exports[i].dll, name) == 0) &&
		    (strcmp(exports[i].name, "DllInitialize") == 0))
			return (void *)exports[i].addr;
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

	for (i = 0; i < sections; i++, sect_hdr++) {
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
	if (memcmp(pe_sign, nt_hdr->magic, sizeof(pe_sign)) != 0)
		return -EINVAL;

	/* Make sure Image is PE32 */
	if (nt_hdr->opt_hdr.opt_std_hdr.magic != COFF_MAGIC_PE32)
		return -EINVAL;
	
	if (nt_hdr->file_hdr.machine != COFF_MACHINE_I386) {
		ERROR("%s", "Driver is not for i386");
		return -EINVAL;
	}

	/* Make sure this is a relocatable 32 bit dll */
	char_must = COFF_CHAR_IMAGE | COFF_CHAR_32BIT;
	if ((nt_hdr->file_hdr.characteristics & char_must) != char_must)
		return -EINVAL;

	/* Must be a relocatable dll */
	if ((nt_hdr->file_hdr.characteristics & COFF_CHAR_RELOCS_STRIPPED))
		return -EINVAL;

	/* Make sure we have at least one section */
	if (nt_hdr->file_hdr.num_sections == 0)
		return -EINVAL;

	if (nt_hdr->opt_hdr.opt_nt_hdr.section_alignment <
	   nt_hdr->opt_hdr.opt_nt_hdr.file_alignment) {
		ERROR("Alignment mismatch: secion: 0x%lx, file: 0x%lx",
		      nt_hdr->opt_hdr.opt_nt_hdr.section_alignment,
		      nt_hdr->opt_hdr.opt_nt_hdr.file_alignment);
		return -EINVAL;
	}

	if ((nt_hdr->file_hdr.characteristics & COFF_CHAR_DLL))
		return COFF_CHAR_DLL;
	if ((nt_hdr->file_hdr.characteristics & COFF_CHAR_IMAGE))
		return COFF_CHAR_IMAGE;
	return -EINVAL;
}

static int import(void *image, struct coffpe_import_dirent *dirent, char *dll)
{
	cu32 *lookup_tbl, *address_tbl;
	char *symname = 0;
	int i;
	int ret = 0;
	void *adr;

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

		adr = get_export(symname);
		if (adr != NULL)
			DBGTRACE1("found symbol: %s:%s, rva = %08X",
				  dll, symname, (unsigned int)address_tbl[i]);
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

static int read_exports(void *image, struct nt_header *nt_hdr, char *dll)
{
	struct section_header *export_section;
	struct export_dir_table *export_dir_table;
	cu32 *export_addr_table;
	int i;
	unsigned int *name_table;

	export_section = get_section(nt_hdr, ".edata");
	if (export_section)
		DBGTRACE1("%s", "found exports section");
	else
		return 0;

	export_dir_table = (struct export_dir_table *)
		(image + export_section->rawdata_addr);
	name_table = (unsigned int *)(image + export_dir_table->name_addr_rva);
	export_addr_table = (cu32 *)
		(image + export_dir_table->export_table_rva);

	for (i = 0; i < export_dir_table->num_name_addr; i++) {
		if (nt_hdr->opt_hdr.export_tbl.rva <= *export_addr_table ||
		    *export_addr_table >= (nt_hdr->opt_hdr.export_tbl.rva +
					   nt_hdr->opt_hdr.export_tbl.size))
			DBGTRACE1("%s", "forwarder rva");

		DBGTRACE1("export symbol: %s, at %08X",
		     (char *)(image + *name_table),
		     (unsigned int)(image + *export_addr_table));
		     
		exports[num_exports].dll = dll;
		exports[num_exports].name = (char *)(image + *name_table);
		exports[num_exports].addr = (cu32)(image + *export_addr_table);

		num_exports++;
		name_table++;
		export_addr_table++;
	}
	return 0;
}

static int fixup_imports(void *image, struct nt_header *nt_hdr)
{
	int i;
	char *name;
	int ret = 0;
	struct coffpe_import_dirent *dirent;

	dirent = RVA2VA(image, nt_hdr->opt_hdr.import_tbl.rva,
			  struct coffpe_import_dirent *);

	for (i = 0; dirent[i].name_rva; i++) {
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

	do {
		int i;
		uint16_t fixup, offset;

		size = (fixup_block->block_size - (2 * sizeof(uint32_t))) /
			sizeof(uint16_t);
		for (i = 0; i < size; i++) {
			uint32_t *loc;
			uint32_t addr;
			fixup = fixup_block->fixup[i];
			offset = fixup & 0xfff;
			loc = RVA2VA(image, fixup_block->page_rva + offset,
				   uint32_t *);

			switch ((fixup >> 12) & 0x0f) {
			case COFF_FIXUP_ABSOLUTE:
				break;
			case COFF_FIXUP_HIGHLOW:
				addr = RVA2VA(image, (*loc - base), uint32_t);
				*loc = addr;
				break;
			default:
				ERROR("unknown fixup: %08X", fixup);
				return -EOPNOTSUPP;
				break;
			}
		}
		fixup_block = (struct coffpe_relocs *)
			((size_t)fixup_block + fixup_block->block_size);
	} while (fixup_block->block_size);

	return 0;
}

int load_pe_images(struct pe_image *pe_image, int n)
{
	struct nt_header *nt_hdr;
	unsigned int nt_hdr_offset;
	int i = 0;
	void *image;
	int size;
	struct optional_header *opt_hdr;

	for (i = 0; i < n; i++) {
		image = pe_image[i].image;
		size = pe_image[i].size;

		/* The PE header is found at the RVA specified at offset 3c. */
		if (size < 0x3c + 4)
			return -EINVAL;
		nt_hdr_offset =  *(unsigned int *)(image+0x3c);
		nt_hdr = (struct nt_header *)((char *)image + nt_hdr_offset);
		pe_image[i].type = check_nt_hdr(nt_hdr);
		if (pe_image[i].type <= 0)
			return -EINVAL;

		if (read_exports(image, nt_hdr, pe_image[i].name))
			return -EINVAL;
	}

	for (i = 0; i < n; i++) {
		image = pe_image[i].image;
		size = pe_image[i].size;

		nt_hdr_offset =  *(unsigned int *)(image+0x3c);
		nt_hdr = (struct nt_header *)((char *)image + nt_hdr_offset);
		opt_hdr = &nt_hdr->opt_hdr;

		if (fixup_reloc(image, nt_hdr))
			return -EINVAL;
		if (fixup_imports(image, nt_hdr))
			return -EINVAL;
		flush_icache_range(image, pe_image[i].size);

		pe_image[i].entry = RVA2VA(image,
					   opt_hdr->opt_std_hdr.entry_rva,
					   void *);
		DBGTRACE1("entry is at %p, rva at %08X", pe_image[i].entry, 
		     (unsigned int)opt_hdr->opt_std_hdr.entry_rva);
	} for (i = 0; i < n; i++) {
		image = pe_image[i].image;
		size = pe_image[i].size;

		nt_hdr_offset =  *(unsigned int *)(image+0x3c);
		nt_hdr = (struct nt_header *)((char *)image + nt_hdr_offset);
		opt_hdr = &nt_hdr->opt_hdr;

		if (pe_image[i].type == COFF_CHAR_DLL) {
			struct ustring ustring;
			char *buf = "0\0t0m0p00";
			int (*dll_entry)(struct ustring *ustring) STDCALL;

			memset(&ustring, 0, sizeof(ustring));
			ustring.buf = buf;
			dll_entry = (void *)get_dll_init(pe_image[i].name);

			DBGTRACE1("calling dll_init at %p", dll_entry);
			if (!dll_entry || dll_entry(&ustring))
				ERROR("DLL initialize failed for %s",
				      pe_image[i].name);
		}
		else if (pe_image[i].type == COFF_CHAR_IMAGE)
			;
		else
			ERROR("illegal image type: %d", pe_image[i].type);
	}
	return 0;
}
