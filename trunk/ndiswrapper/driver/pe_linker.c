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

#define RVA2VA(image, rva, type) (type)(ULONG_PTR)((void *)image + rva)

#ifdef TEST_LOADER
#define WRAP_EXPORT_FUNC char *
static WRAP_EXPORT_FUNC get_export(char *name)
{
	return name;
}
#else
extern struct wrap_export ntoskernel_exports[], ndis_exports[],
	misc_funcs_exports[], hal_exports[];
#ifdef CONFIG_USB
extern struct wrap_export usb_exports[];
#endif

static char *get_export(char *name)
{
	int i;

	for (i = 0 ; ntoskernel_exports[i].name != NULL; i++)
		if (strcmp(ntoskernel_exports[i].name, name) == 0)
			return (char *)ntoskernel_exports[i].func;

	for (i = 0 ; ndis_exports[i].name != NULL; i++)
		if (strcmp(ndis_exports[i].name, name) == 0)
			return (char *)ndis_exports[i].func;

	for (i = 0 ; misc_funcs_exports[i].name != NULL; i++)
		if (strcmp(misc_funcs_exports[i].name, name) == 0)
			return (char *)misc_funcs_exports[i].func;

	for (i = 0 ; hal_exports[i].name != NULL; i++)
		if (strcmp(hal_exports[i].name, name) == 0)
			return (char *)hal_exports[i].func;

#ifdef CONFIG_USB
	for (i = 0 ; usb_exports[i].name != NULL; i++)
		if (strcmp(usb_exports[i].name, name) == 0)
			return (char *)usb_exports[i].func;
#endif

	for (i = 0; i < num_exports; i++)
		if (strcmp(exports[i].name, name) == 0)
			return (char *)exports[i].addr;

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


static const char image_directory_name[15][15] = {
	"EXPORT",
	"IMPORT",
	"RESOURCE",
	"EXCEPTION",
	"SECURITY",
	"BASERELOC",
	"DEBUG",
	"COPYRIGHT",
	"GLOBALPTR",
	"TLS",
	"LOAD_CONFIG",
	"BOUND_IMPORT",
	"IAT",
	"DELAY_IMPORT",
	"COM_DESCRIPTOR" };
/*
 * Find and validate the coff header
 *
 */
static int check_nt_hdr(IMAGE_NT_HEADERS *nt_hdr)
{
	int i;
	WORD attr;

	/* Validate the "PE\0\0" signature */
	if (nt_hdr->Signature != IMAGE_NT_SIGNATURE) {
		ERROR("Bad signature %08x", nt_hdr->Signature);
		return -EINVAL;
	}

	/* Make sure Image is PE32 or PE32+ */
	if(nt_hdr->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
		ERROR("bad magic: %04X", nt_hdr->OptionalHeader.Magic);
		return -EINVAL;
	}

	/* Validate the image for the current architecture. */
	if (nt_hdr->FileHeader.Machine !=
#ifdef CONFIG_64BIT
	    IMAGE_FILE_MACHINE_AMD64
#else
	    IMAGE_FILE_MACHINE_I386
#endif
		) {
		ERROR("Driver is not for current architecture "
		      " (PE signature is %04X)", nt_hdr->FileHeader.Machine);
		return -EINVAL;
	}

	/* Must have attributes */
#ifdef CONFIG_64BIT
	attr = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
#else
	attr = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE;
#endif
	if((nt_hdr->FileHeader.Characteristics & attr) != attr)
		return -EINVAL;

	/* Must be relocatable */
	attr = IMAGE_FILE_RELOCS_STRIPPED;
	if ((nt_hdr->FileHeader.Characteristics & attr))
		return -EINVAL;

	/* Make sure we have at least one section */
	if(nt_hdr->FileHeader.NumberOfSections == 0)
		return -EINVAL;

	if(nt_hdr->OptionalHeader.SectionAlignment <
	   nt_hdr->OptionalHeader.FileAlignment) {
		ERROR("Alignment mismatch: secion: 0x%x, file: 0x%x",
		      nt_hdr->OptionalHeader.SectionAlignment,
		      nt_hdr->OptionalHeader.FileAlignment);
		return -EINVAL;
	}

	DBGTRACE1("Number of DataDictionary entries %d",
		  nt_hdr->OptionalHeader.NumberOfRvaAndSizes);
	for(i=0; i< nt_hdr->OptionalHeader.NumberOfRvaAndSizes; i++) {
		DBGTRACE3("DataDirectory %s RVA:%X Size:%d",
			  (i<=IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)?
			  image_directory_name[i] : "Unknown",
			  nt_hdr->OptionalHeader.DataDirectory[i].VirtualAddress,
			  nt_hdr->OptionalHeader.DataDirectory[i].Size);
	}

	if((nt_hdr->FileHeader.Characteristics & IMAGE_FILE_DLL))
		return IMAGE_FILE_DLL;
	if((nt_hdr->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE))
		return IMAGE_FILE_EXECUTABLE_IMAGE;
	return -EINVAL;
}

static int import(void *image, IMAGE_IMPORT_DESCRIPTOR *dirent, char *dll)
{
	ULONG_PTR *lookup_tbl, *address_tbl;
	char *symname = 0;
	int i;
	int ret = 0;
	void *adr;

	lookup_tbl  = RVA2VA(image, dirent->u.OriginalFirstThunk, ULONG_PTR *);
	address_tbl = RVA2VA(image, dirent->FirstThunk, ULONG_PTR *);

	for (i = 0; lookup_tbl[i]; i++) {
		if (IMAGE_SNAP_BY_ORDINAL(lookup_tbl[i])) {
			ERROR("ordinal import not supported: %Lu",
			      (uint64_t)lookup_tbl[i]);
			return -1;
		}
		else {
			symname = RVA2VA(image,
					 ((lookup_tbl[i] &
					   ~IMAGE_ORDINAL_FLAG) + 2), char *);
		}

		adr = get_export(symname);
		if (adr != NULL)
			DBGTRACE1("found symbol: %s:%s, rva = %Lu",
				  dll, symname, (uint64_t)address_tbl[i]);
		if (adr == NULL) {
			ERROR("Unknown symbol: %s:%s", dll, symname);
			ret = -1;
		}
		DBGTRACE1("Importing rva: %p, %p: %s : %s",
			  (void *)(address_tbl[i]), adr, dll, symname);
		address_tbl[i] = (ULONG_PTR)adr;
	}
	return ret;
}

static int read_exports(struct pe_image *pe)
{
	IMAGE_EXPORT_DIRECTORY *export_dir_table;
	uint32_t *export_addr_table;
	int i;
	uint32_t *name_table;
	PIMAGE_OPTIONAL_HEADER opt_hdr;
	IMAGE_DATA_DIRECTORY *export_data_dir;

	opt_hdr = &pe->nt_hdr->OptionalHeader;
	export_data_dir =
		&opt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	if (export_data_dir->Size == 0) {
		DBGTRACE1("No exports");
		return 0;
	}

	export_dir_table =
		RVA2VA(pe->image, export_data_dir->VirtualAddress,
		       IMAGE_EXPORT_DIRECTORY *);

	name_table = (unsigned int *)(pe->image +
				      export_dir_table->AddressOfNames);
	export_addr_table = (uint32_t *)
		(pe->image + export_dir_table->AddressOfFunctions);

	for (i = 0; i < export_dir_table->NumberOfNames; i++) {

		if (export_data_dir->VirtualAddress <= *export_addr_table ||
		    *export_addr_table >= (export_data_dir->VirtualAddress +
					   export_data_dir->Size))
			DBGTRACE1("%s", "forwarder rva");

		DBGTRACE1("export symbol: %s, at %p",
			  (char *)(pe->image + *name_table),
			  pe->image + *export_addr_table);

		exports[num_exports].dll = pe->name;
		exports[num_exports].name = (pe->image + *name_table);
		exports[num_exports].addr = (pe->image + *export_addr_table);

		num_exports++;
		name_table++;
		export_addr_table++;
	}
	return 0;
}

static int fixup_imports(void *image, IMAGE_NT_HEADERS *nt_hdr)
{
	int i;
	char *name;
	int ret = 0;
	IMAGE_IMPORT_DESCRIPTOR *dirent;
	IMAGE_DATA_DIRECTORY *import_data_dir;
	PIMAGE_OPTIONAL_HEADER opt_hdr;

	opt_hdr = &nt_hdr->OptionalHeader;
	import_data_dir =
		&opt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	dirent = RVA2VA(image, import_data_dir->VirtualAddress,
			IMAGE_IMPORT_DESCRIPTOR *);

	for (i = 0; dirent[i].Name; i++) {
		name = RVA2VA(image, dirent[i].Name, char*);

		DBGTRACE1("Imports from dll: %s\n", name);
		ret += import(image, &dirent[i], name);
	}
	return ret;
}

static int fixup_reloc(void *image, IMAGE_NT_HEADERS *nt_hdr)
{
        ULONG_PTR base;
	ULONG_PTR size;
	IMAGE_BASE_RELOCATION *fixup_block;
	IMAGE_DATA_DIRECTORY *base_reloc_data_dir;
	PIMAGE_OPTIONAL_HEADER opt_hdr;

	opt_hdr = &nt_hdr->OptionalHeader;
	base = opt_hdr->ImageBase;
	base_reloc_data_dir = 
		&opt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (base_reloc_data_dir->Size == 0) {
		ERROR("%s", "No relocation found");
		return -EINVAL;
	}

	fixup_block = RVA2VA(image, base_reloc_data_dir->VirtualAddress,
			     IMAGE_BASE_RELOCATION *);
	DBGTRACE3("fixup_block=%p, image=%p",
		  fixup_block, image);
	DBGTRACE3("fixup_block info: %x %d", 
		  fixup_block->VirtualAddress, fixup_block->SizeOfBlock);

	do {
		int i;
		WORD fixup, offset;

		size = (fixup_block->SizeOfBlock -
			sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		DBGTRACE3("found %Lu relocations in this block",
			  (uint64_t)size);

		for (i = 0; i < size; i++) {
			fixup = fixup_block->TypeOffset[i];
			offset = fixup & 0xfff;
			switch ((fixup >> 12) & 0x0f) {
			case IMAGE_REL_BASED_ABSOLUTE:
				break;

			case IMAGE_REL_BASED_HIGHLOW: {
				uint32_t addr;
				uint32_t *loc =
					RVA2VA(image,
					       fixup_block->VirtualAddress +
					       offset, uint32_t *);
				addr = RVA2VA(image, (*loc - base), uint32_t);
				DBGTRACE3("relocation: *%p (Val:%X)= %X",
					  loc, *loc, addr);
				*loc = addr;
			}
				break;

			case IMAGE_REL_BASED_DIR64: {
				uint64_t addr;
				uint64_t *loc =
					RVA2VA(image,
					       fixup_block->VirtualAddress +
					       offset, uint64_t *);
				addr = RVA2VA(image, (*loc - base), uint64_t);
				DBGTRACE3("relocation: *%p (Val:%llX)= %llx",
					  loc, *loc, addr);
				*loc = addr;
			}
				break;

			default:
				ERROR("unknown fixup: %08X",
				      (fixup >> 12) & 0x0f);
				return -EOPNOTSUPP;
				break;
			}
		}
		DBGTRACE1("Finished relocating block");

		fixup_block = (IMAGE_BASE_RELOCATION *)
			((void *)fixup_block + fixup_block->SizeOfBlock);
	} while (fixup_block->SizeOfBlock);
	DBGTRACE1("done relocating all");	

	return 0;
}

/* Expand the image in memroy if necessary. The image on disk does not
 * necessarily maps the image of the driver in memory, so we have to
 * re-write it in order to fullfill the sections alignements. The
 * advantage to do that is that rva_to_va becomes a simple
 * addition. */
static int fix_pe_image(struct pe_image *pe)
{
	void *image;
	IMAGE_SECTION_HEADER *sect_hdr;
	int i, sections;
	int image_size;

	if (pe->size == pe->opt_hdr->SizeOfImage) {
		/* Nothing to do */
		return 0;
	}

	DBGTRACE1("image must be re-written in memory");

	image_size = pe->opt_hdr->SizeOfImage;
#ifdef CONFIG_64BIT
	image = __vmalloc(image_size, GFP_KERNEL | __GFP_HIGHMEM,
			  PAGE_KERNEL_EXEC);
#else
	image = vmalloc(image_size);
#endif
	if (image == NULL) {
		ERROR("Failed to allocate enough space for new image:"
		      " %d bytes", image_size);
		return -ENOMEM;
	}

	/* Copy all the headers, ie everything before the first section. */

	sections = pe->nt_hdr->FileHeader.NumberOfSections;
	sect_hdr = IMAGE_FIRST_SECTION(pe->nt_hdr);

	DBGTRACE3("Copying headers: %u bytes", sect_hdr->PointerToRawData);

	memcpy(image, pe->image, sect_hdr->PointerToRawData);

	/* Copy all the sections */
	for (i = 0; i < sections; i++) {
		DBGTRACE3("Copy section %s from %x to %x",
			  sect_hdr->Name, sect_hdr->PointerToRawData,
			  sect_hdr->VirtualAddress);
		if (sect_hdr->VirtualAddress+sect_hdr->SizeOfRawData >
		    image_size) {
			ERROR("Invalid section %s in driver", sect_hdr->Name);
			vfree(image);
			return -EINVAL;
		}

		memcpy(image+sect_hdr->VirtualAddress,
		       pe->image + sect_hdr->PointerToRawData,
		       sect_hdr->SizeOfRawData);
		sect_hdr++;
	}

	vfree(pe->image);
	pe->image = image;
	pe->size = image_size;

	/* Update our internal pointers */
	pe->nt_hdr =
		(IMAGE_NT_HEADERS *)(pe->image +
				     ((IMAGE_DOS_HEADER *)pe->image)->e_lfanew);
	pe->opt_hdr = &pe->nt_hdr->OptionalHeader;

	DBGTRACE3("set nt headers: nt_hdr=%p, opt_hdr=%p, image=%p",
		  pe->nt_hdr, pe->opt_hdr, pe->image);

	return 0;
}

int load_pe_images(struct pe_image *pe_image, int n)
{
	int i = 0;
	struct pe_image *pe;

#ifdef DEBUG
	/* Sanity checkings */
#define CHECK_SZ(a,b) { if (sizeof(a) != b) {			 \
			ERROR("%s is bad, got %zd, expected %d",	\
			      #a , sizeof(a), (b)); return -EINVAL; } }

	CHECK_SZ(IMAGE_SECTION_HEADER, IMAGE_SIZEOF_SECTION_HEADER);
	CHECK_SZ(IMAGE_FILE_HEADER, IMAGE_SIZEOF_FILE_HEADER);
	CHECK_SZ(IMAGE_OPTIONAL_HEADER, IMAGE_SIZEOF_NT_OPTIONAL_HEADER);
	CHECK_SZ(IMAGE_NT_HEADERS, 4 + IMAGE_SIZEOF_FILE_HEADER +
		 IMAGE_SIZEOF_NT_OPTIONAL_HEADER);
	CHECK_SZ(IMAGE_DOS_HEADER, 0x40);
	CHECK_SZ(IMAGE_EXPORT_DIRECTORY, 40);
	CHECK_SZ(IMAGE_BASE_RELOCATION, 8);
	CHECK_SZ(IMAGE_IMPORT_DESCRIPTOR, 20);
#undef CHECK_SZ
#endif

	for (i = 0; i < n; i++) {
		IMAGE_DOS_HEADER *dos_hdr;
		pe = &pe_image[i];
		dos_hdr = pe->image;

		if (pe->size < sizeof(IMAGE_DOS_HEADER)) {
			DBGTRACE1("image too small: %d", pe->size);
 			return -EINVAL;
		}

		pe->nt_hdr =
			(IMAGE_NT_HEADERS *)(pe->image + dos_hdr->e_lfanew);
		pe->opt_hdr = &pe->nt_hdr->OptionalHeader;

		pe->type = check_nt_hdr(pe->nt_hdr);
		if (pe_image[i].type <= 0) {
			DBGTRACE1("pe_image[i].type <=0");
			return -EINVAL;
		}

		if (fix_pe_image(pe)) {
			DBGTRACE1("bad image");
			return -EINVAL;
		}

		if (read_exports(pe)) {
			DBGTRACE1("read_exports");
			return -EINVAL;
		}
	}

	for (i = 0; i < n; i++) {
	        pe = &pe_image[i];

		if (fixup_reloc(pe->image, pe->nt_hdr)) {
			DBGTRACE1("fixup_reloc");
			return -EINVAL;
		}
		if (fixup_imports(pe->image, pe->nt_hdr)) {
			DBGTRACE1("fixup_imports");
			return -EINVAL;
		}
		flush_icache_range(pe->image, pe->size);

		pe->entry =
			RVA2VA(pe->image,
			       pe->nt_hdr->OptionalHeader.AddressOfEntryPoint,
			       void *);
		DBGTRACE1("entry is at %p, rva at %08X", pe_image[i].entry, 
			  pe->opt_hdr->AddressOfEntryPoint);
	} for (i = 0; i < n; i++) {
	        pe = &pe_image[i];

		if (pe->type == IMAGE_FILE_DLL) {
			struct unicode_string ustring;
			char *buf = "0/0t0m0p00";
			int (*dll_entry)(struct unicode_string *ustring)
				STDCALL;

			memset(&ustring, 0, sizeof(ustring));
			ustring.buf = (wchar_t *)buf;
			dll_entry = (void *)get_dll_init(pe_image[i].name);

			DBGTRACE1("calling dll_init at %p", dll_entry);
			if (!dll_entry || dll_entry(&ustring))
				ERROR("DLL initialize failed for %s",
				      pe_image[i].name);
		}
		else if (pe->type == IMAGE_FILE_EXECUTABLE_IMAGE)
			;
		else
			ERROR("illegal image type: %d", pe->type);
	}
	return 0;
}
