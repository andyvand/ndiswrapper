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

#ifndef PE_LOADER_H
#define PE_LOADER_H

#pragma pack(1)

#define COFF_MACHINE_I386 0x14c
#define COFF_MACHINE_ARM  0x1c0

#define COFF_CHAR_RELOCS_STRIPPED 0x0001
#define COFF_CHAR_IMAGE 0x0002
#define COFF_CHAR_32BIT 0x0100
#define COFF_CHAR_DLL 0x2000

#define COFF_MAGIC_PE32 0x10b

#define COFF_FIXUP_ABSOLUTE 0
#define COFF_FIXUP_HIGH16 1
#define COFF_FIXUP_LOW16 2
#define COFF_FIXUP_HIGHLOW 3

typedef signed short cs16;
typedef unsigned short cu16;
typedef signed long cs32;
typedef unsigned long cu32;
typedef signed char cs8;
typedef unsigned char cu8;

/* COFF File Header */
struct coff_file_header
{
	cu16 machine;
	cu16 num_sections;
	cu32 timedatestamp;
	cu32 symtab_ptr;
	cu32 symtab_entries;
	cu16 optionalhdr_size;
	cu16 characteristics;

};

/* The "header data directory" contains these */
struct mscoff_datadir_entry
{
	cu32 rva;
	cu32 size;
};

struct optional_std_header
{
	cu16 magic;
	cu8  linkver_major;
	cu8  linkver_minor;
	cu32 text_size;
	cu32 data_size;
	cu32 bss_size;
	cu32 entry_rva;
	cu32 code_base_rva;
	cu32 data_base_rva;
};

struct optional_nt_header
{
	cu32 image_base;
	cu32 section_alignment;
	cu32 file_alignment;
	cu16 osver_major;
	cu16 osver_minor;
	cu16 imagever_major;
	cu16 imagever_minor;
	cu16 subsysver_major;
	cu16 subsysver_minor;
	cu32 reserved;
	cu32 imagesize;
	cu32 headers_size;
	cu32 checksum;
	cu16 subsys;
	cu16 dll_char;
	cu32 stackreserve_size;
	cu32 stackcommit_size;
	cu32 heapreserve_size;
	cu32 heapcommit_size;
	cu32 loaderflags;
	cu32 datadir_size;
};

/* optional header required for images */
struct optional_header
{
	struct optional_std_header opt_std_hdr;
	struct optional_nt_header opt_nt_hdr;

	/* header data dir */
	struct mscoff_datadir_entry export_tbl;
	struct mscoff_datadir_entry import_tbl;
	struct mscoff_datadir_entry resource_tbl;
	struct mscoff_datadir_entry exception_tbl;
	struct mscoff_datadir_entry certificate_tbl;
	struct mscoff_datadir_entry basereloc_tbl;
	struct mscoff_datadir_entry other_tbl[10];
};

struct nt_header
{
	char magic[4];
	struct coff_file_header file_hdr;
	struct optional_header opt_hdr;
};

/* section header (right after ht_header) */
struct section_header
{
	cu8  name[8];
	cu32 virt_size;
	cu32 virt_addr;
	cu32 rawdata_size;
	cu32 rawdata_addr;
	cu32 relocs_addr;
 	cu32 linenum_addr;
	cu16 relocs_num;
	cu16 linenums_num;
	cu32 characteristics;
};

/* Used by exports section */
struct coffpe_exports
{
	cu32 export_flags;
	cu32 timedatestamp;
	cu16 version_major;
	cu16 version_minor;
	cu32 name_rva;      //Name of dll
	cu32 ordinal_base;
	cu32 addresses_size;
	cu32 names_size;
	cu32 addresses_rva;   // Location of symbols
	cu32 names_rva;     // Location of symbol names
	cu32 ordinals_rva;
};

struct coffpe_import_dirent
{
	cu32 import_lookup_tbl;
	cu32 timedatestamp;
	cu32 forwarder_chain;
	cu32 name_rva;
	cu32 import_address_table;
};

/* Reloc sections */
struct coffpe_relocs
{
	cu32 page_rva;
	cu32 block_size;
	cu16 fixup[1];
};

struct export_dir_table
{
	cu32 flags;
	cu32 timestamp;
	cu16 version_major;
	cu16 version_minir;
	cu32 name_rva;
	cu32 ordinal_base;
	cu32 num_addr_table_entries;
	cu32 num_name_addr;
	cu32 export_table_rva;
	cu32 name_addr_rva;
	cu32 ordinal_table_rva;
};

struct exports
{
	char *dll;
	char *name;
	cu32 addr;
};

struct pe_image
{
	char *name;
	void *entry;
	void *image;
	int size;
	int type;
};

#pragma pack()

int load_pe_images(struct pe_image[], int n);
int load_pe_image(void **entry, void *image, int size);

#endif /* PE_LOADER_H */
