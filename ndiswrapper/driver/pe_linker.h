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

#ifndef PE_LINKER_H
#define PE_LINKER_H

#include "ntoskernel.h"

#pragma pack(1)

#define COFF_MACHINE_I386	0x014c
#define COFF_MACHINE_IA64	0x0200
#define COFF_MACHINE_ARM	0x01c0
#define COFF_MACHINE_AMD64	0x8664

#define COFF_CHAR_RELOCS_STRIPPED 0x0001
#define COFF_CHAR_IMAGE 0x0002
#define COFF_CHAR_32BIT 0x0100
#define COFF_CHAR_DLL 0x2000

#define COFF_MAGIC_PE32 0x10b
#define COFF_MAGIC_PE32PLUS 0x20b

#define COFF_FIXUP_ABSOLUTE 0
#define COFF_FIXUP_HIGH16 1
#define COFF_FIXUP_LOW16 2
#define COFF_FIXUP_HIGHLOW 3

/* COFF File Header */
struct coff_file_header
{
	USHORT machine;
	USHORT num_sections;
	ULONG timedatestamp;
	ULONG symtab_ptr;
	ULONG symtab_entries;
	USHORT optionalhdr_size;
	USHORT characteristics;

};

/* The "header data directory" contains these */
struct mscoff_datadir_entry
{
	ULONG rva;
	ULONG size;
};

struct optional_std_header
{
	USHORT magic;
	UCHAR  linkver_major;
	UCHAR  linkver_minor;
	ULONG text_size;
	ULONG data_size;
	ULONG bss_size;
	ULONG entry_rva;
	ULONG code_base_rva;
	ULONG data_base_rva;
};

struct optional_nt_header
{
	ULONG image_base;
	ULONG section_alignment;
	ULONG file_alignment;
	USHORT osver_major;
	USHORT osver_minor;
	USHORT imagever_major;
	USHORT imagever_minor;
	USHORT subsysver_major;
	USHORT subsysver_minor;
	ULONG reserved;
	ULONG imagesize;
	ULONG headers_size;
	ULONG checksum;
	USHORT subsys;
	USHORT dll_char;
	ULONG stackreserve_size;
	ULONG stackcommit_size;
	ULONG heapreserve_size;
	ULONG heapcommit_size;
	ULONG loaderflags;
	ULONG datadir_size;
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
	UCHAR  name[8];
	ULONG virt_size;
	ULONG virt_addr;
	ULONG rawdata_size;
	ULONG rawdata_addr;
	ULONG relocs_addr;
 	ULONG linenum_addr;
	USHORT relocs_num;
	USHORT linenums_num;
	ULONG characteristics;
};

/* Used by exports section */
struct coffpe_exports
{
	ULONG export_flags;
	ULONG timedatestamp;
	USHORT version_major;
	USHORT version_minor;
	ULONG name_rva;      //Name of dll
	ULONG ordinal_base;
	ULONG addresses_size;
	ULONG names_size;
	ULONG addresses_rva;   // Location of symbols
	ULONG names_rva;     // Location of symbol names
	ULONG ordinals_rva;
};

struct coffpe_import_dirent
{
	ULONG import_lookup_tbl;
	ULONG timedatestamp;
	ULONG forwarder_chain;
	ULONG name_rva;
	ULONG import_address_table;
};

/* Reloc sections */
struct coffpe_relocs
{
	ULONG page_rva;
	ULONG block_size;
	USHORT fixup[1];
};

struct export_dir_table
{
	ULONG flags;
	ULONG timestamp;
	USHORT version_major;
	USHORT version_minir;
	ULONG name_rva;
	ULONG ordinal_base;
	ULONG num_addr_table_entries;
	ULONG num_name_addr;
	ULONG export_table_rva;
	ULONG name_addr_rva;
	ULONG ordinal_table_rva;
};

struct exports
{
	char *dll;
	char *name;
	ULONG_PTR addr;
};

#pragma pack()

int load_pe_images(struct pe_image[], int n);

#endif /* PE_LINKER_H */
