
/*
 *  Copyright (C) 2004 Pontus Fuchs, Giridhar Pemmasani
 *
 *  This program is free software; you can redistribute it and/or 
modify
 *  it under the terms of the GNU General Public License as published 
by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 */

#ifndef WINNT_TYPES_H
#define WINNT_TYPES_H

/*--------------------------------------------------------------------------*/
#ifdef CONFIG_X86_64
typedef uint64_t ULONG_PTR;
#define STDCALL
#define _FASTCALL
#define FASTCALL_DECL_1(decl1) decl1
#define FASTCALL_DECL_2(decl1,decl2) decl1, decl2
#define FASTCALL_DECL_3(decl1,decl2,decl3) decl1, decl2, decl3
#define FASTCALL_ARGS_1(arg1) arg1
#define FASTCALL_ARGS_2(arg1,arg2) arg1, arg2
#define FASTCALL_ARGS_3(arg1,arg2,arg3) arg1, arg2, arg3
#else
typedef uint32_t ULONG_PTR;
#define STDCALL __attribute__((__stdcall__, regparm(0)))
#define _FASTCALL __attribute__((__stdcall__)) __attribute__((regparm (3)))
#define FASTCALL_DECL_1(decl1) int _dummy1_, int _dummy2_, decl1
#define FASTCALL_DECL_2(decl1,decl2) int _dummy1_, decl2, decl1
#define FASTCALL_DECL_3(decl1,decl2,decl3) int _dummy1_, decl2, decl1, decl3
#define FASTCALL_ARGS_1(arg1) 0, 0, arg1
#define FASTCALL_ARGS_2(arg1,arg2) 0, arg2, arg1
#define FASTCALL_ARGS_3(arg1,arg2,arg3) 0, arg2, arg1, arg3
#endif

#define NOREGPARM __attribute__((regparm(0)))
#define packed __attribute__((packed))

/*--------------------------------------------------------------------------*/

typedef uint8_t BOOLEAN;
typedef uint8_t  BYTE;
typedef uint8_t  *LPBYTE;
typedef int16_t  SHORT;
typedef uint16_t USHORT;
typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef uint32_t *PDWORD;
typedef int32_t  LONG;
typedef uint32_t ULONG;
typedef uint64_t ULONGLONG;

typedef size_t SIZE_T;
typedef SHORT wchar_t;
typedef short CSHORT;
typedef int32_t INT;
typedef long long LARGE_INTEGER;
typedef uint32_t UINT;

typedef wchar_t WCHAR;
typedef WCHAR *PWSTR;
typedef WCHAR *LPWSTR;
typedef char CHAR, *PCHAR;
typedef unsigned char UCHAR, *PUCHAR;
typedef const char *PCSTR, *LPCSTR;
typedef const char *PCSZ;
typedef const WCHAR *PCWSTR, *LPCWSTR;

typedef LONG NTSTATUS;

typedef struct _STRING {
  USHORT Length;
  USHORT MaximumLength;
  PCHAR Buffer;
} STRING, *PSTRING;

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef STRING ANSI_STRING;
typedef PSTRING PANSI_STRING;

#endif /* WINNT_TYPES_H */
