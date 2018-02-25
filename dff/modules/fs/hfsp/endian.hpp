/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2014 ArxSys
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *  
 * See http://www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 * 
 * Author(s):
 *  Frederic Baguelin <fba@digital-forensic.org>
 */

#ifndef __ENDIAN_HPP__
#define __ENDIAN_HPP__

#ifdef __GNUC__
//#if (__GNUC__ < 4 || (__GNUC__ == 4 && __GNUC_MINOR__ < 8))
//static inline unsigned short __builtin_bswap16(unsigned short a) {return (a<<8)|(a>>8);}
//#endif
	#define bswap16 __builtin_bswap16
	#define bswap32 __builtin_bswap32
	#define bswap64 __builtin_bswap64
#elif _MSC_VER
	#include <intrin.h>
	#define bswap16 _byteswap_ushort
	#define bswap32 _byteswap_ulong
	#define bswap64 _byteswap_uint64
#endif

#endif
