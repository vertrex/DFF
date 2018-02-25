/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2013 ArxSys
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
 *  Solal J. <sja@digital-forensic.org>
 */


#ifndef __EXPORT_HPP__
#define __EXPORT_HPP__

#ifndef WIN32
#define IMPORT	extern
#define EXPORT
#define PACK_START _Pragma("pack(push, 1)")
#define PACK_END _Pragma("pack(pop)")
#else
#define EXPORT	 __declspec( dllexport )
#define IMPORT 	__declspec(dllimport)
#define PACK_START __pragma(pack(push, 1))
#define PACK_END __pragma(pack(pop))
#include <String>
#include "windows.h"
#endif

#endif
