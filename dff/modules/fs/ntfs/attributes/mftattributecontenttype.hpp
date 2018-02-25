/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *  
 * See http: *www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 * 
 * Author(s):
 *  Solal Jacob <sja@digital-forensic.org>
 */

#ifndef __MFT_ATTRIBUTE_CONTENT_TYPE_HH__ 
#define __MFT_ATTRIBUTE_CONTENT_TYPE_HH__

#include "mftattribute.hpp"
#include "mftattributecontent.hpp"
#include "standardinformation.hpp"
#include "filename.hpp"
#include "attributelist.hpp"
#include "volume.hpp"
#include "objectid.hpp"
#include "indexroot.hpp"
#include "indexallocation.hpp"
#include "data.hpp"
#include "bitmap.hpp"
#include "reparsepoint.hpp"

#define $STANDARD_INFORMATION   16	
#define $ATTRIBUTE_LIST         32
#define $FILE_NAME		48
#define $OBJECT_ID              64
//#define $SECURY_DESCRIPTOR    80 //0x50
#define $VOLUME_NAME            96 
#define $VOLUME_INFORMATION     112 
#define $DATA			128
#define $INDEX_ROOT             144
#define $INDEX_ALLOCATION       160
#define $BITMAP                 176
#define $SYMOBLIC_LINK          192
#define $REPARSE_POINT          192
//#define $EA_INFORMATION       208 // 0xd0
//#define $EA                   224 //0xe0
//#define $PROPERTY_SET         240 // 0xf0 
//#define $LOGGED_UTILITY_STREAM 256 //0x100

typedef MFTAttributeContent* (*ContentObject)(MFTAttribute*);

struct ContentType
{
  uint32_t	Id;
  ContentObject	newObject;
};

ContentType const ContentTypes[] =
{
  { $STANDARD_INFORMATION, &StandardInformation::create },
  { $FILE_NAME, &FileName::create },
  { $OBJECT_ID, &ObjectId::create },
  { $ATTRIBUTE_LIST, &AttributeList::create },
  { $VOLUME_NAME, &VolumeName::create },
  { $VOLUME_INFORMATION, &VolumeInformation::create },
  { $DATA, &Data::create },
  { $INDEX_ROOT, &IndexRoot::create },
  { $INDEX_ALLOCATION, &IndexAllocation::create },
  { $BITMAP, &Bitmap::create },
  { $REPARSE_POINT, &ReparsePoint::create },
  { 0, NULL },
};
 
#endif
