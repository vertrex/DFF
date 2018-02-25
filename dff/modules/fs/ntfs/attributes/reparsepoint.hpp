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

#ifndef __REPARSE_POINT_HH__
#define __REPARSE_POINT_HH__

#include "ntfs_common.hpp"
#include "mftattributecontent.hpp"

PACK_START
typedef struct s_ReparsePoint_s 
{
  uint16_t              type;
  uint16_t              flags;
  uint16_t              dataSize;
  uint16_t              reserved;

  uint16_t              targetOffset;
  uint16_t              targetSize;
  uint16_t              printOffset;
  uint16_t              printSize;
//uint32_t              flags for symlink see ntfs3g reparse.c /layout.h

//guid uint64_t guid1;
//guid uint64_t guid2;
}			ReparsePoint_s;
PACK_END

class ReparsePoint : public MFTAttributeContent
{
private:
  std::string           __target;
  std::string           __print;
  ReparsePoint_s        __reparsePoint;
public:
		        ReparsePoint(MFTAttribute* mftAttribute);
			~ReparsePoint();
  std::list<Variant_p>	flags(void) const;
  uint32_t              dataSize(void) const;
  uint16_t              targetOffset(void) const;
  uint16_t              targetSize(void) const;
  uint16_t              printOffset(void) const;
  uint16_t              printSize(void) const;
  const std::string	target(void) const;
  const std::string	print(void) const;
  const std::string     typeName(void) const;
  Attributes		_attributes(void);
  static MFTAttributeContent*	create(MFTAttribute* mftAttribute);
};

#endif
