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

#ifndef __BITMAP_HH__ 
#define __BITMAP_HH__

#include <vector>

#include "ntfs_common.hpp"
#include "mftattributecontent.hpp"

/**
 *  Store start & end offset in cluster
 */
class Range
{
public:
  Range(uint64_t start, uint64_t end);
  uint64_t      start(void) const;
  uint64_t      end(void) const;
private:
  uint64_t      __start;
  uint64_t      __end;
};

class Bitmap : public MFTAttributeContent
{
public:
  Bitmap(MFTAttribute* mftAttribute);
  ~Bitmap();
  //bool                          isAllocated(uint64_t offset) const;
  std::vector<Range>            unallocatedRanges(void);

  Attributes                    _attributes(void);
  static MFTAttributeContent*	create(MFTAttribute* mftAttribute);
  const std::string             typeName(void) const;
};

#endif
