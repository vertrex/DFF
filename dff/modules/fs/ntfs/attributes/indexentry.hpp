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

#ifndef __INDEX_ENTRY_HH__
#define __INDEX_ENTRY_HH__

#include <vector>

#include "ntfs_common.hpp"

using namespace DFF;

PACK_START
typedef struct s_IndexEntry_s
{
  uint8_t       mftEntryId[6];
  uint16_t      sequence; 
  uint16_t      size;
  uint16_t      contentSize;
  uint8_t       flags;
  uint8_t       unknown[3];
  //int8_t*     content[contentSize]
  //uint64_t    vnc; //-> content[contentSize] - 8
}		IndexEntry_s;
PACK_END

class IndexEntry
{
private:
  IndexEntry_s                  __indexEntry;
  //uint64_t                    __vcn;
public:
                                IndexEntry(VFile*);
  uint64_t                      mftEntryId(void) const;
  uint16_t                      sequence(void) const;
  uint16_t                      size(void) const;
  uint16_t                      contentSize(void) const;
  uint32_t                      flags(void) const;
  bool                          isLast(void) const;
  bool                          haveChild(void) const;
  //uint64_t                    vcn(void) const;
};

class IndexEntries
{
private:
 std::vector<IndexEntry>        __entries;
public:
                                IndexEntries(void);
 size_t                         readEntries(VFile* vfile, uint32_t entriesStart, uint32_t entriesEnd);
 size_t                         count(void) const;
 std::vector<IndexEntry>        entries(void);
};

#endif
