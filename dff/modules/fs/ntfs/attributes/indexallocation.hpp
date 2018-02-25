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

#ifndef __INDEX_ALLOCATION_HH__
#define __INDEX_ALLOCATION_HH__

#include <vector>

#include "ntfs_common.hpp"
#include "indexroot.hpp"
#include "mftattributecontent.hpp"

PACK_START
typedef struct s_IndexRecord_s
{
  uint32_t                      signature;
  uint16_t                      fixupArrayOffset;
  uint16_t                      fixupArrayCount; 
  uint64_t                      sequence;
  uint64_t                      vcn;
}				IndexRecord_s;
PACK_END

class IndexRecord
{
private:
  IndexRecord_s                 __indexRecord;
  IndexList_s                   __indexList;
  IndexEntries                  __indexEntries;
public:
                                IndexRecord(VFile*);
  uint32_t                      signature(void) const;
  uint16_t                      fixupArrayOffset(void) const;
  uint16_t                      fixupArrayCount(void) const;
  uint64_t                      sequence(void) const;
  uint64_t                      vcn(void) const;

  uint32_t                      indexEntriesStart(void) const;
  uint32_t                      indexEntriesEnd(void) const;
  uint32_t                      endOfEntries(void) const;
  uint32_t                      flags(void) const;
 
  void                          readEntries(VFile* vfile);
  void                          readIndexList(VFile* vfile);
  IndexEntries                  indexEntries(void);
};

class IndexAllocation : public MFTAttributeContent
{
private:
  std::vector<IndexRecord>      __indexRecords;
  uint64_t                      __state;
public:
		                IndexAllocation(MFTAttribute* mftAttribute);
			        ~IndexAllocation();
  const std::string             typeName(void) const;
  Attributes		        _attributes(void);
  static MFTAttributeContent*	create(MFTAttribute* mftAttribute);
  void		                fileMapping(FileMapping *fm);
  void                          updateState(void);
  uint64_t                      fileMappingState(void);
  std::vector<IndexEntry>       indexEntries(void);
};

#endif
