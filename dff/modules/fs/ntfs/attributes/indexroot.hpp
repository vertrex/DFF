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

#ifndef __INDEX_ROOT_HH__
#define __INDEX_ROOT_HH__

#include <vector>

#include "ntfs_common.hpp"
#include "mftattributecontent.hpp"
#include "indexentry.hpp"

PACK_START
typedef struct s_IndexList_s
{
  uint32_t              indexEntriesStart;
  uint32_t              indexEntriesEnd;
  uint32_t              endOfEntries;
  uint32_t              flags;   
}			IndexList_s;
PACK_END

PACK_START
typedef struct s_IndexRoot_s 
{
  uint32_t              indexType;
  uint32_t              sortType;
  uint32_t              indexRecordSize;
  uint8_t               indexRecordClusterSize;// == << * -1 ?
  uint8_t               unused[3];
}			IndexRoot_s;
PACK_END
 
class IndexRoot : public MFTAttributeContent
{
private:
  IndexRoot_s                   __indexRoot;
  IndexList_s                   __indexList;
  IndexEntries                  __indexEntries;
public:
		                IndexRoot(MFTAttribute* mftAttribute);
			        ~IndexRoot();
  const std::string             typeName(void) const;
  Attributes		        _attributes(void);
  static MFTAttributeContent*	create(MFTAttribute* mftAttribute);
  uint32_t                      indexType(void);
  uint32_t                      sortType(void);
  uint32_t                      indexRecordSize(void);
  uint8_t                       indexRecordClusterSize(void);
  bool                          isIndexSmall(void) const;
  bool                          isIndexLarge(void) const;

  uint32_t                      indexEntriesStart(void) const;
  uint32_t                      indexEntriesEnd(void) const;
  uint32_t                      endOfEntries(void) const;
  uint32_t                      flags(void) const;  
  std::vector<IndexEntry>       indexEntries(void);
};

#endif
