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

#ifndef __ATTRIBUTE_LIST_HH__
#define __ATTRIBUTE_LIST_HH__

#include  <vector>

#include "ntfs_common.hpp"
#include "mftattribute.hpp"
#include "mftattributecontent.hpp"


PACK_START
typedef struct s_AttributeList_s
{
  uint32_t      typeId;
  uint16_t      size;
  uint8_t       nameSize;
  uint8_t       nameOffset;
  uint64_t      VCNStart;
  uint8_t       mftEntryId[6];
  uint8_t       sequence[2];
  uint16_t      attributeId;
}		AttributeList_s;
PACK_END

class AttributeListItems
{
private:
  std::string       __name;
  AttributeList_s   __attributeList;
public:
                    AttributeListItems(VFile*);
                    AttributeListItems(const AttributeListItems& copy);
                    ~AttributeListItems();
  uint32_t          typeId(void) const;
  uint16_t          size(void) const;
  const std::string name(void) const;
  uint64_t          VCNStart(void) const;
  uint64_t          mftEntryId(void) const;
  uint16_t          sequence(void) const;
  uint16_t          attributeId(void) const;
};

class AttributeList : public MFTAttributeContent
{
private:
  std::vector<AttributeListItems> __attributes;
public:
                                AttributeList(MFTAttribute* mftAttribute);
		                ~AttributeList();
  Attributes                    _attributes(void);
  MFTAttributes                 mftAttributes(void);
  const std::string             typeName(void) const;
  static MFTAttributeContent*	create(MFTAttribute* mftAttribute);
};

#endif
