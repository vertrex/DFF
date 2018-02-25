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
#include "vfile.hpp"

#include "indexroot.hpp"
#include "mftattributecontent.hpp"
#include "mftattribute.hpp"

/* XXX implement flags()
#define PUSH_FLAGS(x, y)\
  if ((this->__fileName.flags & x) == x)\
    flagsList.push_back(NEW_VARIANT(std::string(y)));
*/ 

IndexRoot::IndexRoot(MFTAttribute* mftAttribute) : MFTAttributeContent(mftAttribute)
{
  VFile* vfile = this->open();

  if (vfile->read((void*)&this->__indexRoot, sizeof(IndexRoot_s)) != sizeof(IndexRoot_s))
  {
    delete vfile;
    throw std::string("$INDEX_ROOT can't read IndexRoot.");
  }
  if (vfile->read((void*)&this->__indexList, sizeof(IndexList_s)) != sizeof(IndexList_s))
  {
    delete vfile;
    throw std::string("$INDEX_ROOT can't read IndexList.");
  }
  try
  {
    vfile->seek(sizeof(IndexRoot_s));
    this->__indexEntries.readEntries(vfile, this->indexEntriesStart(), this->indexEntriesEnd());
  }
  catch(std::string const& error)
  {
    std::cout << "$INDEX_ROOT error in read entries " << error << std::endl;
  }
  catch(vfsError e)
  {
    std::cout << "$INDEX_ROOT error in read entries " << e.error << std::endl;
  }
  delete vfile;
}

IndexRoot::~IndexRoot()
{
}

MFTAttributeContent*	IndexRoot::create(MFTAttribute*	mftAttribute)
{
  return (new IndexRoot(mftAttribute));
}

uint32_t        IndexRoot::indexType(void)
{
  return (this->__indexRoot.indexType);
}

uint32_t        IndexRoot::sortType(void)
{
  return (this->__indexRoot.sortType);
}

uint32_t        IndexRoot::indexRecordSize(void)
{
  return (this->__indexRoot.indexRecordSize);
}

uint8_t         IndexRoot::indexRecordClusterSize(void)
{
  return (this->__indexRoot.indexRecordClusterSize);
}

Attributes	IndexRoot::_attributes(void)
{
  Attributes	attrs;

  MAP_ATTR("Attributes", MFTAttributeContent::_attributes())
  MAP_ATTR("Index type", this->indexType())
  MAP_ATTR("Sort type", this->sortType())
  MAP_ATTR("Index record size", this->indexRecordSize())
  MAP_ATTR("Index record cluster size", this->indexRecordClusterSize())

  MAP_ATTR("Index entries start", this->indexEntriesStart())
  MAP_ATTR("Index entries end", this->indexEntriesEnd())
  MAP_ATTR("End of entries", this->endOfEntries())
  MAP_ATTR("flags", this->flags())
  return (attrs);
}

const std::string  IndexRoot::typeName(void) const
{
  return (std::string("$NDEX_ROOT"));
}

uint32_t        IndexRoot::indexEntriesStart(void) const
{
  return (this->__indexList.indexEntriesStart);
}

uint32_t        IndexRoot::indexEntriesEnd(void) const
{
  return (this->__indexList.indexEntriesEnd);
}

uint32_t        IndexRoot::endOfEntries(void) const
{
  return (this->__indexList.endOfEntries);
}

uint32_t        IndexRoot::flags(void) const
{
  return (this->__indexList.flags);
}

bool            IndexRoot::isIndexSmall(void) const
{
  return (this->__indexList.flags == 0x00);
}

bool            IndexRoot::isIndexLarge(void) const
{
  return (this->__indexList.flags == 0x01);
}

std::vector<IndexEntry>     IndexRoot::indexEntries(void)
{
  std::vector<IndexEntry> entries;
  std::vector<IndexEntry> currentEntries = this->__indexEntries.entries();
  entries.insert(entries.end(), currentEntries.begin(), currentEntries.end());   
  return (entries);
}
