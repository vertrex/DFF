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

#include "indexentry.hpp"

IndexEntry::IndexEntry(VFile *vfile)
{
  if (vfile->read((void*)&this->__indexEntry, sizeof(IndexEntry_s)) != sizeof(IndexEntry_s))
    throw std::string("Can't read Index entry");
  uint64_t offset = vfile->tell() + this->size() - sizeof(IndexEntry_s);
  if (vfile->seek(offset) != offset)
    throw std::string("Can't seek to offset in IndexEntry");
}

uint64_t        IndexEntry::mftEntryId(void) const
{
  uint64_t mftEntryId = 0;

  mftEntryId = *((uint32_t*)&this->__indexEntry.mftEntryId);
  *((uint32_t*)&mftEntryId + 1) = *((uint16_t*)&this->__indexEntry.mftEntryId + 2);

  return (mftEntryId);
}

uint16_t        IndexEntry::sequence(void) const
{
  return (this->__indexEntry.sequence);
}

uint16_t        IndexEntry::size(void) const
{
  return (this->__indexEntry.size);
}

uint16_t        IndexEntry::contentSize(void) const
{
  return (this->__indexEntry.contentSize);
}

uint32_t        IndexEntry::flags(void) const
{
  return (this->__indexEntry.flags);
}

//uint64_t        IndexEntry::vcn(void) const
//{
  //return (this->__vcn);
//}

bool            IndexEntry::haveChild(void) const
{
  return ((this->__indexEntry.flags & 0x01) == 0x01);
}

bool            IndexEntry::isLast(void) const
{
  return ((this->__indexEntry.flags & 0x02) == 0x02);
}

/*
 *  IndexEntries : read and store entry
 */

IndexEntries::IndexEntries(void)
{
}

std::vector<IndexEntry> IndexEntries::entries(void) 
{
  return (this->__entries);
}

/*
 *  VFile should be positioned at entries start
 */
size_t IndexEntries::readEntries(VFile* vfile, uint32_t entriesStart, uint32_t entriesEnd)
{
  uint64_t lastOffset = vfile->tell() + entriesStart;
  uint64_t currentOffset = lastOffset;
  if (vfile->seek(lastOffset) != lastOffset)
    throw std::string("IndexEntries::readEntries() can't seek to entry start");

  while ((currentOffset != entriesStart) && ((currentOffset + sizeof(IndexEntry_s)) < vfile->node()->size()))
  {
    IndexEntry entry(vfile);
    this->__entries.push_back(entry);

    if (entry.isLast())
      break;
    currentOffset = vfile->tell();
    if (currentOffset == lastOffset)
      break;
    lastOffset = currentOffset;
  }

  return (this->__entries.size());
}

size_t IndexEntries::count(void) const
{
  return (this->__entries.size());
}
