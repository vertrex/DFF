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
#include "filemapping.hpp"

#include "indexallocation.hpp"
#include "mftattributecontent.hpp"
#include "mftattribute.hpp"
#include "mftentrynode.hpp"
#include "mftnode.hpp"
#include "ntfs.hpp"
#include "bootsector.hpp"

#define PUSH_FLAGS(x, y)\
  if ((this->__fileName.flags & x) == x)\
    flagsList.push_back(NEW_VARIANT(std::string(y)));

IndexAllocation::IndexAllocation(MFTAttribute* mftAttribute) : MFTAttributeContent(mftAttribute), __state(0)
{
  uint64_t indexSize = mftAttribute->ntfs()->bootSectorNode()->indexRecordSize();
  VFile* vfile = this->open();
  try 
  {
    /* 
     *  Read struct at start of block and get fixup array info
     */
    for (uint64_t currentOffset = 0; currentOffset < this->size(); currentOffset += indexSize)
    {
      if (vfile->seek(currentOffset) != currentOffset)
        break;
      IndexRecord indexRecord(vfile); //XXX large alloc ? 
      if (indexRecord.signature() != *(uint32_t*)&"INDX")
        break;
      this->__indexRecords.push_back(indexRecord);
    }

    /*
     *  Now index can be read with fixup replaced
     */
    this->mftAttribute()->mftEntryNode()->updateState();
    this->updateState();
    for (uint64_t indexRecordId = 0; indexRecordId < this->__indexRecords.size(); ++indexRecordId)
    {
       uint64_t entriesOffset = (indexRecordId * indexSize) + sizeof(IndexRecord_s);
       if (vfile->seek(entriesOffset) != entriesOffset)
         break;

       this->__indexRecords[indexRecordId].readEntries(vfile);
    }
  }
  catch(std::string const& error)
  {
    std::cout << "$INDEX_ALLOCATION error : " << error << std::endl;
  }
  catch(vfsError const& error)
  {
    std::cout << "$INDEX_ALLOCATION vfs error : " << error.error << std::endl;
  }
  delete vfile;
}

MFTAttributeContent*	IndexAllocation::create(MFTAttribute*	mftAttribute)
{
  return (new IndexAllocation(mftAttribute));
}

IndexAllocation::~IndexAllocation()
{
}

Attributes	IndexAllocation::_attributes(void)
{
  Attributes	attrs;

  MAP_ATTR("Attributes", MFTAttributeContent::_attributes())
  MAP_ATTR("Number of records", this->__indexRecords.size())

  //for reacord in this
  //MAP_ATTR("signature", this->signature())
  //MAP_ATTR("fixup array offset", this->fixupArrayOffset())
  //MAP_ATTR("fixup array count", this->fixupArrayCount())
  //MAP_ATTR("sequence", this->sequence())
  //MAP_ATTR("VCN", this->vcn())

  return (attrs);
}

const std::string       IndexAllocation::typeName(void) const
{
  return (std::string("$NDEX_ALLOCATION"));
}

std::vector<IndexEntry>     IndexAllocation::indexEntries(void)
{
  std::vector<IndexEntry> entries;
  std::vector<IndexRecord>::iterator record = this->__indexRecords.begin();

  for (; record != this->__indexRecords.end(); ++record)
  {
    std::vector<IndexEntry> currentEntries = (*record).indexEntries().entries();
    entries.insert(entries.end(), currentEntries.begin(), currentEntries.end());
  }  

  return (entries);
}

void            IndexAllocation::updateState(void)
{
  this->__state++;
}

uint64_t	IndexAllocation::fileMappingState(void)
{
  return (this->__state);
}

void		IndexAllocation::fileMapping(FileMapping* fm)
{
  MFTAttribute* mftAttribute = this->mftAttribute();
  uint16_t sectorSize = this->mftAttribute()->mftEntryNode()->ntfs()->bootSectorNode()->bytesPerSector();
  uint32_t clusterSize = mftAttribute->ntfs()->bootSectorNode()->clusterSize();
  uint32_t sectorPerCluster = mftAttribute->ntfs()->bootSectorNode()->sectorsPerCluster();
  uint64_t totalSize = mftAttribute->VNCStart() * clusterSize;
  uint64_t indexSize = mftAttribute->ntfs()->bootSectorNode()->indexRecordSize();
  Node*	fsNode = mftAttribute->ntfs()->fsNode();
  std::vector<RunList> runList = this->runList();
  if (runList.size() == 0)
    return ;

  std::vector<RunList>::iterator run = runList.begin();
  uint64_t startOffset = (*run).offset * clusterSize; 
  uint64_t currentFixup = 0; //totalSector
  uint32_t currentIndexRecord = 0;
  for (; run != runList.end(); ++run)
  {
    if ((*run).offset == 0) //Sparse ? 
      fm->push(totalSize, (*run).length * clusterSize, NULL, 0);
    else
    {
      if (this->__indexRecords.size() == 0)
        fm->push(totalSize, (*run).length * clusterSize, fsNode, (*run).offset * clusterSize);
      else 
      {
        uint64_t sectorOffset = 0;//(*run).offset + clusterSize;
        for (uint64_t sector = 0; sector < (*run).length * sectorPerCluster; sector++)
        {
          uint64_t nextIndexRecordId = (totalSize+ sectorOffset) / indexSize; 
          fm->push(totalSize + sectorOffset, sectorSize - sizeof(uint16_t), fsNode, ((*run).offset * clusterSize) + sectorOffset);
          sectorOffset += sectorSize - sizeof(uint16_t);

          if (nextIndexRecordId > currentIndexRecord)
          {
            startOffset = ((*run).offset * clusterSize) +  ((nextIndexRecordId * indexSize)  - totalSize);
            currentIndexRecord++;
            currentFixup = 0;
          }
          if (currentIndexRecord >= this->__indexRecords.size())
          {
            fm->push(totalSize + sectorOffset, sizeof(uint16_t), fsNode, ((*run).offset * clusterSize) + sectorOffset);
          }
          else
          { 
            uint64_t currentFixupOffset = this->__indexRecords[currentIndexRecord].fixupArrayOffset() + sizeof(uint16_t) + (sizeof(uint16_t) * currentFixup);
            fm->push(totalSize + sectorOffset,
                   sizeof(uint16_t),
                   fsNode,
                   currentFixupOffset + startOffset); 
          }
          currentFixup++;
          sectorOffset += sizeof(uint16_t);
        }
      }  
    }
    totalSize += (*run).length * clusterSize; 
  }
}

/* 
 *   IndexRecord 
 */
IndexRecord::IndexRecord(VFile *vfile)
{
   if (vfile->read((void*)&this->__indexRecord, sizeof(IndexRecord_s)) != sizeof(IndexRecord_s))
     throw std::string("Can't read Index record");
   if (vfile->read((void*)&this->__indexList, sizeof(IndexList_s)) != sizeof(IndexList_s))
     throw std::string("Can't read Index record index list");
}

void            IndexRecord::readEntries(VFile* vfile)
{
  this->__indexEntries.readEntries(vfile, this->indexEntriesStart(), this->indexEntriesEnd());
}

uint32_t        IndexRecord::signature(void) const
{
  return (this->__indexRecord.signature);
}

uint16_t        IndexRecord::fixupArrayOffset(void) const
{
  return (this->__indexRecord.fixupArrayOffset);
}

uint16_t        IndexRecord::fixupArrayCount(void) const
{
  return (this->__indexRecord.fixupArrayCount);
}

uint64_t        IndexRecord::sequence(void) const
{
  return (this->__indexRecord.sequence);
}

uint64_t        IndexRecord::vcn(void) const
{
  return (this->__indexRecord.vcn);
}

/*
 *  IndexList_s 
 */

uint32_t        IndexRecord::indexEntriesStart(void) const
{
  return (this->__indexList.indexEntriesStart);
}

uint32_t        IndexRecord::indexEntriesEnd(void) const
{
  return (this->__indexList.indexEntriesEnd);
}

uint32_t        IndexRecord::endOfEntries(void) const
{
  return (this->__indexList.endOfEntries);
}

uint32_t        IndexRecord::flags(void) const
{
  return (this->__indexList.flags);
}

IndexEntries    IndexRecord::indexEntries(void)
{
  return (this->__indexEntries);
}

