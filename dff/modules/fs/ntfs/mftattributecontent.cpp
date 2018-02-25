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
#include "filemapping.hpp"
#include "vfile.hpp"

#include "mftattributecontent.hpp"
#include "mftattribute.hpp"
#include "mftentrynode.hpp"
#include "ntfs.hpp"
#include "ntfsopt.hpp"
#include "bootsector.hpp"

MFTAttributeContent::MFTAttributeContent(MFTAttribute* mftAttribute) : Node("MFTAC", (uint64_t)mftAttribute->contentSize(), NULL,  mftAttribute->ntfs(), false), __mftAttribute(mftAttribute), __state(0)
{
  this->__mftAttribute->mftEntryNode()->updateState();
}

MFTAttributeContent::~MFTAttributeContent()
{
}

MFTAttribute* MFTAttributeContent::mftAttribute(void)
{
  return (this->__mftAttribute);
}

void		MFTAttributeContent::fileMapping(FileMapping* fm)
{
  this->__state++;
  if (this->__mftAttribute->isResident())
     fm->push(0, this->__mftAttribute->contentSize(), this->__mftAttribute->mftEntryNode(), this->__mftAttribute->contentOffset());
  else
  {
    uint32_t	clusterSize = this->__mftAttribute->ntfs()->bootSectorNode()->clusterSize();
    uint64_t	totalSize = this->__mftAttribute->VNCStart() * clusterSize;
    Node*	fsNode = this->__mftAttribute->ntfs()->fsNode();
    std::vector<RunList> runList = this->runList();
    std::vector<RunList>::iterator run = runList.begin();

    for (; run != runList.end(); ++run)
    {
      if ((*run).offset == 0) //Sparse
        fm->push(totalSize, (*run).length * clusterSize, NULL, 0);
      else 
        fm->push(totalSize, (*run).length * clusterSize, fsNode, (*run).offset * clusterSize);
      totalSize += (*run).length * clusterSize;  
    }
  }
}

std::vector<RunList>    MFTAttributeContent::runList(void)
{
  uint64_t	         runPreviousOffset = 0;
  std::vector<RunList>   runLists;

  VFile* runList = this->__mftAttribute->mftEntryNode()->open();  
  if (runList->seek(this->__mftAttribute->offset() + this->__mftAttribute->runListOffset()) != this->__mftAttribute->offset() + this->__mftAttribute->runListOffset())
  {
    delete runList;
    return (runLists);
  }
  
  while (true)
  { 
    int64_t  runOffset = 0;
    uint64_t runLength = 0;
    RunListInfo	runListInfo;
    runListInfo.byte = 0;

    if (runList->read(&(runListInfo.byte), sizeof(uint8_t)) != sizeof(uint8_t))
      break;
    if (runListInfo.info.offsetSize > 8) 
      break;
    if (runList->read(&runLength, runListInfo.info.lengthSize) != runListInfo.info.lengthSize)
      break;
    if (runListInfo.info.offsetSize)
      if (runList->read(&runOffset, runListInfo.info.offsetSize) != runListInfo.info.offsetSize)
        break;

    if ((runListInfo.info.offsetSize > 0) && (int8_t)(runOffset >> (8 * (runListInfo.info.offsetSize - 1))) < 0) 
    {
      int64_t toffset = -1;

      memcpy(&toffset, &runOffset, runListInfo.info.offsetSize);
      runOffset = toffset;
    }
    if (runLength == 0)
      break;
    runPreviousOffset += runOffset;

    RunList run;
    if (runOffset == 0)
      run.offset = 0;
    else 
      run.offset = runPreviousOffset;
    run.length = runLength;
    runLists.push_back(run);
  }
  delete runList;
  return (runLists);
}

/**
 *  Return MFTAttribute attributes
 */ 
Attributes	MFTAttributeContent::_attributes(void)
{
  Attributes	attrs;

  if (this->__mftAttribute == NULL)
    return attrs;

  bool advancedAttributes = this->__mftAttribute->ntfs()->opt()->advancedAttributes();

  MAP_ATTR("type id", this->__mftAttribute->typeId())
  MAP_ATTR("length", this->__mftAttribute->length())
  if (this->__mftAttribute->nameSize())
      MAP_ATTR("name", this->attributeName())
  MAP_ATTR("id", this->__mftAttribute->id())
  if (advancedAttributes)
    MAP_ATTR("flags", this->__mftAttribute->flags()) //XXX

  if (this->__mftAttribute->isResident())
  {
    MAP_ATTR("Content size", this->__mftAttribute->contentSize());
    MAP_ATTR("Content offset", this->__mftAttribute->contentOffset());
  }
  else
  {
    if (advancedAttributes)
    {
      MAP_ATTR("VNC start", this->__mftAttribute->VNCStart())
      MAP_ATTR("VNC end", this->__mftAttribute->VNCEnd())
      MAP_ATTR("Run list offset", this->__mftAttribute->runListOffset())
      MAP_ATTR("Compression unit size", this->__mftAttribute->compressionBlockSize())
    }
    MAP_ATTR("Content allocated size", this->__mftAttribute->contentAllocatedSize())
    MAP_ATTR("Content actual size", this->__mftAttribute->contentActualSize())
    MAP_ATTR("Content initialized size", this->__mftAttribute->contentInitializedSize())
  }
  MAP_ATTR("Compressed", this->__mftAttribute->isCompressed())

  return attrs;
}

std::string	MFTAttributeContent::attributeName(void) const
{
  if (this->__mftAttribute->nameSize())
    return (this->__mftAttribute->name());
  return ("");
}

const std::string	MFTAttributeContent::typeName(void) const
{
  std::ostringstream  idStream;

  if (this->__mftAttribute)
    idStream << "Unknown MFT attribute (" << this->__mftAttribute->typeId() << ")";

  return (idStream.str());
}

uint64_t	MFTAttributeContent::_attributesState(void)
{
  return (this->__state);
}

uint64_t	MFTAttributeContent::fileMappingState(void)
{
  return (this->__state);
}

void MFTAttributeContent::updateState(void)
{
  this->__state++;
}
