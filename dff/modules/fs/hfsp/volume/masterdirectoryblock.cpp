/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2014 ArxSys
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *  
 * See http://www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 * 
 * Author(s):
 *  Frederic Baguelin <fba@digital-forensic.org>
 */


#include "volume.hpp"


MasterDirectoryBlock::MasterDirectoryBlock() : __mdb()
{
}


MasterDirectoryBlock::~MasterDirectoryBlock()
{
}


uint16_t	MasterDirectoryBlock::type()
{
  return HfsVolume;
}


void		MasterDirectoryBlock::process(Node* origin, uint64_t offset, fso* fsobj) throw (std::string)
{
  VFile*	vf;

  memset(&this->__mdb, 0, sizeof(master_dblock));
  if (origin == NULL)
    throw std::string("Provided node does not exist");
  try
    {
      vf = origin->open();
      vf->seek(offset);
      if (vf->read(&this->__mdb, sizeof(master_dblock)) != sizeof(master_dblock))
	{
	  vf->close();
	  delete vf;
	  throw std::string("Error while reading HFS Volume Header");
	}
    }
  catch (...)
    {
    }
  this->sanitize();
}


void		MasterDirectoryBlock::sanitize() throw (std::string)
{
  std::stringstream	sstr;

  if ((this->blockSize() % 512) != 0)
    sstr << "Block size (" << this->blockSize() <<  ") is not a muliple of 512\n";
  // In some odd cases it could happen that there are more free allocation blocks than
  // total blocks. 
  // Test case : create a dump with mkfs.hfs -h, mount it and copy more data than
  // possible.
  // if (this->totalBlocks() < this->freeBlocks())
  //   sstr << "More free blocks (" << this->freeBlocks() << ") than total blocks (" << this->totalBlocks() << ")\n";
  if (!sstr.str().empty())
    throw (sstr.str());
}


Attributes	MasterDirectoryBlock::_attributes()
{
  Attributes	vmap;

  vmap["volume name"] = new Variant(this->volumeName());
  vmap["created"] = new Variant(this->createDate());
  vmap["modified"] = new Variant(this->modifyDate());
  vmap["backup"] = new Variant(this->backupDate());
  vmap["Total number of files"] = new Variant(this->fileCount());
  vmap["Total number of folders"] = new Variant(this->folderCount());
  vmap["number of files in root directory"] = new Variant(this->rootdirFiles());
  vmap["number of folders in root directory"] = new Variant(this->rootdirFolders());
  vmap["bitmap block"] = new Variant(this->volumeBitmapBlock());
  vmap["first allocation block"] = new Variant(this->firstAllocationBlock());
  vmap["backup sequence number"] = new Variant(this->backupSeqNumber());
  vmap["allocation block size"] = new Variant(this->blockSize());
  vmap["total number of allocation blocks"] = new Variant(this->totalBlocks());
  vmap["total number of free allocation blocks"] = new Variant(this->freeBlocks());
  vmap["total mounted"] = new Variant(this->writeCount());
  vmap["clump size"] = new Variant(this->clumpSize());
  vmap["embed signature"] = new Variant(this->embedSignature());
  return vmap;
}


uint32_t	MasterDirectoryBlock::totalBlocks()
{
  return (uint32_t)bswap16(this->__mdb.totalBlocks);
}


uint32_t	MasterDirectoryBlock::blockSize()
{
  return bswap32(this->__mdb.blockSize);
}


ExtentsList	MasterDirectoryBlock::overflowExtents()
{
  uint8_t	i;
  Extent*	extent;
  ExtentsList	extents;
  
  extent = NULL;
  for (i = 0; i != 3; ++i)
    {
      extent = new Extent(this->__mdb.overflowExtents[i], this->blockSize());
      extents.push_back(extent);
    }
  return extents;
}


ExtentsList	MasterDirectoryBlock::catalogExtents()
{
  uint8_t	i;
  Extent*	extent;
  ExtentsList	extents;
  
  extent = NULL;
  for (i = 0; i != 3; ++i)
    {
      extent = new Extent(this->__mdb.catalogExtents[i], this->blockSize());
      extents.push_back(extent);
    }
  return extents;
}


uint16_t	MasterDirectoryBlock::signature()
{
  return bswap16(this->__mdb.signature);
}


DateTime*	MasterDirectoryBlock::createDate()
{
  uint32_t	cdate;

  cdate = bswap32(this->__mdb.createDate);
  return new HFSDateTime(cdate);
}


DateTime*	MasterDirectoryBlock::modifyDate()
{
  uint32_t	mdate;

  mdate = bswap32(this->__mdb.modifyDate);
  return new HFSDateTime(mdate);
}
  

uint16_t	MasterDirectoryBlock::attributes()
{
  return bswap16(this->__mdb.attributes);
}


uint16_t	MasterDirectoryBlock::rootdirFiles()
{
  return bswap16(this->__mdb.rootdirFiles);
}


uint16_t	MasterDirectoryBlock::volumeBitmapBlock()
{
  return bswap16(this->__mdb.volumeBitmapBlock);
}


uint16_t	MasterDirectoryBlock::nextAllocationBlock()
{
  return bswap16(this->__mdb.nextAllocationBlock);
}


uint32_t	MasterDirectoryBlock::clumpSize()
{
  return bswap32(this->__mdb.clumpSize);
}


uint16_t	MasterDirectoryBlock::firstAllocationBlock()
{
  return bswap16(this->__mdb.firstAllocationBlock);
}


uint32_t	MasterDirectoryBlock::nextCatalogNodeId()
{
    return bswap32(this->__mdb.nextCatalogNodeId);
}

uint16_t	MasterDirectoryBlock::freeBlocks()
{
  return bswap16(this->__mdb.freeBlocks);
}


std::string	MasterDirectoryBlock::volumeName()
{
  return std::string(this->__mdb.volumeName, 28);
}


DateTime*	MasterDirectoryBlock::backupDate()
{
  uint32_t	bdate;

  bdate = bswap32(this->__mdb.backupDate);
  return new HFSDateTime(bdate);
}


uint16_t	MasterDirectoryBlock::backupSeqNumber()
{
  return bswap16(this->__mdb.backupSeqNumber);
}


uint32_t	MasterDirectoryBlock::writeCount()
{
  return bswap32(this->__mdb.writeCount);
}


uint32_t	MasterDirectoryBlock::OverflowClumpSize()
{
  return bswap32(this->__mdb.OverflowClumpSize);
}


uint32_t	MasterDirectoryBlock::CatalogClumpSize()
{
  return bswap32(this->__mdb.CatalogClumpSize);
}


uint16_t	MasterDirectoryBlock::rootdirFolders()
{
  return bswap16(this->__mdb.rootdirFolders);
}


uint32_t	MasterDirectoryBlock::fileCount()
{
  return bswap32(this->__mdb.fileCount);
}


uint32_t	MasterDirectoryBlock::folderCount()
{
  return bswap32(this->__mdb.folderCount);
}


uint64_t	MasterDirectoryBlock::overflowSize()
{
  return (uint64_t)bswap32(this->__mdb.overflowSize);
}


uint64_t	MasterDirectoryBlock::catalogSize()
{
  return (uint64_t)bswap32(this->__mdb.catalogSize);
}


uint16_t	MasterDirectoryBlock::embedSignature()
{
  return bswap16(this->__mdb.embedSignature);
}


bool		MasterDirectoryBlock::isWrapper()
{
  return (bswap16(this->__mdb.embedSignature) == HfspVolume || bswap16(this->__mdb.embedSignature) == HfsxVolume);
}


uint16_t	MasterDirectoryBlock::embedStartBlock()
{
  return bswap16(this->__mdb.embedExtent.startBlock);
}


uint16_t	MasterDirectoryBlock::embedBlockCount()
{
  return bswap16(this->__mdb.embedExtent.blockCount);
}
