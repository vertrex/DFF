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


VolumeHeader::VolumeHeader() : __vheader()
{
}


VolumeHeader::~VolumeHeader()
{
}


uint16_t	VolumeHeader::type()
{
  if (this->__vheader.signature == HfspVolume)
    return HfspVolume;
  else if (this->__vheader.signature == HfsxVolume)
    return HfsxVolume;
  // return 0 if bad signature, backup volume will be read in volume.cpp
  return 0;
}


void	VolumeHeader::process(Node* origin, uint64_t offset, fso* fsobj) throw (std::string)
{
  VFile*	vf;
  std::string	err;

  vf = NULL;
  err = std::string("");
  memset(&this->__vheader, 0, sizeof(volumeheader));
  if (origin == NULL)
    throw std::string("Provided node does not exist");
  try
    {
      vf = origin->open();
      vf->seek(offset);
      if (vf->read(&this->__vheader, sizeof(volumeheader)) != sizeof(volumeheader))
	{
	  err = std::string("Error while reading HFS Volume Header");
	}
    }
  catch (...)
    {
      err = std::string("Error while reading HFS Volume Header");
    }
  if (vf != NULL)
    {
      vf->close();
      delete vf;
    }
  if (!err.empty())
    throw err;
  this->sanitize();
}


void		VolumeHeader::sanitize() throw (std::string)
{
  if ((this->blockSize() % 512) != 0)
    throw std::string("Block size is not a muliple of 512");
  if (this->totalBlocks() < this->freeBlocks())
    throw std::string("More free block than total blocks");
}


Attributes	VolumeHeader::_attributes()
{
  Attributes	vmap;

  vmap["version"] = new Variant(this->version());
  vmap["last mounted version"] = new Variant(this->lastMountedVersion());
  vmap["created"] = new Variant(this->createDate());
  vmap["modified"] = new Variant(this->modifyDate());
  vmap["backup"] = new Variant(this->backupDate());
  vmap["checked"] = new Variant(this->checkedDate());
  vmap["Total number of files"] = new Variant(this->fileCount());
  vmap["Total number of folders"] = new Variant(this->folderCount());
  vmap["allocation block size"] = new Variant(this->blockSize());
  vmap["total number of allocation blocks"] = new Variant(this->totalBlocks());
  vmap["total number of free allocation blocks"] = new Variant(this->freeBlocks());
  vmap["total mounted"] = new Variant(this->writeCount());
  vmap["clump size for resource fork"] = new Variant(this->rsrcClumpSize());
  vmap["clump size for data fork"] = new Variant(this->dataClumpSize());
  return vmap;
}


uint32_t	VolumeHeader::blockSize()
{
  return bswap32(this->__vheader.blockSize);
}


uint32_t	VolumeHeader::totalBlocks()
{
  return bswap32(this->__vheader.totalBlocks);
}


uint16_t	VolumeHeader::signature()
{
  return bswap16(this->__vheader.signature);
}


uint16_t	VolumeHeader::version()
{
  return bswap16(this->__vheader.version);
}


uint32_t	VolumeHeader::attributes()
{
  return bswap32(this->__vheader.attributes);
}


uint32_t	VolumeHeader::lastMountedVersion()
{
  return bswap32(this->__vheader.lastMountedVersion);
}


uint32_t	VolumeHeader::journalInfoBlock()
{
  return bswap32(this->__vheader.journalInfoBlock);
}


DateTime*       VolumeHeader::createDate()
{
  uint32_t	cdate;

  cdate = bswap32(this->__vheader.createDate);
  return new HFSDateTime(cdate);  
}


DateTime*	VolumeHeader::modifyDate()
{
  uint32_t	mdate;
    
  mdate = bswap32(this->__vheader.modifyDate);
  return new HFSDateTime(mdate);
}


DateTime*	VolumeHeader::backupDate()
{
  uint32_t	bdate;

  bdate = bswap32(this->__vheader.backupDate);
  return new HFSDateTime(bdate);
}


DateTime*	VolumeHeader::checkedDate()
{
  uint32_t	chkdate;

  chkdate = bswap32(this->__vheader.checkedDate);
  return new HFSDateTime(chkdate);
}
 

uint32_t	VolumeHeader::fileCount()
{
  return bswap32(this->__vheader.fileCount);
}


uint32_t	VolumeHeader::folderCount()
{
  return bswap32(this->__vheader.folderCount);
}


uint32_t	VolumeHeader::freeBlocks()
{
  return bswap32(this->__vheader.freeBlocks);
}


uint32_t	VolumeHeader::nextAllocation()
{
  return bswap32(this->__vheader.nextAllocation);
}


uint32_t	VolumeHeader::rsrcClumpSize()
{
  return bswap32(this->__vheader.rsrcClumpSize);
}



uint32_t	VolumeHeader::dataClumpSize()
{
  return bswap32(this->__vheader.dataClumpSize);
}


uint32_t	VolumeHeader::nextCatalogID()
{
  return bswap32(this->__vheader.nextCatalogID);
}


uint32_t	VolumeHeader::writeCount()
{
  return bswap32(this->__vheader.writeCount);
}


uint64_t	VolumeHeader::encodingsBitmap()
{
  return bswap64(this->__vheader.encodingsBitmap);
}


ExtentsList	VolumeHeader::allocationExtents()
{
  return this->__extentsList(this->__vheader.allocationFile);
}


uint64_t	VolumeHeader::allocationSize()
{
  return bswap64(this->__vheader.allocationFile.logicalSize);
}


ExtentsList	VolumeHeader::overflowExtents()
{
  return this->__extentsList(this->__vheader.extentsFile);
}


uint64_t	VolumeHeader::overflowSize()
{
  return bswap64(this->__vheader.extentsFile.logicalSize);
}


ExtentsList	VolumeHeader::catalogExtents()
{
  return this->__extentsList(this->__vheader.catalogFile);
}


uint64_t	VolumeHeader::catalogSize()
{
  return bswap64(this->__vheader.catalogFile.logicalSize);
}


ExtentsList	VolumeHeader::attributesExtents()
{
  return this->__extentsList(this->__vheader.attributesFile);
}


ExtentsList	VolumeHeader::startupExtents()
{
  return this->__extentsList(this->__vheader.startupFile);
}


bool	VolumeHeader::isHfspVolume()
{
  return (this->signature() == HfspVolume || this->version() == 4);
}


bool	VolumeHeader::isHfsxVolume()
{
  return (this->signature() == HfsxVolume || this->version() == 5);
}


bool	VolumeHeader::createdByFsck()
{
  return (this->lastMountedVersion() == Fsck);
}


bool	VolumeHeader::isJournaled()
{
  return (this->lastMountedVersion() == Journaled 
	  || ((this->attributes() & VolumeJournaled) == VolumeJournaled));
}


bool	VolumeHeader::isMacOsX()
{
  return (this->lastMountedVersion() == MacOsX);
}


bool	VolumeHeader::isMacOs()
{
  return (this->lastMountedVersion() == MacOs);
}


bool	VolumeHeader::correctlyUmount()
{
  return (((this->attributes() & VolumeUmounted) == VolumeUmounted)
	  && ((this->attributes() & BootVolumeInconsistent) != BootVolumeInconsistent));
}


bool	VolumeHeader::hasBadBlocksExtents()
{
  return ((this->attributes() & VolumeSparedBlocks) == VolumeSparedBlocks);
}


bool	VolumeHeader::isRamDisk()
{
  return ((this->attributes() & VolumeNoCacheRequired) == VolumeNoCacheRequired);
}


bool	VolumeHeader::isCatalogIdReused()
{
  return ((this->attributes() & CatalogNodeIDsReused) == CatalogNodeIDsReused);
}


bool	VolumeHeader::isWriteProtected()
{
  return ((this->attributes() & VolumeSoftwareLock) == VolumeSoftwareLock);
}


ExtentsList	VolumeHeader::__extentsList(fork_data fork)
{
  int		i;
  Extent*	extent;
  ExtentsList	extents;

  for (i = 0; i != 8; ++i)
    {
      if (fork.extents[i].blockCount > 0)
	{
	  extent = new Extent(fork.extents[i], this->blockSize());
	  extents.push_back(extent);
	}
    }
  return extents;
}
