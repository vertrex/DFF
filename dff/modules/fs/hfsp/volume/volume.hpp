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


#ifndef __HFSP_VOLUME_HPP__
#define __HFSP_VOLUME_HPP__

#include <stdint.h>

#include "export.hpp"
#include "node.hpp"
#include "datetime.hpp"

#include "endian.hpp"

#include "extents/fork.hpp"

// Following defines are used in volume_header.signature
#define HfsVolume	0x4244 // BD
#define HfspVolume	0x482b // H+
#define HfsxVolume	0x4858 // HX

// Following defines are used in volume_header.version
#define Journaled	0x4846534a // HFSJ
#define MacOs		0x382e3130 // 8.10
#define MacOsX		0x31302e30 // 10.0
#define Fsck		0x6673636b // fsck

// Following defines are used in volume_header.attributes
#define VolumeUmounted		(1<<8)
#define VolumeSparedBlocks	(1<<9)
#define VolumeNoCacheRequired	(1<<10)
#define	BootVolumeInconsistent	(1<<11)
#define	CatalogNodeIDsReused	(1<<12)
#define	VolumeJournaled		(1<<13)
#define VolumeSoftwareLock	(1<<14)

using namespace DFF;

class VolumeInformation
{
public:
  VolumeInformation() {}
  virtual ~VolumeInformation() {}
  virtual uint16_t	type() = 0;
  virtual void		process(Node* origin, uint64_t offset, fso* fsobj) throw (std::string) = 0;
  virtual bool		isWrapper() {return false;}
  virtual Attributes	_attributes() = 0;
  virtual uint32_t	blockSize() = 0;
  virtual uint32_t	totalBlocks() = 0;
  virtual ExtentsList	overflowExtents() = 0;
  virtual uint64_t	overflowSize() = 0;
  virtual ExtentsList	catalogExtents() = 0;
  virtual uint64_t	catalogSize() = 0;
};


class VolumeFactory
{
private:
  void			__readBuffer(Node* origin, uint64_t offset, uint8_t* buffer, uint16_t size) throw (std::string);
public:
  VolumeFactory();
  ~VolumeFactory();
  VolumeInformation*	createVolumeInformation(Node* origin, fso* fsobj) throw (std::string);
};


PACK_START
typedef struct	s_master_dblock
{
  uint16_t	signature; // 0x4244 || 0xD2D7
  uint32_t	createDate;
  uint32_t	modifyDate;
  
  uint16_t	attributes;
  uint16_t	rootdirFiles;
  uint16_t	volumeBitmapBlock; // always 3?
  uint16_t	nextAllocationBlock;
  uint16_t	totalBlocks;
  uint32_t	blockSize;
  uint32_t	clumpSize;
  uint16_t	firstAllocationBlock;
  uint32_t	nextCatalogNodeId;
  uint16_t	freeBlocks;
  char		volumeName[28];
  uint32_t	backupDate;
  uint16_t	backupSeqNumber;
  uint32_t	writeCount;
  uint32_t	OverflowClumpSize;
  uint32_t	CatalogClumpSize;
  uint16_t	rootdirFolders;
  uint32_t	fileCount;
  uint32_t	folderCount;
  uint32_t	finderInfo[8];
  uint16_t	embedSignature;
  hfs_extent	embedExtent;
  uint32_t	overflowSize;
  hfs_extent	overflowExtents[3];
  uint32_t	catalogSize;
  hfs_extent	catalogExtents[3];
}		master_dblock;
PACK_END


class MasterDirectoryBlock : public VolumeInformation
{
private:
  master_dblock	__mdb;

public:
  MasterDirectoryBlock();
  ~MasterDirectoryBlock();
  virtual uint16_t	type();
  virtual void		process(Node* origin, uint64_t offset, fso* fsobj) throw (std::string);
  virtual Attributes	_attributes();
  virtual uint32_t	totalBlocks();
  virtual uint32_t	blockSize();
  virtual ExtentsList	overflowExtents();
  virtual uint64_t	overflowSize();
  virtual ExtentsList	catalogExtents();
  virtual uint64_t	catalogSize();

  void		sanitize() throw (std::string);
  uint16_t	signature();
  DateTime*	createDate();
  DateTime*	modifyDate();
  
  uint16_t	attributes();
  uint16_t	rootdirFiles();
  uint16_t	volumeBitmapBlock();
  uint16_t	nextAllocationBlock();
  uint32_t	clumpSize();
  uint16_t	firstAllocationBlock();
  uint32_t	nextCatalogNodeId();
  uint16_t	freeBlocks();

  std::string	volumeName();

  DateTime*	backupDate();
  uint16_t	backupSeqNumber();
  uint32_t	writeCount();
  uint32_t	OverflowClumpSize();
  uint32_t	CatalogClumpSize();
  uint16_t	rootdirFolders();
  uint32_t	fileCount();
  uint32_t	folderCount();
  //uint32_t	finderInfo[8]();
  uint16_t	embedSignature();
  uint16_t	embedStartBlock();
  uint16_t	embedBlockCount();
  bool		isWrapper();
  // extent	catalogExtents[3];
};


PACK_START
typedef struct s_volumeheader
{
  uint16_t	signature; // H+ or HX
  uint16_t	version;
  uint32_t	attributes;
  uint32_t	lastMountedVersion;
  uint32_t	journalInfoBlock;
 
  uint32_t	createDate;
  uint32_t	modifyDate;
  uint32_t	backupDate;
  uint32_t	checkedDate;
 
  uint32_t	fileCount;
  uint32_t	folderCount;
 
  uint32_t	blockSize;
  uint32_t	totalBlocks;
  uint32_t	freeBlocks;
 
  uint32_t	nextAllocation;
  uint32_t	rsrcClumpSize;
  uint32_t	dataClumpSize;
  uint32_t	nextCatalogID;

  uint32_t	writeCount;
  uint64_t	encodingsBitmap;

  uint32_t	finderInfo[8];
  
  fork_data	allocationFile;
  fork_data	extentsFile;
  fork_data	catalogFile;
  fork_data	attributesFile;
  fork_data	startupFile;
}		volumeheader;
PACK_END


class VolumeHeader : public VolumeInformation
{
private:
  volumeheader	__vheader;
  ExtentsList	__extentsList(fork_data fork);
public:
  VolumeHeader();
  ~VolumeHeader();
  virtual uint16_t	type();
  virtual void		process(Node* origin, uint64_t offset, fso* fsobj) throw (std::string);
  virtual Attributes	_attributes();
  virtual ExtentsList	overflowExtents();
  virtual uint64_t	overflowSize();
  virtual ExtentsList	catalogExtents();
  virtual uint64_t	catalogSize();

  void		sanitize() throw (std::string);
  uint16_t	signature();
  uint16_t	version();
  uint32_t	attributes();
  uint32_t	lastMountedVersion();
  uint32_t	journalInfoBlock();

  DateTime*	createDate();
  DateTime*	modifyDate();
  DateTime*	backupDate();
  DateTime*	checkedDate();
 
  uint32_t	fileCount();
  uint32_t	folderCount();
 
  uint32_t	blockSize();
  uint32_t	totalBlocks();
  uint32_t	freeBlocks();

  uint32_t	nextAllocation();
  uint32_t	rsrcClumpSize();
  uint32_t	dataClumpSize();
  uint32_t	nextCatalogID();

  uint32_t	writeCount();
  uint64_t	encodingsBitmap();

  ExtentsList	allocationExtents();
  uint64_t	allocationSize();

  ExtentsList	attributesExtents();
  ExtentsList	startupExtents();
  
  bool		isHfspVolume();
  bool		isHfsxVolume();
  bool		createdByFsck();
  bool		isJournaled();
  bool		isMacOsX();
  bool		isMacOs();
  bool		correctlyUmount();
  bool		hasBadBlocksExtents();
  bool		isRamDisk();
  bool		isCatalogIdReused();
  bool		isWriteProtected();
};


#endif
