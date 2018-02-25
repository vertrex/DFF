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


class VolumeHeader
{
private:
  volumeheader	__vheader;

public:
  VolumeHeader();
  ~VolumeHeader();
  void		process(Node* origin, fso* fsobj) throw (std::string);
  Attributes	_attributes();

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

  fork_data	allocationFile();
  fork_data	extentsFile();
  fork_data	catalogFile();
  fork_data	attributesFile();
  fork_data	startupFile();
  
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
