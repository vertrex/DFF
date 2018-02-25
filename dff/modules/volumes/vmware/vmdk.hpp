/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2013 ArxSys
 *
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
 *  MOUNIER Jeremy <jmo@digital-forensic.org>
 *
 */

#ifndef __VMDK_HPP__
#define __VMDK_HPP__

#include <iostream>
#include <string>
#include "node.hpp"
#include "vfile.hpp"

#define VMDK_DISK_DESCRIPTOR 0x69442023     /*"# Di" */
#define VMDK_SPARSE_MAGICNUMBER 0x564d444b    /*"VMDK" */
#define VMDK_ESX_SPARSE_MAGICNUMBER 0x44574f43 /* "COWD" */

// Create Type definitions
#define CTYPE_MONO_SPARSE "monolithicSparse"
#define CTYPE_MONO_FLAT "monolithicFlat"
#define CTYPE_EXTENT_SPARSE "twoGbMaxExtentSparse"
#define CTYPE_EXTENT_FLAT "twoGbMaxExtentFlat"
// Terms that include vmfs indicate that the disk is an ESX Server disk
#define CTYPE_VMFS "vmfs"
#define CTYPE_VMFS_RAWDEVICEMAP "vmfsRawDeviceMap"
#define CTYPE_VMFS_PASSTHROUGT "vmfsPassthroughRawDeviceMap"
#define CTYPE_VMFS_SPARSE "vmfsSparse"
//The terms fullDevice, vmfsRaw, and partitionedDevice are used 
//when the virtual machine is configured to make direct use of a physical disk
#define CTYPE_FULL "fullDevice"
#define CTYPE_PARTITION "partitionedDevice"
#define CTYPE_VMFS_RAW "vmfsRaw"
// Optimized for stream
#define CTYPE_STREAM "streamOptimized"

#define SECTOR_SIZE 0x200

#define GDSTART_MONO 0x15
#define GDSTART_TWO 0x1
#define GRAIN_SIZE 0x80
#define GTE_PER_GT 0x200

using namespace DFF;

#pragma pack(1)
typedef struct sparseExtentHeader
{
  uint32_t    magicNumber;
  uint32_t    version;
  uint32_t    flags;
  uint64_t    capacity;
  uint64_t    grainSize;
  uint64_t    descriptorOffset;
  uint64_t    descriptorSize;
  uint32_t    GTEsPerGT;
  uint64_t    RGDOffset;
  uint64_t    GDOffset;
  uint64_t    overHead;
  bool        uncleanShutdown;
  char        singleEndLineChar;
  char        nonEndLineChar;
  char        doubleEndLineChar1;
  char        doubleEndLineChar2;
  uint16_t    compressAlgorithm;
  uint8_t     pad[433];
} SparseExtentHeader;
#pragma pack()

#pragma pack(1)
typedef struct COWDisk_Header
{
  uint32_t    magicNumber;
  uint32_t    version;
  uint32_t    flags;
  uint32_t    numSectors;
  uint32_t    grainSize;
  uint32_t    gdOffset;
  uint32_t    numGDEntries;
  uint32_t    freeSector;
/* The spec incompletely documents quite a few further fields, but states
 * that they are unused by the current format. Replace them by padding. */
  char        reserved1[1604];
  uint32_t    savedGeneration;
  char        reserved2[8];
  int32_t     uncleanShutdown;
  char        padding[396];
} COWDisk_Header;
#pragma pack()

typedef enum vmdktype
  {
    HOST_SPARSE = 1,
    FLAT,
    ZERO,
    VMFS,
    ESX_SPARSE
  }vmdktype;

typedef struct extentInfo
{
  
  sparseExtentHeader	header;

  unsigned int	id;
  unsigned int	version;
  vmdktype	type;
  Node		*node;
  VFile		*vfile;

  uint64_t	sectors;
  uint64_t	sectorsPerGrain;
  
  uint64_t	sectorGD;
  uint64_t	sectorRGD;
  
  uint64_t	overheadSectors;
  
  unsigned int	sectorsPerGDE;
  unsigned int	GDEntries;
  unsigned int	GTEntries;

  
  char		*descData;
  uint64_t	descriptorSector;
  uint64_t	descriptorSize;
  
  bool			footer;
  unsigned short	compression;
  
} extentInfo;


#endif
