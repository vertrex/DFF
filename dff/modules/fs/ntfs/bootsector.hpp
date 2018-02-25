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

#ifndef __NTFS_BOOTSECTOR_HH__
#define __NTFS_BOOTSECTOR_HH__

#include "ntfs_common.hpp"

using namespace DFF;
using namespace std;

class NTFS;

PACK_START
typedef struct s_BPB
{
  uint16_t	bytesPerSector;
  uint8_t	sectorsPerCluster;
  uint8_t	reserved[7];
  uint8_t	mediaDescriptor;
  uint8_t	reserved2[18];
  uint64_t	totalSectors;
  uint64_t	MFTLogicalClusterNumber;
  uint64_t	MFTMirrorLogicalClusterNumber;
  int8_t	clustersPerMFTRecord;
  uint8_t	reserved3[3];
  int8_t	clustersPerIndexRecord;  
  uint8_t	reserved4[3];
  uint64_t	volumeSerialNumber;
  uint32_t	reserved5;
}		BPB;
PACK_END


PACK_START
typedef struct s_BootStrap
{
  uint8_t  	bootStrap[426];
}		BootStrap;
PACK_END

PACK_START
typedef struct s_BootSector
{
  uint8_t 	jump[3];
  uint64_t 	OEMID;
  BPB		bpb;
  BootStrap	bootStrap;
  uint16_t	endOfSector;
}		BootSector;
PACK_END


class BootSectorNode : public Node
{
private:
  NTFS*				__ntfs;
  BootSector			__bootSector;
  uint64_t			__state; 
public:
				BootSectorNode(NTFS* ntfs);
				~BootSectorNode();
  virtual void			fileMapping(FileMapping *fm);
  virtual uint64_t		fileMappingState(void);	
  virtual uint64_t		_attributesState(void);
  virtual Attributes		_attributes(void);
  virtual const std::string 	dataType(void);
  uint64_t			OEMDID(void) const;
  uint16_t			bytesPerSector(void) const;
  uint8_t			sectorsPerCluster(void) const;
  uint32_t			clusterSize(void) const;
  uint8_t			mediaDescriptor(void) const;
  uint64_t			totalSectors(void) const;
  uint64_t			MFTLogicalClusterNumber(void) const;
  uint64_t			MFTMirrorLogicalClusterNumber(void) const;
  int8_t			clustersPerMFTRecord(void) const;
  uint32_t			MFTRecordSize(void) const;
  int8_t			clustersPerIndexRecord(void) const;  
  uint32_t			indexRecordSize(void) const;
  uint64_t			volumeSerialNumber(void) const;
  uint16_t			endOfSector(void) const;
  void				validate(void) const;
};

#endif
