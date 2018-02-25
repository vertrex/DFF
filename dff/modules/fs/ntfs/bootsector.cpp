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

#include "bootsector.hpp"
#include "ntfs.hpp"
#include "ntfsopt.hpp"

BootSectorNode::BootSectorNode(NTFS* ntfs) : Node(std::string("$Boot"), 512, ntfs->rootDirectoryNode(), ntfs), __ntfs(ntfs), __state(0)
{
  this->__ntfs->setStateInfo("Parsing NTFS boot sectors");

  //this make cache ourselves with a size of 512
  VFile* vfile = this->open();
  uint64_t readed = vfile->read((void*)&this->__bootSector, sizeof(BootSector));
  delete vfile;

  if (readed != sizeof(BootSector))
    throw std::string("Can't read start of boot sector");

  this->__state = 1; //we change state because we modify our own size
  if (ntfs->fsNode()->size() > this->bytesPerSector() * 16)
    this->setSize(this->bytesPerSector() * 16);
  else 
    throw std::string("Can't read full boot sector");
} 

BootSectorNode::~BootSectorNode()
{
}

void	BootSectorNode::validate(void) const
{
  this->__ntfs->setStateInfo("Validating NTFS boot sector");
  if (this->endOfSector() != 0xAA55)
    throw std::string("Boot sector as an invalid end of sector value"); 
  if (this->bytesPerSector() == 0 || this->bytesPerSector() % 512)
    throw std::string("Boot sector as an invalid bytes per sector value");
  if (this->sectorsPerCluster() == 0)
    throw std::string("Boot sector as an invalid sector per cluster value");
  if (this->totalSectors() == 0) 
    throw std::string("Boot sector as an invalid total sectors value");
  if ((this->MFTLogicalClusterNumber() > this->totalSectors()) && (this->MFTMirrorLogicalClusterNumber() > this->totalSectors()))
    throw std::string("Boot sector can't resolve a valid MTF cluster");
  if (this->clustersPerMFTRecord() == 0)
    throw std::string("Boot sector as an invalid cluster per MFT record value");
  if (this->clustersPerIndexRecord() == 0)
    throw std::string("Boot sector as an invalid cluster per index buffer value");
  this->__ntfs->setStateInfo("NTFS boot sector is valid");
}

void 		BootSectorNode::fileMapping(FileMapping *fm)
{
  fm->push(0, this->size(), this->__ntfs->fsNode(), 0);
}

uint64_t	BootSectorNode::fileMappingState(void)
{
  return (this->__state);
}

uint64_t	BootSectorNode::_attributesState(void)
{
  return (this->__state);
}

Attributes      BootSectorNode::_attributes(void)
{
  Attributes    attrs;

  MAP_ATTR("OEM ID", this->OEMDID())
  MAP_ATTR("Bytes per sector", this->bytesPerSector())
  MAP_ATTR("Sectors per cluster", this->sectorsPerCluster())
  MAP_ATTR("Cluster size", this->clusterSize())
  MAP_ATTR("Media descriptor", this->mediaDescriptor())
  MAP_ATTR("Total sectors", this->totalSectors())
  MAP_ATTR("MFT logical cluster number", this->MFTLogicalClusterNumber())
  MAP_ATTR("MFT mirror logical cluster number", this->MFTMirrorLogicalClusterNumber())
  MAP_ATTR("Clusters per MFT record", this->clustersPerMFTRecord())
  MAP_ATTR("MFT entry size", this->MFTRecordSize())
  MAP_ATTR("Clusters per index record", this->clustersPerIndexRecord())
  MAP_ATTR("Index record size", this->indexRecordSize());
  MAP_ATTR("Volume serial number", this->volumeSerialNumber())
  MAP_ATTR("End of sector", this->endOfSector())
 
  return attrs;
}

const std::string	BootSectorNode::dataType(void)
{
  return std::string("ntfs/bootsector");
}

uint64_t 	BootSectorNode::OEMDID(void) const
{
  return (this->__bootSector.OEMID);
}

uint16_t 	BootSectorNode::bytesPerSector(void) const
{
  return (this->__bootSector.bpb.bytesPerSector);
}

uint8_t		BootSectorNode::sectorsPerCluster(void) const
{
  return (this->__bootSector.bpb.sectorsPerCluster);
}

uint32_t	BootSectorNode::clusterSize(void) const
{
 return (this->__bootSector.bpb.sectorsPerCluster * this->__bootSector.bpb.bytesPerSector);
}

uint8_t		BootSectorNode::mediaDescriptor(void) const
{
  return (this->__bootSector.bpb.mediaDescriptor);
}

uint64_t	BootSectorNode::totalSectors(void) const
{
  return (this->__bootSector.bpb.totalSectors);
}

uint64_t BootSectorNode::MFTLogicalClusterNumber(void) const
{
  return (this->__bootSector.bpb.MFTLogicalClusterNumber);
}

uint64_t	BootSectorNode::MFTMirrorLogicalClusterNumber(void) const
{
  return (this->__bootSector.bpb.MFTMirrorLogicalClusterNumber);
}

int8_t		BootSectorNode::clustersPerMFTRecord(void) const
{
  return (this->__bootSector.bpb.clustersPerMFTRecord);
}

uint32_t	BootSectorNode::MFTRecordSize(void) const
{
  if (this->__bootSector.bpb.clustersPerMFTRecord > 0)
    return (this->__bootSector.bpb.clustersPerMFTRecord * this->__bootSector.bpb.sectorsPerCluster * this->__bootSector.bpb.bytesPerSector);
  else
    return (1 << (this->__bootSector.bpb.clustersPerMFTRecord * -1));
};

int8_t		BootSectorNode::clustersPerIndexRecord(void) const
{
  return (this->__bootSector.bpb.clustersPerIndexRecord);
}

uint32_t        BootSectorNode::indexRecordSize(void) const
{
  if (this->__bootSector.bpb.clustersPerIndexRecord > 0)
    return (this->__bootSector.bpb.clustersPerIndexRecord * this->__bootSector.bpb.sectorsPerCluster * this->__bootSector.bpb.bytesPerSector);
  else
    return (1 << (this->__bootSector.bpb.clustersPerIndexRecord * -1));
}

uint64_t	BootSectorNode::volumeSerialNumber(void) const
{
  return (this->__bootSector.bpb.volumeSerialNumber);
}

uint16_t	BootSectorNode::endOfSector(void) const
{
  return (this->__bootSector.endOfSector);
}
