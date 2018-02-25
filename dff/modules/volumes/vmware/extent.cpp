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

#include "exceptions.hpp"
#include "extent.hpp"

#include "node.hpp"


Extent::Extent(DFF::Node *nd, uint32_t id)
{
  this->vmdk = nd;
  this->id = id;
  this->vfile = this->vmdk->open();
  this->readSparseHeader();
}

Extent::~Extent()
{
}

int	Extent::readSparseHeader()
{

  sparseExtentHeader header;
  /** Read VMDK _Header **/
  try
    {
      this->vfile->seek(0);
      this->vfile->read(&header, sizeof(SparseExtentHeader));
    }
  catch (envError & e)
    {
      std::cerr << "Error reading _Header : arg->get(\"parent\", &_node) failed." << std::endl;
      throw e;
    }
  if ((header.magicNumber == VMDK_SPARSE_MAGICNUMBER) && (header.version == 1))
    {
      //      printf("VMDK header founded, version: %x\n",header.version);
      this->header = header;
      //      this->id = header.id;
      this->version = header.version;
      //xxx
      this->type = HOST_SPARSE;
      //xxx
      this->sectors = header.capacity;
      this->sectorsPerGrain = header.grainSize;
      this->sectorGD = header.GDOffset;
      this->sectorRGD = header.RGDOffset;
      this->overheadSectors = header.overHead;
      
      this->descriptorSector = header.descriptorOffset;
      this->descriptorSize = header.descriptorSize;
      
      this->GTEntries = header.GTEsPerGT;
      //calculate
      unsigned int sPerGDE = (header.GTEsPerGT * header.grainSize);
      unsigned int GDEs = (header.capacity + (sPerGDE -1)) / sPerGDE;
      
      this->sectorsPerGDE = sPerGDE;
      this->GDEntries = GDEs;

      return 1;
    }
  return 0;
}

int	Extent::createBackupHeader(int type)
{
  
  unsigned int	GTentry;

  //std::cout << "Reconstruct Extent" << std::endl;

  //  this->id = _extents.size();
  this->version = 1;
  this->type = HOST_SPARSE;
  this->sectorsPerGrain = GRAIN_SIZE;
  if (type == 0)
    {
      this->sectorGD = GDSTART_MONO;
      this->sectorRGD = GDSTART_MONO;
    }
  else
    {
      this->sectorGD = GDSTART_TWO;
      this->sectorRGD = GDSTART_TWO;
    }
    //  extent->overheadSectors = header.overHead;
  this->GTEntries = GTE_PER_GT;
      //calculate
  unsigned int sPerGDE = (GTE_PER_GT * GRAIN_SIZE);
  this->sectorsPerGDE = sPerGDE;

  try
    {
      if (type == 0)
  	vfile->seek(GDSTART_MONO * SECTOR_SIZE);
      else
  	vfile->seek(GDSTART_TWO * SECTOR_SIZE);
      vfile->read(&GTentry, sizeof(unsigned int));
    }
  catch (envError & e)
    {
      std::cerr << "Error reading entry : arg->get(\"parent\", &_node) failed." << std::endl;
      throw e;
    }

  //capacity = ((First GT offset - GD offset) / 4) * (GRAIN_SIZE * SECTOR_SIZE)
  if (type == 0)
    this->sectors = (((GTentry * SECTOR_SIZE) - (GDSTART_MONO * SECTOR_SIZE)) / 4) * (GRAIN_SIZE * SECTOR_SIZE);
  else
    this->sectors = (((GTentry * SECTOR_SIZE) - (GDSTART_TWO * SECTOR_SIZE)) / 4) * (GRAIN_SIZE * SECTOR_SIZE);
  
  //  printf("gt entry offset: %x\n", GTentry * SECTOR_SIZE);
  //  printf("gd start offset: %x\n", GDSTART_MONO * SECTOR_SIZE);
  //  printf("extent sectors : %llx\n", this->sectors);

  unsigned int GDEs = (this->sectors + (sPerGDE -1)) / sPerGDE;
  this->GDEntries = GDEs;
  return 0;
}
