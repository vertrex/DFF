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

#include "exceptions.hpp"
#include "vfile.hpp"
#include "variant.hpp"


VolumeFactory::VolumeFactory()
{
}


VolumeFactory::~VolumeFactory()
{
}


VolumeInformation*	VolumeFactory::createVolumeInformation(Node* origin, fso* fsobj) throw (std::string)
{
  std::string		error;
  VolumeInformation*	vinfo;
  uint16_t		signature;
  uint8_t*		buffer;
  uint64_t		offset;

  vinfo = NULL;
  buffer = NULL;
  offset = 1024;
  if (origin == NULL)
    throw std::string("Provided origin does not exist");
  if ((buffer = (uint8_t*)malloc(sizeof(uint8_t)*512)) == NULL)
    throw std::string("can't alloc memory");
  try
    {
      this->__readBuffer(origin, 1024, buffer, 512);
    }
  catch (std::string e)
    {
      error = e;
    }
  memcpy(&signature, buffer, 2);
  signature = bswap16(signature);
  if (signature == HfsVolume)
    vinfo = new MasterDirectoryBlock();
  else if (signature == HfspVolume || signature == HfsxVolume)
    vinfo = new VolumeHeader();
  else
    {
      // reading at entry at the end of the volume
      offset = origin->size()-1024;
      this->__readBuffer(origin, offset, buffer, 512);
      memcpy(&signature, buffer, 2);
      signature = bswap16(signature);
      if (signature == HfsVolume)
	vinfo = new MasterDirectoryBlock();
      else if (signature == HfspVolume || signature == HfsxVolume)
	vinfo = new VolumeHeader();
      else
	error = std::string("Cannot find Hfs version");
    }
  if (buffer != NULL)
    free(buffer);
  if (!error.empty())
    throw error;
  if (vinfo != NULL)
    vinfo->process(origin, offset, fsobj);
  return vinfo;
}


void		VolumeFactory::__readBuffer(Node* origin, uint64_t offset, uint8_t* buffer, uint16_t size) throw (std::string)
{
  std::string	error;
  VFile*	vfile;
  
  vfile = NULL;
  try
    {
      vfile = origin->open();
      vfile->seek(offset);
      if (vfile->read(buffer, size) != size)
	error = std::string("Cannot read on node");
    }
  catch (std::string& err)
    {
      error = err;
    }
  catch (vfsError& err)
    {
      error = err.error;
    }
  if (vfile != NULL)
    {
      vfile->close();
      delete vfile;
    }
  if (!error.empty())
    throw error;
}
