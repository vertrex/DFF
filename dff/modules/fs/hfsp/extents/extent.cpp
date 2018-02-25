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

#include "extent.hpp"


Extent::Extent(hfsp_extent ext, uint64_t block_size)
{
  this->__startBlock = (uint64_t)bswap32(ext.startBlock);
  this->__blockCount = (uint64_t)bswap32(ext.blockCount);
  this->__blockSize = block_size;
}


Extent::Extent(hfs_extent ext, uint64_t block_size)
{
  this->__startBlock = (uint64_t)bswap16(ext.startBlock);
  this->__blockCount = (uint64_t)bswap16(ext.blockCount);
  this->__blockSize = block_size;
}


Extent::~Extent()
{
}


uint64_t	Extent::startBlock()
{
  return this->__startBlock;
}


uint64_t	Extent::startOffset()
{
  return this->__startBlock * this->__blockSize;
}


uint64_t	Extent::blockCount()
{
  return this->__blockCount;
}


uint64_t	Extent::size()
{
  return this->__blockCount * this->__blockSize;
}


void		Extent::dump(std::string tab)
{
  if (this->size() == 0)
    std::cout << tab << "Empty" << std::endl;
  else
    {
      std::cout << tab << "start block: " << this->startBlock() << std::endl;
      std::cout << tab << "start offset: " << this->startOffset() << std::endl;
      std::cout << tab << "block count: " << this->blockCount() << std::endl;
      std::cout << tab << "alloc bytes: " << this->size() << std::endl;
    }
}
