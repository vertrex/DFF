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

#include "fork.hpp"


ForkData::ForkData(uint32_t fileid, uint64_t blocksize) : __fileId(fileid), __blockSize(blocksize), __logicalSize(0), __totalBlocks(0), __type(Data), __etree(NULL), __extents()
{
}


ForkData::ForkData(uint32_t fileid, ExtentsTree* etree) : __fileId(fileid), __blockSize(0), __logicalSize(0), __totalBlocks(0), __type(Data), __etree(etree), __extents()
{
  if (etree != NULL)
    this->__blockSize = this->__etree->blockSize();
}


ForkData::~ForkData()
{
  this->__clearExtents();
}


void		ForkData::process(ExtentsList initial, uint64_t logicalSize, ForkData::Type type) throw (std::string)
{
  unsigned int	i;
  uint64_t	size;
  std::map<uint64_t, Extent*>	extents;
  std::map<uint64_t, Extent*>::iterator mit;

  if (this->__blockSize == 0)
    return;
  this->__clearExtents();
  this->__logicalSize = logicalSize;
  this->__extents = initial;
  size = 0;
  for (i = 0; i < this->__extents.size(); i++)
    size += this->__extents[i]->size();
  if (size < this->__logicalSize)
    {
      if (this->__etree != NULL)
	{
	  extents = this->__etree->extentsById(this->__fileId, type);
	  for (mit = extents.begin(); mit != extents.end(); mit++)
	    {
	      if (mit->second != NULL)
		{
		  size = mit->second->size();
		  this->__extents.push_back(mit->second);
		  this->__totalBlocks += mit->second->blockCount();
		}
	    }
	  extents.clear();
      	}
      else
      	std::cout << "[!] No Extents Overflow File set. Resulting data will be truncated" << std::endl;
    }
}


uint64_t	ForkData::logicalSize()
{
  return this->__logicalSize;
}


uint32_t	ForkData::totalBlocks()
{
  return this->__totalBlocks;
}


uint64_t	ForkData::allocatedBytes()
{
  return this->__totalBlocks * this->__blockSize;
}


uint64_t	ForkData::slackSize()
{
  uint64_t	allocated;
  uint64_t	size;

  size = this->logicalSize();
  allocated = this->allocatedBytes();
  if (size <= allocated)
    return allocated - size;
  else
    return 0;
}


ExtentsList	ForkData::extents()
{
  return this->__extents;
}


Extent*		ForkData::getExtent(uint32_t id)
{
  if (id < this->__extents.size() - 1)
    return this->__extents[id];
  else
    return NULL;
}


void		ForkData::dump(std::string tab)
{
  unsigned int	i;
  
  std::cout << tab << "logical size: " << this->logicalSize() << std::endl;
  std::cout << tab << "total blocks: " << this->totalBlocks() << std::endl;
  std::cout << tab << "allocated bytes: " << this->allocatedBytes()  << std::endl;
  std::cout << tab << "slack size: " << this->slackSize()  << std::endl;
  std::cout << tab << "Extent information" << std::endl;
  for (i = 0; i < this->__extents.size(); i++)
    {
      std::cout << tab << "Extent " << i << std::endl;
      this->__extents[i]->dump("\t\t");
    }
}


void	ForkData::__clearExtents()
{
  unsigned int	i;

  for (i = 0; i < this->__extents.size(); i++)
    delete this->__extents[i];
  this->__extents.clear();
}
