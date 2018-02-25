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

#include "allocation.hpp"

#include "exceptions.hpp"

AllocationFile::AllocationFile() : __cacheOffset(0), __blocks(0), __percent(0), __cache(NULL), __handler(NULL), __allocation(NULL), __vfile(NULL), __freeBlocks()
{
}


AllocationFile::~AllocationFile()
{
  this->__clearCache();
}


void		AllocationFile::setHandler(HfsFileSystemHandler* handler) throw (std::string)
{
  if (handler == NULL)
    throw std::string("Cannot create Catalog tree because provided handler does not exist");
  this->__handler = handler;
}


void			AllocationFile::process(Node* allocation, uint64_t offset, uint64_t blocks) throw (std::string)
{
  uint64_t		current;
  uint64_t		nsize;
  uint64_t		start;
  bool			commit;
  
  if (this->__handler == NULL)
    throw std::string("No handler provided");
  if (allocation == NULL)
    throw std::string("Provided allocation file does not exist");
  if (offset > allocation->size())
    throw std::string("Provided offset is greater than allocation file size");
  this->__allocation = allocation;
  this->__blocks = blocks;
  this->__percent = 0;
  try
    {
      this->__vfile = this->__allocation->open();
    }
  catch (vfsError& e)
    {
      throw std::string("Cannot open allocation file");
    }
  this->__initCache();
  nsize = 0;
  start = 0;
  commit = false;
  for (current = 0; current < this->__blocks; ++current)
    {
      if (!this->isBlockAllocated(current))
	{
	  if (commit == false)
	    {
	      start = current;
	      commit = true;
	    }
	  nsize += this->__handler->blockSize();
	}
      else
	{
	  if (commit)
	    {
	      this->__freeBlocks[start] = current;
	      commit = false;
	    }
	}
    }
  this->__progress(current);
  UnallocatedNode* unalloc = new UnallocatedNode("$Unallocated space", nsize, this->__handler->mountPoint(), this->__handler->fsObject());
  unalloc->setContext(this->__handler->origin(), this->__handler->blockSize(), this->__freeBlocks);
}


bool			AllocationFile::isBlockAllocated(uint64_t block) throw (std::string)
{
  uint64_t		offset;
  uint64_t		coffset;
  uint8_t		byte;

  offset = block / 8;
  if (offset > this->__allocation->size())
    throw std::string("Provided block is greater than possible range");
  if (offset < this->__cacheOffset || offset > this->__cacheOffset+10485760)
    this->__updateCache(offset);
  coffset = offset - this->__cacheOffset;
  byte = *(this->__cache+coffset);
  return (byte & (1 << (7 - (block % 8)))) != 0;
}


void		AllocationFile::__clearCache()
{
  if (this->__cache != NULL)
    {
      free(this->__cache);
      this->__cache = NULL;
    }
  this->__cacheOffset = 0;
}


void		AllocationFile::__initCache()
{
  if (this->__cache == NULL)
    {
      if ((this->__cache = (uint8_t*)malloc(sizeof(uint8_t) * 10485760)) == NULL)
	throw std::string("Cannot allocate cache for allocation file");
    }
  this->__updateCache(0);
  this->__cacheOffset = 0;
}



void			AllocationFile::__updateCache(uint64_t offset)
{
  int64_t		size;

  if (offset + 10485760 > this->__allocation->size())
    size = this->__allocation->size() - offset;
  else
    size = 10485760;
  try
    {
      this->__vfile->seek(offset);
      // XXX enhance read error
      if (this->__vfile->read(this->__cache, size) != size)
	std::cout << "Error while filling allocation cache!" << std::endl;
    }
  catch (vfsError& e)
    {
      throw std::string("Error while reading allocation file");
    }
  this->__cacheOffset = offset;
}


void			AllocationFile::__progress(uint64_t current)
{
  uint64_t		percent;
  std::stringstream	sstr;

  percent = (current * 100) / this->__blocks;
  if (this->__percent < percent)
    {
      sstr << "Processing bitmap allocation block: " << percent << "% (" << current << " / " << this->__blocks << ")" << std::endl;
      this->__handler->fsObject()->stateinfo = sstr.str();
      sstr.str("");
      this->__percent = percent;
    }
}


UnallocatedNode::UnallocatedNode(std::string name, uint64_t size, Node* parent, fso* fsobj) : Node(name, size, parent, fsobj), __freeBlocks(), __origin(NULL), __bsize(0) 
{
}


UnallocatedNode::~UnallocatedNode()
{ 
}


void	UnallocatedNode::setContext(Node* origin, uint64_t bsize, const std::map<uint64_t, uint64_t>& freeBlocks)
{
  this->__origin = origin;
  this->__bsize = bsize;
  this->__freeBlocks = freeBlocks;
}


void	UnallocatedNode::fileMapping(FileMapping* fm)
{
  std::map<uint64_t, uint64_t>::iterator	mit;
  uint64_t					coffset;
  uint64_t					asize;

  coffset = 0;
  for (mit = this->__freeBlocks.begin(); mit != this->__freeBlocks.end(); ++mit)
    {
      asize = (mit->second - mit->first) * this->__bsize;
      fm->push(coffset, asize, this->__origin, mit->first * this->__bsize);
      coffset += asize;
    }
}
