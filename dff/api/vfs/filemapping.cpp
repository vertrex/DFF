/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2013 ArxSys
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

#include "node.hpp"
#include "filemapping.hpp"

namespace DFF
{

FileMapping::FileMapping(Node* node)
{
  this->__node = node;
  this->__maxOffset = 0;
  this->__refcount = 1;
  mutex_init(&this->__fm_mutex); 
}

FileMapping::~FileMapping()
{
  uint32_t	i;

  for (i = 0; i != this->__chunks.size(); i++)
  {
    delete this->__chunks[i];
    this->__chunks[i] = NULL;
  }
  mutex_destroy(&this->__fm_mutex);
}

void			FileMapping::addref(void)
{
  mutex_lock(&this->__fm_mutex);
  this->__refcount++;
  mutex_unlock(&this->__fm_mutex);
}

void			FileMapping::delref(void)
{
  mutex_lock(&this->__fm_mutex);
  this->__refcount--;
  if (this->__refcount == 0)
  {
     delete this;
     return ;
  }
  mutex_unlock(&this->__fm_mutex);
}

uint64_t		FileMapping::refcount(void)
{
  uint64_t count;
  mutex_lock(&this->__fm_mutex);
  count =  this->__refcount;
  mutex_unlock(&this->__fm_mutex);
  return count;
}

Node*			FileMapping::node(void)
{
  return (this->__node);
}

uint32_t		FileMapping::chunkCount()
{
  return this->__chunks.size();
}

chunk*			FileMapping::chunkFromIdx(uint32_t idx)
{
  if (idx < this->__chunks.size())
    return this->__chunks[idx];
  else
    return NULL;
}

std::vector<chunk *>	FileMapping::chunksFromIdxRange(uint32_t begidx, uint32_t endidx)
{
  std::vector<chunk *>	v;
  uint32_t		vsize;
  std::vector<chunk *>::iterator	begit;
  std::vector<chunk *>::iterator	endit;
  
  vsize = this->__chunks.size();
  if ((begidx < endidx) && (begidx < vsize) && (endidx < vsize))
    {
      begit = this->__chunks.begin()+begidx;
      endit = this->__chunks.begin()+endidx;
      v.assign(begit, endit);
    }
  return v;
}

std::vector<chunk *>	FileMapping::chunksFromOffsetRange(uint64_t begoffset, uint64_t endoffset)
{
  std::vector<chunk *>	v;
  uint32_t		begidx;
  uint32_t		endidx;

  if ((begoffset > endoffset) || (begoffset > this->__maxOffset) || (endoffset > this->__maxOffset))
    throw("provided offset too high");
  try
    {
      begidx = this->chunkIdxFromOffset(begoffset);
      endidx = this->chunkIdxFromOffset(endoffset);
      v = this->chunksFromIdxRange(begidx, endidx);
    }
  catch (...)
    {
    }
  return v;
}

chunk*			FileMapping::firstChunk()
{
  if (this->__chunks.size() > 0)
    return this->__chunks.front();
  else
    return NULL;
}

chunk*			FileMapping::lastChunk()
{
  if (this->__chunks.size() > 0)
    return this->__chunks.back();
  else
    return NULL;
}


std::vector<chunk *>	FileMapping::chunks()
{
  return this->__chunks;
}

uint32_t		FileMapping::__bsearch(uint64_t offset, uint32_t lbound, uint32_t rbound, bool* found)
{
  uint32_t		mbound;

  if (rbound < lbound)
    return rbound;
  mbound = (rbound + lbound) / 2;
  if (offset < this->__chunks[mbound]->offset)
    {
      if (mbound > 0)
	return this->__bsearch(offset, lbound, mbound - 1, found);
      else
	return 0;
    }
  else if (offset > this->__chunks[mbound]->offset + this->__chunks[mbound]->size - 1)
    return this->__bsearch(offset, mbound + 1, rbound, found);
  else
    {
      *found = true;
      return mbound;
    }
}


chunk*			FileMapping::chunkFromOffset(uint64_t offset)
{
  chunk*		chk;
  uint32_t		idx;
  bool			found;

  mutex_lock(&this->__fm_mutex);

  found = false;
  if (this->__chunks.size() == 0)
  {
    mutex_unlock(&this->__fm_mutex);
    throw(std::string("file mapping is empty"));
  }
  if (offset > this->__maxOffset)
  {
    mutex_unlock(&this->__fm_mutex);
    throw("provided offset too high");
  }
  if (this->__chunks.size() == 1)
  {
    //if there's only one chunk, there are two possibilities:
    // - either file's mapping is represented by only one chunk starting from 0
    // - or file's mapping is partial and only represents parts of the file. The stored chunk starts from an offset != 0
    chk = this->__chunks[0];
    //first, check if stored chunk contains the requested offset
    if (offset >= chk->offset && offset <= chk->offset + chk->size - 1)
    {
      mutex_unlock(&this->__fm_mutex);
      return chk;
    }
    // if not, it means the offset is lesser than the starting offset of the stored chunk
    // if offset is greater than chk->offset + chk->size, an exception has been raised (offset > __maxOffset)
    else
    {
       // a virtual chunk is created and is treated as a buffer full of 0 in mfso::readFromMapping
       chk = new chunk;
       chk->offset = 0;
       chk->size = this->__chunks[0]->offset;
       chk->origin = NULL;
       chk->originoffset = 0;
       this->__chunks.insert(this->__chunks.begin(), chk);
       mutex_unlock(&this->__fm_mutex);
       return chk;
    }
  } 
  else
  {
    //otherwise, there are at least 2 chunks and two possibilities:
    // - either the chunk containing the requested offset is found
    // - or the chunk containing the requested offset is NOT found
    idx = this->__bsearch(offset, 0, this->__chunks.size() - 1, &found);
    if (found)
    {
      mutex_unlock(&this->__fm_mutex);
      return this->__chunks[idx];
    }
    else
    {
      //__bsearch always provide the left-most chunk meaning provided offset
      //is greater than chunk[idx]->offset + chunk[idx]->size - 1.
      //We need to map the gap
      //If returned idx is the last chunk, check if size of node is greater than
      //chunks[idx]->offset + chunks[idx]->size ?
      //at the moment, we throw an exception
      if (idx == this->__chunks.size() - 1)
      {
    	mutex_unlock(&this->__fm_mutex);
	throw(std::string("no more chunk available. file is not complete"));
      }
      //if idx is the first chunk, it means first part of the mapping of the file is
      //missing. A virtual chunk is created to fill the gap.
      else if (idx == 0)
      {
	if (offset < this->__chunks[0]->offset)
        {
          //std::cout << "offset < this->__chunks[0]->offset" << std::endl;
	  chk = new chunk;
	  chk->offset = 0;
	  chk->size = this->__chunks[0]->offset;
	  chk->origin = NULL;
	  chk->originoffset = 0;
	  this->__chunks.insert(this->__chunks.begin(), chk);
     	  mutex_unlock(&this->__fm_mutex);
	  return chk;
	}
	else
	{
	  chk = new chunk;
	  //std::cout << "offset > this->__chunks[0]->offset" <<  std::endl;
	  chk->offset = this->__chunks[0]->offset + this->__chunks[0]->size;
	  chk->size = this->__chunks[1]->offset - chk->offset;
	  chk->origin = NULL;
	  chk->originoffset = 0;
	  this->__chunks.insert(this->__chunks.begin()+1, chk);
    	  mutex_unlock(&this->__fm_mutex);
	  return chk;
	}
      }
      //requested offset is in the middle of two mapped chunks. A virtual chunk
      //is created which fill the gap.
      else
      {
	chk = new chunk;
	//std::cout << idx << " < offset < " << (idx + 1) << std::endl;
	chk->offset = this->__chunks[idx]->offset + this->__chunks[idx]->size;
	chk->size = this->__chunks[idx+1]->offset - chk->offset;
	chk->origin = NULL;
	chk->originoffset = 0;
	this->__chunks.insert(this->__chunks.begin()+idx+1, chk);
    	mutex_unlock(&this->__fm_mutex);
	return chk;
      }
    }
  }
}


chunk*		FileMapping::__makeChunk(uint64_t offset, uint64_t size, class Node* origin, uint64_t originoffset)
{
  chunk		*c;

  c = new chunk;
  c->offset = offset;
  c->size = size;
  if (this->__maxOffset < offset + size)
    this->__maxOffset = offset + size;
  c->origin = origin;
  c->originoffset = originoffset;
  return c;
}


void		FileMapping::__manageConflicts(uint32_t idx, uint64_t offset, uint64_t size, class Node* origin, uint64_t originoffset)
{
  chunk*	c;
  uint32_t	counter;
  
  if (size == 0)	// no data available, nothing to do
    return;

  // based on the algorithm of __bsearch, it must never happen but log it
  if (offset < this->__chunks[idx]->offset)
    {
      //std::cout << "offset: (" << offset << ") is lesser than current idx (" << this->__chunks[idx]->offset << ")\n" << std::endl;
    }

  else if (offset == this->__chunks[idx]->offset)
    {
      //std::cout << "offset: " << offset << " -- size: " << size << " -- IDX: offset: " << this->__chunks[idx]->offset << " -- size: " << this->__chunks[idx]->size << std::endl;
      if (size < this->__chunks[idx]->size)	// create new chunk and remove overlap from actual chunk
	{
	  c = this->__makeChunk(offset, size, origin, originoffset);
	  this->__chunks[idx]->size -= size;
	  this->__chunks[idx]->offset += size;
	  this->__chunks[idx]->originoffset += size;
	  this->__chunks.insert(this->__chunks.begin()+idx, c);
	}
      else if (size == this->__chunks[idx]->size)	// just rewrite new position on underlying layer
	{
	  this->__chunks[idx]->origin = origin;
	  this->__chunks[idx]->originoffset = originoffset;
	}
      else	// size > this->__chunks[idx]->size
	{
	  if (this->__chunks.size() == 1)	// only one chunk, update size, origin and originoffset
	    {
	      this->__chunks[idx]->size = size;
	      this->__chunks[idx]->origin = origin;
	      this->__chunks[idx]->originoffset = originoffset;
	    }
	  else	// need to find chunk where overlap stops
	    {
	      counter = idx;
	      while ((counter != this->__chunks.size() - 1) && (this->__chunks[counter]->offset+this->__chunks[counter]->size <= offset+size))
		++counter;
	      //std::cout << "idx: " << idx << "counter: " << counter << std::endl;
	    }
	}
    }
  else	// offset > this->__chunks[idx]->offset
    { 
      //std::cout << "offset > " << std::endl;
      // chunk[idx] | current | chunk[idx]
      // allocate one chunk for the current offset
      // update chunks[idx] size to reflect overlap
      // allocate a new one 
      if (offset+size < this->__chunks[idx]->offset + this->__chunks[idx]->size)
	{
	  uint64_t	u_offset;
	  uint64_t	u_size;
	  uint64_t	u_originoffset;

	  u_offset = offset+size;
	  u_size = (this->__chunks[idx]->offset+this->__chunks[idx]->size) - u_offset;
	  u_originoffset = this->__chunks[idx]->originoffset + u_offset + u_size;
	  this->__chunks[idx]->size = offset - this->__chunks[idx]->offset;
	  c = this->__makeChunk(offset, size, origin, originoffset);
	  this->__chunks.insert(this->__chunks.begin()+idx+1, c);
	  c = this->__makeChunk(u_offset, u_size, this->__chunks[idx]->origin, u_originoffset);
	  this->__chunks.insert(this->__chunks.begin()+idx+2, c);
	}
      else if (offset+size == this->__chunks[idx]->offset + this->__chunks[idx]->size)
	{
	  this->__chunks[idx]->size = offset - this->__chunks[idx]->offset;
	  c = this->__makeChunk(offset, size, origin, originoffset);
	  this->__chunks.insert(this->__chunks.begin()+idx+1, c);
	}
      else // offset+size > chunks[idx]->offset+chunks[idx]->size
	{
	  if (this->__chunks.size() == 1)
	    {
	      this->__chunks[idx]->size = offset - this->__chunks[idx]->offset;
	      c = this->__makeChunk(offset, size, origin, originoffset);
	      this->__chunks.insert(this->__chunks.begin()+1, c);
	    }
	  else
	    {
	      counter = idx;
	      while ((counter != this->__chunks.size() - 1) && (this->__chunks[counter]->offset+this->__chunks[counter]->size <= offset+size))
		++counter;
	      //std::cout << "idx: " << idx << "counter: " << counter << std::endl;
	    }
	}
    }
}


uint32_t	FileMapping::chunkIdxFromOffset(uint64_t offset, uint32_t sidx)
{
  uint32_t	idx;
  chunk*	chk;
  bool		found;
  
  if (offset > this->__maxOffset)
    throw("provided offset too high");
  if (this->__chunks.size() == 0)
    throw(std::string("provided offset is not mapped"));
  if (sidx > this->__chunks.size() - 1)
    throw(std::string("provided idx is too high"));
  if (this->__chunks.size() == 1)
    {
      chk = this->__chunks[0];
      if (offset >= chk->offset && offset <= chk->offset + chk->size - 1)
	return 0;
      else
	throw(std::string("provided offset is not mapped"));
    }
  else
    {
      idx = this->__bsearch(offset, sidx, this->__chunks.size() - 1, &found);
      if (found)
	return idx;
      else
	throw(std::string("provided offset is not mapped"));
    }
}


void				FileMapping::forceAllocChunk(uint64_t offset, uint64_t size, class Node* origin, uint64_t originoffset)
{
  std::vector<chunk*>::iterator	it;
  uint32_t			idx;
  chunk				*c;
  bool				found;

  found = false;
  if (this->__chunks.size() == 0)
    it = this->__chunks.begin();
  else if (this->__chunks.size() == 1)
    {
      if (offset < this->__chunks[0]->offset && offset+size < this->__chunks[0]->offset + this->__chunks[0]->size - 1)
	it = this->__chunks.begin();
      else if (offset > (this->__chunks[0]->offset + this->__chunks[0]->size - 1))
	it = this->__chunks.begin() + 1;
      else
	return this->__manageConflicts(0, offset, size, origin, originoffset);
    }
  else
    {
      idx = this->__bsearch(offset, 0, this->__chunks.size() - 1, &found);
      if (found)
	return this->__manageConflicts(idx, offset, size, origin, originoffset);
      if (idx >= 1)
      	{
      	  if (idx == this->__chunks.size() - 1)
	    it = this->__chunks.end();
      	  else if (offset >= (this->__chunks[idx-1]->offset + this->__chunks[idx-1]->size) && (offset + size) <= this->__chunks[idx+1]->offset)
      	    it = this->__chunks.begin() + idx + 1;
	}
      else if ((offset + size) <= this->__chunks[idx]->offset)
	it = this->__chunks.begin();
    }
  c = this->__makeChunk(offset, size, origin, originoffset);
  this->__chunks.insert(it, c);
}

void				FileMapping::allocChunk(uint64_t offset, uint64_t size, class Node* origin, uint64_t originoffset)
{
  std::vector<chunk*>::iterator	it;
  uint32_t			idx;
  chunk				*c;
  bool				found;

  found = false;
  if (this->__chunks.size() == 0)
    it = this->__chunks.begin();
  else if (this->__chunks.size() == 1)
    {
      if (offset < this->__chunks[0]->offset)
	it = this->__chunks.begin();
      else if (offset > (this->__chunks[0]->offset + this->__chunks[0]->size - 1))
	it = this->__chunks.begin() + 1;
      else
	throw (std::string("provided offset is already mapped !"));
    }
  else
    {
      idx = this->__bsearch(offset, 0, this->__chunks.size() - 1, &found);
      if (found)
	throw (std::string("provided offset is already mapped !"));
      if (idx >= 1)
      	{
      	  if (idx == this->__chunks.size() - 1)
      	    {
      	      if (offset >= (this->__chunks[idx-1]->offset + this->__chunks[idx-1]->size))
      		it = this->__chunks.end();
      	      else
      		throw (std::string("provided offset is already mapped !"));
      	    }
      	  else if (offset >= (this->__chunks[idx-1]->offset + this->__chunks[idx-1]->size) && (offset + size) <= this->__chunks[idx+1]->offset)
      	    it = this->__chunks.begin() + idx + 1;
      	  else
      	    throw (std::string("provided offset is already mapped !"));
      	}
      else if ((offset + size) <= this->__chunks[idx]->offset)
	it = this->__chunks.begin();
      else
      	throw (std::string("provided offset is already mapped !"));
    }
  c = this->__makeChunk(offset, size, origin, originoffset);
  this->__chunks.insert(it, c);
}

void			FileMapping::push(uint64_t offset, uint64_t size, class Node* origin, uint64_t originoffset, bool force)
{
  if (force)
    this->forceAllocChunk(offset, size, origin, originoffset);
  else
    this->allocChunk(offset, size, origin, originoffset);
}


uint64_t	FileMapping::maxOffset()
{
  return this->__maxOffset;
}

}
