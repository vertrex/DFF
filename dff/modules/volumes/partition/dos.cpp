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

#include "dos.hpp"
#include "dostypes.hpp"
#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>

/*
 * ---------------------------------------------
 * Starting implementation of DosPartition class
 * ---------------------------------------------
*/

DosPartition::DosPartition() : PartInterface(), __logical(0), __primary(0), __extended(0), __hidden(0), __slot(1),
			       __allocated(), __unallocated(), __vfile(NULL), __ebr_base(0), __protective(false)
{
}

DosPartition::~DosPartition()
{
  if (this->__vfile != NULL)
    {
      try
	{
	  this->__vfile->close();
	  delete this->__vfile;
	}
      catch(vfsError e)
	{
	  std::cout << "Partition error while closing file" << e.error << std::endl;
	}
    }
}


bool    DosPartition::isProtective()
{
  return this->__protective;
}

bool	DosPartition::process(Node* origin, uint64_t offset, uint32_t sectsize, bool force) throw (vfsError)
{
  bool	ret;

  PartInterface::process(origin, offset, sectsize, force);
  ret = true;
  this->__slot = 1;
  this->__primary = 1;
  this->__hidden = 0;
  this->__logical = 1;
  this->__extended = 1;
  this->__vfile = this->_origin->open();
  try
    {
      this->__readMbr();
    }
  catch (vfsError err)
    {
      ret = false;
    }
  return ret;
}


void	DosPartition::makeNodes(Node* root, fso* fsobj)
{
  std::stringstream	ostr;
  metaiterator		mit;
  PartitionNode*	pnode;
  Node*			root_unalloc;
  uint64_t		size;

  this->__makeUnallocated();
  if (this->__allocated.size() > 0)
    {
      for (mit = this->__allocated.begin(); mit != this->__allocated.end(); mit++)
	{
	  if ((mit->second->type & EXTENDED) != EXTENDED)
	    {
	      ostr << "Partition " << mit->second->slot;
	      size = (uint64_t)mit->second->pte->total_blocks * this->_sectsize;
	      pnode = new PartitionNode(ostr.str(), size, root, fsobj);
	      pnode->setCtx(this, mit->first, mit->second->type);
	      ostr.str("");
	    }
	}
    }
  if (this->__unallocated.size() > 0)
    {
      root_unalloc = new Node("Unallocated", 0, root, fsobj);
      if (root_unalloc != NULL)
	{
	  for (mit = this->__unallocated.begin(); mit != this->__unallocated.end(); mit++)
	    {
	      ostr << mit->first << "s--" << mit->second->entry_offset - 1 << "s";
	      size = (mit->second->entry_offset - mit->first) * this->_sectsize;
	      pnode = new PartitionNode(ostr.str(), size, root_unalloc, fsobj);
	      pnode->setCtx(this, mit->first, UNALLOCATED);
	      ostr.str("");
	    }
	}
    }
}


Attributes		DosPartition::result()
{
  std::stringstream	ostr;
  metaiterator		mit;
  Attributes		metares;
  Attributes		rootext;
  Attributes		unallocres;
  Attributes		res;
  Variant*		vptr;

  for (mit = this->__allocated.begin(); mit != this->__allocated.end(); mit++)
    {
      if ((mit->second->type & EXTENDED) == EXTENDED)
	{
	  ostr.str("");
	  ostr << "Extended #" << mit->second->sslot;
	  if (mit->second->sslot > 1)
	    {
	      if ((vptr = new Variant(this->__entryAttributes(mit))) != NULL)
		metares[ostr.str()] = Variant_p(vptr);
	    }
	  else
	    rootext = this->__entryAttributes(mit);
	}
      else if ((mit->second->type & PRIMARY) == PRIMARY)
	{
	  ostr.str("");
	  ostr << "Primary #" << mit->second->sslot << " (effective slot #" << mit->second->slot << ")";
	  if ((vptr = new Variant(this->__entryAttributes(mit))) != NULL)
	    res[ostr.str()] = Variant_p(vptr);
	}
      else
	{
	  ostr.str("");
	  ostr << "Logical #" << mit->second->sslot << " (effective slot #" << mit->second->slot << ")";
	  if ((vptr = new Variant(this->__entryAttributes(mit))) != NULL)
	    rootext[ostr.str()] = Variant_p(vptr);
	}
    }
  for (mit = this->__unallocated.begin(); mit != this->__unallocated.end(); mit++)
    {
      ostr.str("");
      ostr << "Unallocated #" << mit->second->sslot;
      if ((vptr = new Variant(this->__entryAttributes(mit))) != NULL)
	unallocres[ostr.str()] = Variant_p(vptr);
    }
  if (metares.size() && ((vptr = new Variant(metares)) != NULL))
    res["Meta"] = Variant_p(vptr);
  if (unallocres.size() && ((vptr = new Variant(unallocres)) != NULL))
    res["Unalloc"] = Variant_p(vptr);
  if (rootext.size() && ((vptr = new Variant(rootext)) != NULL))
    res["Extended #1"] = Variant_p(vptr);
  return res;
}


Attributes	DosPartition::entryAttributes(uint64_t entry, uint8_t type)
{
  metaiterator		mit;
  Attributes		vmap;

  if ((type == UNALLOCATED) && ((mit = this->__unallocated.find(entry)) != this->__unallocated.end()))
    vmap = this->__entryAttributes(mit);
  else if ((type != UNALLOCATED) && ((mit = this->__allocated.find(entry)) != this->__allocated.end()))
    vmap = this->__entryAttributes(mit);
  return vmap;
}


void		DosPartition::mapping(FileMapping* fm, uint64_t entry, uint8_t type)
{
  metaiterator	mit;
  uint64_t	offset;
  uint64_t	size;
  uint64_t	tsize;
  bool		process;

  process = false;
  if ((type == UNALLOCATED) && ((mit = this->__unallocated.find(entry)) != this->__unallocated.end()))
    {
      offset = this->_offset + mit->first * this->_sectsize;
      size = mit->second->entry_offset * this->_sectsize;
      process = true;
    }
  else if ((type != UNALLOCATED) && ((mit = this->__allocated.find(entry)) != this->__allocated.end()))
    {
      offset = this->_offset + mit->first * this->_sectsize;
      size = (uint64_t)mit->second->pte->total_blocks * this->_sectsize;
      process = true;
    }
  if (process)
    {
      //XXX NEED CASE DUMP
      if (offset > this->_origin->size())
      	fm->push(0, size);
      //XXX NEED CASE DUMP
      else if (offset + size > this->_origin->size())
      	{
      	  tsize = this->_origin->size() - offset;
      	  fm->push(0, tsize, this->_origin, offset);
      	  fm->push(tsize, tsize - size);
      	}
      else
	fm->push(0, size, this->_origin, offset);
    }
}


uint32_t	DosPartition::entriesCount()
{
  metaiterator		mit;
  uint32_t		count;

  count = 0;
  for (mit = this->__allocated.begin(); mit != this->__allocated.end(); mit++)
    if ((mit->second->type & EXTENDED) != EXTENDED)
      ++count;
  return count;
}


uint64_t	DosPartition::lba(uint32_t which)
{
  metaiterator		mit;
  uint32_t		count;
  
  mit = this->__allocated.begin();
  if (which < this->__allocated.size())
    {
      count = 0;
      // XXX Test, test, test
      // enchance entry access ?
      while (count != which)
	{
	  mit++;
	  count++;
	}
      return mit->first / this->_sectsize;
    }
  else
    return (uint64_t)-1;
}


// Private methods implementation

dos_pte*	DosPartition::__toPte(uint8_t* buff)
{
  dos_pte*	pte;
  uint32_t	lba;
  uint32_t	total_blocks;

  memcpy(&lba, buff+8, 4);
  memcpy(&total_blocks, buff+12, 4);
  //XXX try to used CHS instead ! Need geometry
  if ((lba == 0) && (total_blocks == 0))
    return NULL;
  else
    {
      pte = new dos_pte;
      memcpy(pte, buff, 8);
      pte->lba = lba;
      pte->total_blocks = total_blocks;
      return pte;
    }
}


Attributes	DosPartition::__entryAttributes(metaiterator mit)
{
  Attributes		vmap;
  std::stringstream	ostr;

  if (mit->second->type == UNALLOCATED)
    {
      vmap["starting sector"] = new Variant(mit->first);
      vmap["ending sector"] = new Variant(mit->second->entry_offset - 1);
      vmap["total sectors"] = new Variant(mit->second->entry_offset - mit->first);
      ostr.str("");
      ostr << "Unallocated #" << mit->second->sslot;
      vmap["entry type"] = new Variant(ostr.str());
    }
  else
    {
      vmap["starting sector"] = new Variant(mit->first);
      vmap["ending sector"] = new Variant(mit->first + mit->second->pte->total_blocks - 1);
      vmap["total sectors"] = new Variant(mit->second->pte->total_blocks);
      if (mit->second->pte->status == 0x80)
	vmap["status"] = new Variant(std::string("bootable (0x80)"));
      else if (mit->second->pte->status == 0x00)
	vmap["status"] = new Variant(std::string("not bootable (0x00)"));
      else
	{
	  ostr << "invalid (0x" << std::setw(2) << std::setfill('0') << std::hex << (int)mit->second->pte->status << ")";
	  vmap["status"] = new Variant(ostr.str());
	  ostr.str("");
	}
      ostr.str("");
      if ((mit->second->type & PRIMARY) == PRIMARY)
	ostr << "Primary #";
      else if ((mit->second->type & LOGICAL) == LOGICAL)
	ostr << "Logical #";
      else if ((mit->second->type & EXTENDED) == EXTENDED)
	ostr << "Extended #";
      ostr << mit->second->sslot; 
      if ((mit->second->type & HIDDEN) == HIDDEN)
	ostr << " | Hidden";
      vmap["entry type"] = new Variant(ostr.str());
      ostr.str("");
      ostr << dos_partition_types[mit->second->pte->type] << " (0x" << std::setw(2) << std::setfill('0') << std::hex << (int)mit->second->pte->type << ")";
      vmap["partition type"] = new Variant(ostr.str());
      vmap["entry offset"] = new Variant(mit->second->entry_offset);
    }
  return vmap;
}


void	DosPartition::__makeUnallocated()
{
  std::map<uint64_t, metadatum*>::iterator	mit;
  metadatum*					meta;
  uint64_t					sidx;
  uint32_t					counter;

  sidx = 0;
  counter = 1;
  if (this->__allocated.size() > 0)
    {
      for (mit = this->__allocated.begin(); mit != this->__allocated.end(); mit++)
	{
	  if ((mit->second->type & EXTENDED) != EXTENDED)
	    {
	      if (mit->first > sidx)
		{
		  meta = new metadatum;
		  meta->pte = NULL;
		  meta->entry_offset = mit->first;
		  meta->type = UNALLOCATED;
		  meta->slot = (uint32_t)-1;
		  meta->sslot = counter++;
		  this->__unallocated[sidx] = meta;
		}
	      sidx = mit->first + mit->second->pte->total_blocks;
	    }
	}
      if ((this->_offset + (sidx * this->_sectsize)) < this->_origin->size())
	{
	  meta = new metadatum;
	  meta->pte = NULL;
	  meta->entry_offset = ((this->_origin->size() - this->_offset) / this->_sectsize) - 1;
	  meta->type = UNALLOCATED;
	  meta->sslot = counter++;
	  meta->slot = (uint32_t)-1;
	  this->__unallocated[sidx] = meta;
	}
    }
}

void		DosPartition::__readMbr() throw (vfsError)
{
  dos_partition_record	record;
  uint8_t		i;
  dos_pte*		pte;
  //uint32_t		disk_sig;
  Attributes		mbrattr;
  metadatum*		meta;

  this->__vfile->seek(this->_offset);
  if (this->__vfile->read(&record, sizeof(dos_partition_record)) == sizeof(dos_partition_record))
    {
      // XXX where is the best location to provide the following information ?
      // if (record.signature != 0xAA55)
      // 	mbrattr["signature"] = new Variant(std::string("Not setted"));
      // else
      // 	mbrattr["signature"] = new Variant(record.signature);
      // memcpy(&disk_sig, record.a.mbr.disk_signature, 4);
      // mbrattr["disk signature"] = new Variant(disk_sig);
      // this->__res["mbr"] = new Variant(mbrattr);
      for (i = 0; i != 4; i++)
	{
	  if ((pte = this->__toPte(record.partitions+(i*16))) != NULL)
	    {
	      uint64_t lba = pte->lba * this->_sectsize;
	      uint64_t size = pte->total_blocks * this->_sectsize;
	      if (((lba < this->_origin->size()) && ((lba + size) < this->_origin->size())) || this->_force)
		{
		  meta = new metadatum;
		  meta->pte = pte;
		  meta->entry_offset = this->_offset + 446 + i * 16;
		  if (pte->type == GPT_PROTECTIVE)
		    this->__protective = true;
		  if (IS_EXTENDED(pte->type))
		    {
		      meta->slot = (uint32_t)-1;
		      meta->sslot = this->__extended++;
		      meta->type = EXTENDED;
		      this->__ebr_base = pte->lba;
		      this->__readEbr(pte->lba);
		    }
		  else
		    {
		      meta->slot = this->__slot++;
		      meta->sslot = this->__primary++;
		      meta->type = PRIMARY;
		    }
		  this->__allocated[pte->lba] = meta;
		}
	      else
		delete pte;
	    }
	}
    }
}

void	DosPartition::__readEbr(uint64_t csector, uint64_t shift) throw (vfsError)
{
  dos_partition_record	record;
  uint8_t		i;
  dos_pte*		pte;
  uint64_t		offset;
  metadatum*		meta;

  offset = this->_offset + csector*this->_sectsize;
  if ((offset > this->_origin->size()) && !this->_force)
    return;
  this->__vfile->seek(offset);
  if (this->__vfile->read(&record, sizeof(dos_partition_record)) > 0)
    {
      for (i = 0; i != 4; i++)
	{
	  if ((pte = this->__toPte(record.partitions+(i*16))) != NULL)
	    {
	      uint64_t lba = pte->lba * this->_sectsize;
	      uint64_t size = pte->total_blocks * this->_sectsize;
	      if (((lba < this->_origin->size()) && ((lba + size) < this->_origin->size())) || this->_force)
		{
		  if (IS_EXTENDED(pte->type))
		    {
		      if ((this->__ebr_base + pte->lba) != csector)
			{
			  meta = new metadatum;
			  meta->pte = pte;
			  meta->entry_offset = offset + 446 + i * 16;
			  meta->slot = (uint32_t)-1;
			  meta->sslot = this->__extended++;
			  if (i > 2)
			    {
			      this->__hidden++;
			      meta->type = EXTENDED|HIDDEN;
			    }
			  else
			    meta->type = EXTENDED;
			  this->__allocated[this->__ebr_base + pte->lba] = meta;
			  this->__readEbr(this->__ebr_base + (uint64_t)(pte->lba), pte->lba);
			}
		      else
			;
		    }
		  else
		    {
		      meta = new metadatum;
		      meta->pte = pte;
		      meta->entry_offset = offset + 446 + i * 16;
		      meta->slot = this->__slot++;
		      meta->sslot = this->__logical++;
		      if (i > 2)
			{
			  this->__hidden++;
			  meta->type = LOGICAL|HIDDEN;
			}
		      else
			meta->type = LOGICAL;
		      this->__allocated[this->__ebr_base + shift + pte->lba] = meta;
		    }
		}
	      else
		delete pte;
	    }
	}
    }
}
