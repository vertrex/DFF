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
 *  Jeremy MOUNIER <jmo@digital-forensic.org>
 */

#include "exceptions.hpp"
#include "vmnode.hpp"
#include "filemapping.hpp"

VMNode::VMNode(std::string Name, uint64_t size, Node* parent, VMware* vm, Link *lnk): Node(Name, size, parent, vm)
{

  this->_vm = vm;
  this->_lnk = lnk;
  this->_cid = this->_lnk->getCID();
  this->_links = this->_vm->getLinksFromCID(this->_cid);
  this->setFile();
  this->_baseLink = this->getBaseLink();
}

VMNode::~VMNode()
{
}

Link	*VMNode::getBaseLink()
{
  for( std::list<Link*>::iterator lk=this->_links.begin(); lk!=this->_links.end(); ++lk)
    {
      if ((*lk)->isBase())
	return (*lk);
    }
  return NULL;
}


void VMNode::fileMapping(FileMapping *fmap)
{
  // Get extents from first Link
  std::vector<Extent*> extents = this->_baseLink->getExtents();
  // Get number of extents
  uint32_t	nextents = extents.size();
  uint32_t	curextent = 0;
  uint64_t	voffset = 0;
  uint64_t	vextoffset = 0;
  uint64_t	currentGDE = 0;
  int		mapcheck;
  // Parse All extents

  while (curextent < nextents)
    {
      currentGDE = 0;
      vextoffset = 0;
      while (currentGDE < extents[curextent]->GDEntries)
  	{	  
          mapcheck = this->mapGTGrains(currentGDE, curextent, fmap, &voffset, &vextoffset, extents[curextent]->GTEntries);
	  if (mapcheck) {
	    currentGDE++;
	    }
  	}
      curextent++;
    }
}

Link	*VMNode::getDeltaLink(uint64_t currentGDE, uint32_t currentGTE, uint32_t curextent)
{
  uint64_t	GTOffset;
  uint32_t	GTEntry;
  uint64_t	GDEOffset;

  for( std::list<Link*>::iterator lk=this->_links.begin(); lk!=this->_links.end(); ++lk)
    {
      std::vector<Extent*>	extents = (*lk)->getExtents();
      Extent	*ext = extents[curextent];

      GDEOffset = (ext->sectorRGD * SECTOR_SIZE) + (currentGDE * 4);

      GTOffset = this->getGTOffset(GDEOffset, ext);
      
      GTEntry = this->readGTEntry(GTOffset, currentGTE, ext);
      if (GTEntry != 0)
	{
	  return (*lk);
	}
    }
  return this->_baseLink;
}




uint32_t	VMNode::readGTEntry(uint64_t GTEOffset, uint32_t currentGTE, Extent *ext)
{
  uint32_t	GTEntry;

  try
    {
      ext->vfile->seek(GTEOffset + (currentGTE * 4));
      ext->vfile->read(&GTEntry, sizeof(unsigned int));
      
    }
  catch (envError & e)
    {
      std::cerr << "Error reading Entry : arg->get(\"parent\", &_node) failed." << std::endl;
      throw e;
    }
  return GTEntry;
}

//=========================
unsigned int* VMNode::mapGT(uint64_t GTOffset, Extent* ext)
{
  unsigned int* uintmap = new unsigned int[512]();

  try
    {
      ext->vfile->seek(GTOffset);
      ext->vfile->read(uintmap, 2048);
    }
  catch (envError & e)
    {
      std::cerr << "Error reading Entry : arg->get(\"parent\", &_node) failed." << std::endl;
      throw e;
    }
  return uintmap;
}

uint64_t	VMNode::getGTOffset(uint64_t GDEOffset, Extent* ext)
{
  uint64_t	GTOffset;
  uint32_t	GDEntry; // ok 
  
  try
    {
      ext->vfile->seek(GDEOffset);
      ext->vfile->read(&GDEntry, sizeof(unsigned int));
    }
  catch (envError & e)
    {
      std::cerr << "Error reading Entry : arg->get(\"parent\", &_node) failed." << std::endl;
      throw e;
    }
  GTOffset = GDEntry * SECTOR_SIZE;
  return GTOffset;

}


int VMNode::mapGTGrains(uint64_t currentGDE, uint32_t curextent, FileMapping *fm, uint64_t *voffset, uint64_t *vextoffset, uint64_t GTEntries)
{

  uint64_t	grainOffset;
  uint32_t	GTEntry;

  uint64_t	currentGTE = 0;
  uint64_t	GDEOffset;
  uint32_t	grainSize;
  uint64_t	GTOffset;
  unsigned int*	GTable;

  Link *dlink = this->getDeltaLink(currentGDE, currentGTE, curextent);
  std::vector<Extent *> extents = dlink->getExtents();
  Extent *ext = extents[curextent];
  grainSize = (ext->sectorsPerGrain * SECTOR_SIZE);
  GDEOffset = (ext->sectorRGD * SECTOR_SIZE) + (currentGDE * 4);
  GTOffset = this->getGTOffset(GDEOffset, ext);
  GTable = this->mapGT(GTOffset, ext);

  while (currentGTE < GTEntries)
    {
      if (*vextoffset < (ext->sectors * SECTOR_SIZE))
	{
	  GTEntry = GTable[currentGTE];//this->readGTEntry(GTOffset, currentGTE, ext);
	  if (GTEntry != 0)
	    {
	      grainOffset = (uint64_t)(GTEntry) * SECTOR_SIZE;
	      fm->push(*voffset, grainSize, ext->vmdk, grainOffset);
	    }
	  else
	    fm->push(*voffset, grainSize);
	  
	  *voffset += grainSize;
	  *vextoffset += grainSize;
	  currentGTE += 1;
	}
      else
	{
	  return 0;
	}
    }
  return 1;

}
