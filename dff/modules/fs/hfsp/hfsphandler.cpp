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


#include "hfshandlers.hpp"


HfspHandler::HfspHandler() : __allocationNode(NULL), __allocationFile(NULL)
{
}


HfspHandler::~HfspHandler()
{
}


void			HfspHandler::process(Node* origin, uint64_t offset, fso* fsobj) throw (std::string)
{
  this->setOrigin(origin, offset);
  this->setFsObject(fsobj);
  this->_createEtree();
  this->__createAllocation();
  this->_createCatalog();
}


void			HfspHandler::__createAllocation() throw (std::string)
{
  ForkData*		fork;
  VolumeHeader*		vheader;

  if ((vheader = dynamic_cast<VolumeHeader* >(this->_volumeInformation)) == NULL)
    throw std::string("Cannot get volume header on this HFS Volume");
  this->__allocationNode = new SpecialFile("$AllocationFile", this->_mountPoint, this->_fsobj);
  fork = new ForkData(6, this->_extentsTree);
  fork->process(vheader->allocationExtents(), vheader->allocationSize(), ForkData::Data);
  this->__allocationNode->setContext(fork, this->_origin);
  this->__allocationFile = new AllocationFile();
  this->__allocationFile->setHandler(this);
  this->__allocationFile->process(this->__allocationNode, 0, this->_volumeInformation->totalBlocks());
}


std::list<uint64_t>		HfspHandler::detetedEntries()
{
  std::list<uint64_t>		deleted;
  
  return deleted;
}


std::list<uint64_t>		HfspHandler::orphanEntries()
{
  std::list<uint64_t>		orphaned;

  return orphaned;
}


std::list<Node*>		HfspHandler::listFiles(uint64_t uid)
{
  std::list<Node*>		files;
  
  return files;
}


std::list<std::string>		HfspHandler::listNames(uint64_t uid)
{
  std::list<std::string>	names;
  
  return names;
}


Node*				HfspHandler::unallocatedSpace()
{
  return NULL;
}


Node*				HfspHandler::freeSpace()
{
  return NULL;
}


Node*				HfspHandler::slackSpace()
{
  return NULL;
}


void				HfspHandler::report()
{
}
