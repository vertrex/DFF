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


#include "link.hpp"

Link::Link(diskDescriptor *desc, int type, Node *vmdkroot)
{
  this->_descriptor = desc;
  this->_type = type;
  this->_vmdkroot = vmdkroot;

  this->_cid = this->_descriptor->getCID();
  this->_pcid = this->_descriptor->getPCID();

  if (this->_pcid == CID_NOPARENT)
    {
      this->_baseLink = true;
    }
  else
    this->_baseLink = false;
}

Link::~Link()
{
}


void	Link::setLinkStorageVolumeSize()
{

  this->_storageVolumeSize = 0;

  for( std::vector<Extent*>::iterator ext=this->_extents.begin(); ext!=this->_extents.end(); ++ext)
    {
      this->_storageVolumeSize += ((*ext)->sectors * SECTOR_SIZE);
    }
}

int	Link::listExtents()
{
  std::list<std::string>	extnames;

  extnames = this->_descriptor->getExtentNames();
  Node *parent = this->_vmdkroot->parent();
  std::vector<Node *>next = parent->children();

  for( std::list<std::string>::iterator name=extnames.begin(); name!=extnames.end(); ++name)
    {
      for( std::vector<Node*>::iterator in=next.begin(); in!=next.end(); ++in)
	{
	  if ((*name) == (*in)->name())
	    {
	      addExtent((*in));
	    }
	}
    }
 
  if (this->_extents.size() == extnames.size())
    {
      this->setLinkStorageVolumeSize();
      return 1;
    }
  else
    return -1;

}

int	Link::addExtent(Node *vmdk)
{
  uint32_t id;

  id = this->_extents.size();

  Extent *ext = new Extent(vmdk, id);
  this->_extents.push_back(ext);

  return 1;
}

bool	Link::isBase()
{
  return this->_baseLink;
}


uint64_t	Link::volumeSize()
{
  return this->_storageVolumeSize;
}

std::string		Link::getCID()
{
  return this->_cid;
}

std::string		Link::getPCID()
{
  return this->_pcid;
}

std::vector<Extent*>		Link::getExtents()
{
  return this->_extents;
}
