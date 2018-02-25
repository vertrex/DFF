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

#include <iostream>
#include "specialfile.hpp"


VirtualNode::VirtualNode(fso* fsobj) : Node("Virtual", 0, NULL, fsobj), __origin(NULL), __voffset(0)
{
}


VirtualNode::~VirtualNode()
{
}


void	VirtualNode::setContext(Node* origin, uint64_t voffset) throw (std::string)
{
  if (origin == NULL)
    throw std::string("VirtualNode: origin node is null");
  if (origin->size() < voffset)
    throw std::string("VirtualNode: origin node size is smaller than provided offset");
  this->__origin = origin;
  this->__voffset = voffset;
  this->setSize(this->__origin->size() - voffset);
}


void	VirtualNode::setContext(Node* origin, uint64_t voffset, uint64_t size) throw (std::string)
{
  this->setContext(origin, voffset);
  this->setSize(size);
}


void		VirtualNode::fileMapping(FileMapping* fm)
{
  //std::cout << "0 to " << this->size() << " mapped on "  << this->__origin->absolute() << " at " << this->__voffset << std::endl;
  fm->push(0, this->size(), this->__origin, this->__voffset);
}


Attributes	VirtualNode::_attributes(void)
{
  Attributes	attr;

  return attr;
}


SpecialFile::SpecialFile(std::string name, Node* parent, fso* fsobj) : Node(name, 0, parent, fsobj), __fork(NULL), __origin(NULL)
{
}


SpecialFile::~SpecialFile()
{
  delete this->__fork;
}


void		SpecialFile::setContext(ForkData* fork, Node* origin)
{
  this->__fork = fork;
  this->__origin = origin;
  this->setSize(this->__fork->logicalSize());
}


void		SpecialFile::fileMapping(FileMapping* fm)
{
  ExtentsList		extents;
  ExtentsList::iterator	it;
  uint64_t		coffset;
  
  coffset = 0;
  extents = this->__fork->extents();
  for (it = extents.begin(); it != extents.end(); it++)
    {
      if (coffset + (*it)->size() < this->__fork->logicalSize())
	{
	  fm->push(coffset, (*it)->size(), this->__origin, (*it)->startOffset());
	  coffset += (*it)->size();
	}
      else
	{
	  fm->push(coffset, this->__fork->logicalSize() - coffset, this->__origin, (*it)->startOffset());
	  coffset += this->__fork->logicalSize() - coffset;
	}
    }
  for (it = extents.begin(); it != extents.end(); it++)
    delete (*it);
  extents.clear();
}


Attributes	SpecialFile::_attributes(void)
{
  Attributes	attr;

  attr["logical size"] = new Variant(this->__fork->logicalSize());
  attr["total blocks"] = new Variant(this->__fork->totalBlocks());
  attr["allocated bytes"] = new Variant(this->__fork->allocatedBytes());
  if (this->__fork->slackSize() > 0)
    {
      attr["slack space size"] = new Variant(this->__fork->slackSize());
    }
  attr["Extents count"] = new Variant(this->__fork->extents().size());
  return attr;
}
