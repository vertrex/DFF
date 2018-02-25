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

#include "partnode.hpp"

PartitionNode::PartitionNode(std::string name, uint64_t size, Node* parent, fso* fsobj):  Node(name, size, parent, fsobj), __entry(), __type(0), __handler(NULL)
{
}

PartitionNode::~PartitionNode()
{
}

const std::string	PartitionNode::dataType()
{
  if (this->__type == UNALLOCATED)
    return std::string("partition/unallocated");
  else if (this->__entry == 0)
    return std::string("partition/unknown");
  else
    return Node::dataType();
}

void	PartitionNode::fileMapping(FileMapping* fm)
{
  this->__handler->mapping(fm, this->__entry, this->__type);
}

Attributes	PartitionNode::_attributes(void)
{
  return this->__handler->entryAttributes(this->__entry, this->__type);
}

void	PartitionNode::setCtx(PartInterface* handler, uint64_t entry, uint8_t type)
{
  this->__handler = handler;
  this->__entry = entry;
  this->__type = type;
}

std::string	PartitionNode::icon(void)
{
  if (this->__type == UNALLOCATED)
    return (std::string(":disksfilesystemsdeleted"));
  else
    return (std::string(":disksfilesystems"));
}	
