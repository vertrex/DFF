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

#ifndef __PARTNODE_HPP__
#define __PARTNODE_HPP__

#define PRIMARY		0x01
#define EXTENDED	0x02
#define	LOGICAL		0x04
#define HIDDEN		0x08
#define UNALLOCATED	0x10

#include "ipart.hpp"
#include "node.hpp"
#include "fso.hpp"

using namespace DFF;

class PartitionNode : public Node
{
private:
  uint64_t		__entry;
  uint8_t		__type;
  PartInterface*	__handler;
public:
  PartitionNode(std::string name, uint64_t size, Node* parent, fso* fsobj);
  ~PartitionNode();
  void				setCtx(PartInterface* handler, uint64_t entry, uint8_t type);
  virtual void			fileMapping(FileMapping* fm);
  virtual Attributes		_attributes(void);
  virtual const std::string	dataType();
  virtual std::string		icon();
};

#endif
