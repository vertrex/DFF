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
 *  Solal Jacob <sja@digital-forensic.org>
 */

#ifndef __AFFNODE_HPP__
#define __AFFNODE_HPP__

#include "aff.hpp"
#include <iostream>

#include "node.hpp"

class AffNode : public DFF::Node
{
public:
  AffNode(std::string name, uint64_t size, DFF::Node* parent, class aff* fsobj, std::string originalPath, AFFILE* affFile);
  ~AffNode();
  int			        addSegmentAttribute(DFF::Attributes* vmap, AFFILE* af, const char* segname);
  std::string		        originalPath;
  AFFILE*                       affile;
  virtual DFF::Attributes	_attributes();
};
#endif
