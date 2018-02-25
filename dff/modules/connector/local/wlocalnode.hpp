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
 *  Christophe Malinge <cma@digital-forensic.org>
 */

#ifndef __WLOCALNODE_HPP__
#define __WLOCALNODE_HPP__

#include "node.hpp"
#include "vfile.hpp"

using namespace DFF;

class WLocalNode: public Node
{
private:
  DateTime*			wtimeToDateTime(FILETIME *);
public:
  std::string	originalPath;
  enum Type
    {
      FILE,
      DIR
    };
  WLocalNode(std::string, uint64_t, Node *, fso *, uint8_t, std::string);
  ~WLocalNode();
  Attributes		_attributes(void);
};

#endif
