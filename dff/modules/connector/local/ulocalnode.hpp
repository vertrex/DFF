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

#ifndef __ULOCALNODE_HPP__
#define __ULOCALNODE_HPP__

#include "local.hpp"
#include "node.hpp"

namespace DFF
{
  class  DateTime;
}

using namespace DFF;

class ULocalNode: public Node
{
private:
  struct stat*		localStat(void);
  DateTime*		utimeToDateTime(time_t* t1);
public:
  std::string           originalPath;
  enum Type
  {
    FILE,
    DIR
  };
  ULocalNode(std::string name, uint64_t size, Node* parent, class local* fsobj, uint8_t type, std::string origPath);
  virtual Attributes	_attributes();
  ~ULocalNode();
};

#endif
