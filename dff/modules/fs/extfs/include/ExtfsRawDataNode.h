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
 *  Romain Bertholon <rbe@digital-forensic.org>
 *
 */

#ifndef EXTFS_RAW_DATA_NODE
#define EXTFS_RAW_DATA_NODE

#include "node.hpp"

class	ExtfsRawDataNode : public Node
{
public:
  ExtfsRawDataNode(std::string name, uint64_t size, Node * parent, Extfs * fsobj,
		   uint64_t offset);
  ~ExtfsRawDataNode();
  virtual void	fileMapping(FileMapping* fm);


private:
  uint64_t	__offset;
  Node *	__node;
};

#endif
