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

#include "filemapping.hpp"

#include "extfs.hpp"
#include "include/ExtfsRawDataNode.h"

ExtfsRawDataNode::ExtfsRawDataNode(std::string name, uint64_t size, Node * parent,
				   Extfs * fsobj, uint64_t offset)
  : Node (name, size, parent, fsobj)
{
  __offset = offset;
  __node = fsobj->node();
}

ExtfsRawDataNode::~ExtfsRawDataNode()
{
}

void	ExtfsRawDataNode::fileMapping(FileMapping* fm)
{
  fm->push(0, size(), __node, __offset);
}

