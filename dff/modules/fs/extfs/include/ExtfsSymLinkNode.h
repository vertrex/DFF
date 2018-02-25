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

#ifndef EXTFS_SYMLINK_NODE_H
#define EXTFS_SYMLINK_NODE_H

#include "node.hpp"
#include "../extfs.hpp"

class ExtfsSymLinkNode : public Node
{
public :
  ExtfsSymLinkNode(std::string name, uint64_t size, Node * parent, Extfs * fsobj,
		   uint64_t offset);
  ~ExtfsSymLinkNode();

  virtual void		fileMapping(FileMapping* fm);
  virtual Attributes	_attributes();

private :
  uint64_t	__offset;
  Extfs *	__extfs;
};

#endif
