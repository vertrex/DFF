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

#ifndef EXTFS_SLACK_NODE_
# define EXTFS_SLACK_NODE_

#include <string>

#include "extfs.hpp"
#include "node.hpp"

class ExtfsSlackNode : public Node
{
public:
  ExtfsSlackNode(std::string name, uint64_t size, Node * parent, Extfs * fsobj, uint64_t inode_addr);
  ~ExtfsSlackNode();

  virtual void 	fileMapping(FileMapping* fm);

private:
  uint64_t	__inode_addr;
  uint64_t	__size;
  Extfs *	__extfs;
  Inode *	read_inode();
};

#endif /* EXTFS_SLACK_NODE_ */
