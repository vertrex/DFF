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

#ifndef SYMLINK_H
#define SYMLINK_H

#define EXT4_LINK_MAX	65000

#include "../data_structure/includes/Inode.h"

class SymLink : public Inode
{

public:
  SymLink(Extfs *, const SuperBlock *, GroupDescriptor * GD = NULL);
  ~SymLink();
  
  std::string	resolveAbsolutePath(const std::string & path, Node * node);
  Node *	find_target(std::string path, Extfs * extfs);

private:
  uint32_t	__depth;
};

#endif // SYMLINK_H
