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

#include "include/SymLink.h"

SymLink::SymLink(Extfs * extfs, const SuperBlock * SB, GroupDescriptor * GD)
  : Inode(extfs, SB, GD)
{
  __depth = 0;
}

SymLink::~SymLink()
{
}

std::string	SymLink::resolveAbsolutePath(const std::string & target,
					     Node * node)
{
  size_t	pos;		
  std::string	absolute_path = node->path();
  std::string	target_name;

  while ((pos = target.rfind("/")) != std::string::npos)
    {
      std::string tmp = target.substr(pos + 1, absolute_path.size() - 1);
      if (tmp == "..")
	absolute_path = absolute_path.substr(0, pos);
      else if (tmp == ".")
	continue ;
      else
	absolute_path += ("/" + tmp);
    }
  absolute_path += target;
  std::cout << "link path : " << absolute_path << std::endl;
  return absolute_path;
}

Node *	SymLink::find_target(std::string path, Extfs * extfs)
{
  if (__depth >= EXT4_LINK_MAX)
    return NULL;

  Node * node = VFS::Get().GetNode(path);
  if (!node)
    return NULL;
  else if (node->isFile())
    return node;
  else if (node->isLink())
    {
      path = resolveAbsolutePath(path, node);
      __depth++;
      return find_target(path, extfs);
    }
  return NULL;
}
