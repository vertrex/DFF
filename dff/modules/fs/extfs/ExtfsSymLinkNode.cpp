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
#include "include/ExtfsSymLinkNode.h"

ExtfsSymLinkNode::ExtfsSymLinkNode(std::string name, uint64_t size, Node * parent,
				   Extfs * fsobj, uint64_t offset)
  : Node(name, size, parent, fsobj)
{
  __offset = offset;
  __extfs = fsobj;
}

ExtfsSymLinkNode::~ExtfsSymLinkNode()
{
}

void	ExtfsSymLinkNode::fileMapping(FileMapping* fm)
{
  SymLink *	i_symlink = new SymLink(__extfs, __extfs->SB(), __extfs->GD());
  inodes_t	i;
  std::string	path;
  ExtfsNode *	n;

  if (!__offset)
    throw vfsError("Symbolic link size is NULL.");

  i_symlink->setInode(&i);
  try
    {
      i_symlink->read(__offset, &i);
      if (i_symlink->lower_size() <= 60)
	path.insert(0, (char *)&i_symlink->block_pointers()[0],
		    i_symlink->lower_size());	  
      else
	{
	  uint64_t blk = i_symlink->nextBlock() * __extfs->SB()->block_size();
	  uint8_t * array = (uint8_t *)operator new(__extfs->SB()->block_size());
	  __extfs->v_seek_read(blk, array, __extfs->SB()->block_size());	  
	  path.insert(0, (char *)array, i_symlink->lower_size());
	  delete array;
	}
      path = i_symlink->resolveAbsolutePath(path, this);
      Node *	node = i_symlink->find_target(path, __extfs);
      delete i_symlink;

      if (!node)
	throw vfsError("Node " + path + " does not exist.\n");

      n = dynamic_cast<ExtfsNode *>(node);
      
      if (!n)
	throw vfsError("Node " + path + " does not exist (cast).\n");
      this->setSize(n->size());
      n->fileMapping(fm);
    }
  catch (vfsError & e)
    {
      std::cerr << "vfsError exception caught in ExtfsSymLinkNode::fileMapping() : "
		<< e.error << std::endl;
      throw ;
    }
  catch (std::exception & e)
    {
      std::cerr << "ExtfsSymLinkNode::fileMapping() : std::exception caught : "
		<< e.what() << std::endl;
    }
}

Attributes	ExtfsSymLinkNode::_attributes()
{
  Attributes attr;
  return attr;
}
