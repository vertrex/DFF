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

#include "include/ExtfsSlackNode.hpp"
#include "data_structure/includes/Inode.h"
#include "include/utils/SuperblockStructure.h"
#include "data_structure/includes/Ext4Extents.h"

ExtfsSlackNode::ExtfsSlackNode(std::string name, uint64_t size, Node * parent,
			       Extfs * fsobj, uint64_t inode_addr) :
  Node(name, size, parent, fsobj)
{
  Inode *	inode = NULL;
  uint32_t	blk_addr;

  this->__inode_addr = inode_addr;
  this->__size = size;
  this->__extfs = fsobj;

  if ((inode = read_inode()))
    {
      size = 0;
      if (inode->flags() & 0x80000) // uses extents
	{
	  Ext4Extents * ext4 = new Ext4Extents(NULL);
	  try
	    {
	      size = ext4->calc_size(inode);
	    }
	  catch(vfsError & e)
	    {
	      std::cerr << "vfsError caught in OrphansInode::load() : "
			<< e.error << std::endl;
	      return ;
	    }
	}
      else
	{
	  while ((blk_addr = inode->nextBlock()))
	    size += __extfs->SB()->block_size();

	  bool large_files = __extfs->SB()->useRoFeatures(SuperBlockStructure::_LARGE_FILE,
							  __extfs->SB()->ro_features_flags());
	  uint64_t inode_size = inode->getSize(inode->lower_size(), large_files);

	  if (size > inode_size)
	    size -= inode_size;
	  else
	    size = 0;
	  
	}
      this->setSize(size);
      __size = size;
    }
  else
    {
      __size = 0;
      setSize(__size);
    }
}

ExtfsSlackNode::~ExtfsSlackNode()
{
}

void	ExtfsSlackNode::fileMapping(FileMapping * fm)
{
  Inode *	inode = NULL;
  uint64_t	size = 0, blk_addr = 0, inode_size = 0;
  uint64_t	block_size = __extfs->SB()->block_size();
  bool		large_files = false;
  uint32_t	count = 0;
  uint64_t      ooffset = __extfs->SB()->offset() - __BOOT_CODE_SIZE;

  if (!(inode = read_inode()))
    return ;

  large_files = __extfs->SB()->useRoFeatures(SuperBlockStructure::_LARGE_FILE,
					     __extfs->SB()->ro_features_flags());
  inode_size = inode->getSize(inode->lower_size(), inode->upper_size_dir_acl(),
			      large_files);
  large_files = false;
  while ((blk_addr = inode->nextBlock()))
    {      
      size += block_size;
      if (size > inode_size)
	{

	  if (!large_files)
	    {
	      fm->push(0, block_size - inode_size, __extfs->node(),
		       blk_addr * block_size + inode_size + ooffset);
	      large_files = true;
	    }
	  else
	    {
	      fm->push(count * block_size - inode_size, block_size, __extfs->node(),
		       blk_addr * block_size + ooffset);
	    }
	}
      ++count;
    }
}

Inode *	ExtfsSlackNode::read_inode()
{
  Inode	*	inode = NULL;
  inodes_t *	i = NULL;

  try
    {
      inode = new Inode(this->__extfs, this->__extfs->SB(),
			this->__extfs->GD());
      i = new inodes_t;
      inode->setInode(i);
      inode->read(__inode_addr, i);
      inode->init();
    }
  catch (vfsError & e)
    {
      std::cerr << "Exception caught in ExtfNode::_attributes() : "
		<< e.error << std::endl;
      delete i;
      delete inode;
      return NULL;
    }
  catch(std::exception & e)
    {
      std::cerr << "Not enought memory" << std::endl;
      delete i;
      delete inode;
      return NULL;
    }
  return inode;
}
