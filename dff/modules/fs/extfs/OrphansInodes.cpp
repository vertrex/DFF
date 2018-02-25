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

#include <iostream>
#include <sstream>

#include "data_structure/includes/Inode.h"
#include "data_structure/includes/Ext4Extents.h"
#include "include/OrphansInodes.h"
#include "include/ExtfsRawDataNode.h"

OrphansInodes::OrphansInodes(TwoThreeTree * parsed_i_list)
{
  __i_list = parsed_i_list;
}

OrphansInodes::~OrphansInodes()
{
}

void		OrphansInodes::load(class Extfs * extfs)
{
  Inode *	inode = new Inode(extfs, extfs->SB(), extfs->GD());
  uint8_t *	tab = (uint8_t *)operator new(extfs->SB()->inodes_struct_size());
  inodes_t *	inodes_s = (inodes_t *)tab;

  inode->setInode(inodes_s);
  for (unsigned int i = extfs->SB()->f_non_r_inodes();
       i < extfs->SB()->inodesNumber(); ++i)
    {
      if (!__i_list->find(i))
	{
	  uint64_t		addr;
	  std::ostringstream	oss;

	  oss << i;
	  addr = inode->getInodeByNumber(i) + extfs->SB()->offset()
	    - __BOOT_CODE_SIZE;

	  extfs->vfile()->seek(addr);
	  extfs->vfile()->read(tab, extfs->SB()->inodes_struct_size());
	  inode->init();

	  if (inode->block_pointers()[0] 
	      || inode->simple_indirect_block_pointer()
	      || inode->double_indirect_block_pointer()
	      || inode->triple_indirect_block_pointer())
	    {
	      uint64_t	size = 0;

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
		for (unsigned int i = 0; i < 12; ++i)
		  if (inode->block_pointers()[i])
		    size += extfs->SB()->block_size();

	      if (size)
		{
		  ExtfsNode * node = NULL;
		  node = new ExtfsNode(oss.str() + std::string("_content"),
				       size, extfs->orphans(), extfs, addr,
				       false, extfs->addBlockPointers);
		  node->set_i_nb(i);
		}
	    }
	  if (extfs->SB()->inodes_struct_size() > sizeof(inodes_t))
	    {
	      __inode_reminder_t * i_reminder 
		= (__inode_reminder_t *)((uint8_t*)tab + sizeof(inodes_t));

	      if (i_reminder->padding)
		new ExtfsRawDataNode(oss.str(),
				     extfs->SB()->inodes_struct_size(),
				     extfs->orphans(), extfs, addr);
	      else if (inode->unused2() || inode->unused3())
		new ExtfsRawDataNode(oss.str(),
				 extfs->SB()->inodes_struct_size(),
				 extfs->orphans(), extfs, addr);
	      else
		for (unsigned int j = sizeof(__inode_reminder_t)
		       + sizeof(inodes_t); j < extfs->SB()->inodes_struct_size();
		     ++j)
		  if (tab[j])
		    {
		      new ExtfsRawDataNode(oss.str(),
					   extfs->SB()->inodes_struct_size(),
					   extfs->orphans(), extfs, addr);
		      break ;
		    }
	    }
	}
    }
}
