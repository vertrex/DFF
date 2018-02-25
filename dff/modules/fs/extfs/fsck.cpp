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

#include "include/fsck.h"

Fsck::Fsck(inodes_t * inode, VFile * vfile, uint64_t addr)
{
  __inode = inode;
  __vfile = vfile;
  __addr = addr;
}

Fsck::~Fsck()
{
}

void	Fsck::run(Extfs * extfs, std::string name)
{
  Inode * inode = new Inode(extfs, extfs->SB(),
			    extfs->GD());
  uint64_t	size = 0, blk_addr;
  bool		large_file = extfs->SB()->useRoFeatures(SuperBlockStructure::_LARGE_FILE,
							extfs->SB()->ro_features_flags());
  inode->setInode(__inode);
  //  inode->read(__addr, __inode);
  inode->init();

  uint64_t	inode_size = inode->getSize(inode->lower_size(), large_file);

  while ((blk_addr = inode->nextBlock()))
    size += extfs->SB()->block_size();

  if (size < inode_size)
    std::cout << "the size of node " << name << " is wrong is:" << inode_size
	      << "\ts: " << size << std::endl;
  else if ((size - inode_size) >= extfs->SB()->block_size())
    {
      std::cout << "the block size of node " << name 
		<< " is wrong is: " << inode_size << "\ts: " <<size << std::endl;
      
    }
  delete inode;
}
