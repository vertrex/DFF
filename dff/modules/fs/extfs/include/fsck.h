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

#ifndef __FSCK_HPP__
# define __FSCK_HPP__

#include <string>

#include "vfs.hpp"
#include "data_structure/includes/Inode.h"

class	Fsck
{
  /*
    \class Fsck
   
    \brief Verify that the size of inode matches the number of occupied blocks.
  */

 public:
  Fsck(inodes_t * inode, VFile * vfile, uint64_t addr);
  ~Fsck();

  //! run the checks
  void	run(class Extfs * extfs, std::string name);

 private:
  VFile	*	__vfile;
  inodes_t *	__inode;
  uint64_t	__addr;
};

#endif /* __FSCK_HPP__  */
