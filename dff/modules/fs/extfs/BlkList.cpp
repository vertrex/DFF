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

#include <sstream>

#include "include/BlkList.h"

BlkList::BlkList(GroupDescriptor * GD, SuperBlock * SB, VFile * vfile)
{
  __GD = GD;
  __SB = SB;
  __vfile = vfile;
  __end = 0;
}

BlkList::~BlkList()
{
}

void	BlkList::stat(const std::string & blk_list)
{
  size_t  pos;

  if ((pos = blk_list.find("-")) != std::string::npos)
    {
      std::string	tmp = blk_list.substr(pos + 1, blk_list.size() - 1);
      std::istringstream	iss(tmp);
      iss >> __end;
    }
  
  std::stringstream  iss;
  if (pos == std::string::npos)
    iss << blk_list;
  else
    iss << blk_list.substr(0, pos);
  iss >> __begin;
  if (__end && (__begin > __end))
    throw vfsError("BlkList::stat() : last block number > first.");
  if (__end == 0)
    __end = __begin;

  for (; __begin <= __end; ++__begin)
    {
      std::cout << __begin  << " | ";
      std::cout << 
	(blk_allocation_status(__begin) ? "Allocated | " : "Not allocated | ");
      std::cout << "Group : " << __group << " | ";
      std::cout << "Byte addr : " << std::dec << __bit_addr << std::hex 
		<< " (0x" << __bit_addr << ")" << " | ";
      std::cout << "Bit position : " << (int)__dec;
      std::cout << std::endl;
    }
}

bool	BlkList::blk_allocation_status(uint64_t blk_nb)
{
  if ((blk_nb > __SB->blocks_number()))
    throw vfsError("InodeUtils::blk_allocation_status() : "
		   "block number out of range.");
  __group = blk_nb / __SB->block_in_groups_number();
  uint64_t blk_bitmap_addr = ((uint64_t)__GD->block_bitmap_addr(__group))
    * __SB->block_size();

  __bit_addr = ((uint64_t)blk_bitmap_addr) 
    + blk_nb / 8;
  uint8_t	bits;

  if (!__vfile->seek(__bit_addr)
      || !__vfile->read(&bits, sizeof(uint8_t)))
    return false;
  __dec = blk_nb % 8;
  return ((bits >> __dec) & 1);
}
