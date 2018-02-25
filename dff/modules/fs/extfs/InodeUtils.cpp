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

#include "vfile.hpp"
#include "data_structure/includes/Inode.h"
#include "include/utils/InodeUtils.h"


InodeUtils::InodeUtils(const SuperBlock * SB, GroupDescriptor * GD)
{
  _SB = SB;
  _GD = GD;
}

InodeUtils::~InodeUtils()
{
}

uint64_t    InodeUtils::getSize(uint32_t l_size, uint32_t h_size,
                                bool large_file) const
{
  if (large_file)
    {
      uint64_t    size = h_size;
      return (size << 32) + l_size;
    }
  return l_size;
}

uint64_t    InodeUtils::getInodeByNumber(uint32_t inode_number)
{
  if (!inode_number || inode_number > _SB->inodesNumber())
    return 0;
  uint16_t  group = groupNumber(inode_number);
  uint64_t inode_table_addr = ((uint64_t)_GD->inode_table_block_addr(group))
    * _SB->block_size();
  uint64_t tmp = ((inode_number - 1) % _SB->inodes_in_group_number());
  return (uint64_t)inode_table_addr + (tmp * _SB->inodes_struct_size());
}

bool    InodeUtils::isAllocated(uint32_t inode_number, VFile * vfile)
{
  if (!inode_number || (inode_number > _SB->inodesNumber()))
    return false;
  uint16_t group = groupNumber(inode_number);
  uint64_t inode_bitmap_addr = ((uint64_t)_GD->inode_bitmap_addr(group))
    * _SB->block_size();

  uint64_t	bit_addr = ((uint64_t)inode_bitmap_addr) 
    + (inode_number - 1) / 8;
  uint8_t	bits;
  if (!vfile->seek(bit_addr + _SB->offset() - __BOOT_CODE_SIZE)
      || !vfile->read(&bits, sizeof(uint8_t)))
    return false;
  inode_number--;
  uint8_t tmp = inode_number % 8;
  return ((bits >> tmp) & 1);
}

uint16_t  InodeUtils::groupNumber(uint32_t inode_number)
{
  return (inode_number - 1) / _SB->inodes_in_group_number();
}

std::string     InodeUtils::allocationStatus(uint32_t inode_number,
                                             VFile * vfile)
{
  return isAllocated(inode_number, vfile) ?
     "Allocated" : "Not allocated";
}

std::string     InodeUtils::mode(uint16_t file_mode)
{
  std::string	access = "rwxrwxrwx";
  uint16_t	mode = 0x100;

  for (int i = 0; i < 9; ++i,  mode = (mode >> 1))
    access[i] = ((mode & file_mode) ? access[i] : '-');
  return access;
}

std::string     InodeUtils::uid_gid(uint16_t uid, uint16_t gid)
{
  std::string uid_gid;

  std::ostringstream uid_s;
  uid_s << uid;

  std::ostringstream gid_s;
  gid_s << gid;

  uid_gid = uid_s.str() + "/" + gid_s.str();
  return uid_gid;
}

std::string     InodeUtils::set_uid_gid(uint16_t file_mode)
{
  std::string     uidgid;

  if (file_mode & Inode::_ISUID)
    uidgid = " Yes / ";
  else
    uidgid = " No / ";

  if (file_mode & Inode::_ISGID)
    uidgid += "Yes";
  else
    uidgid += "No";
  return uidgid;
}

std::string     InodeUtils::type(uint16_t file_mode)
{
  switch (file_mode & __IFMT)
    {
    case __IFDIR :
      return "d";
    case __IFREG :
      return "-";
    case __IFLNK :
      return "l";
    case __IFBLK :
      return "b";
    case __IFIFO :
      return "p";
    case __IFCHR :
      return "c";
    case __IFSOCK :
      return "s";
    }
  return "?";
}

std::string	InodeUtils::type_mode(uint16_t file_mode)
{
  return type(file_mode) + mode(file_mode);
}	

const SuperBlock *  InodeUtils::SB() const
{
  return _SB;
}

GroupDescriptor *   InodeUtils::GD() const
{
  return _GD;
}
