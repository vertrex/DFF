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

#include "include/utils/InodeStructure.h"

InodeStructure::InodeStructure()
{
  this->__inode = NULL;
  this->__inode_array = NULL;
}

InodeStructure::~InodeStructure()
{
}

const inodes_t *    InodeStructure::inode() const
{
  return this->__inode;
}

const uint8_t *	InodeStructure::InodeArray() const
{
  return !this->__inode_array ? NULL : this->__inode_array;
}

void		InodeStructure::setInode(const inodes_t * inode)
{
  this->__inode = inode;
}

uint16_t	InodeStructure::file_mode() const
{
  return !this->__inode ? 0 :  this->__inode->file_mode;
}

uint16_t	InodeStructure::lower_uid() const
{
  return !this->__inode ? 0 :  this->__inode->lower_uid;
}

uint32_t	InodeStructure::lower_size() const
{
  return !this->__inode ? 0 :  this->__inode->lower_size;
}

uint32_t	InodeStructure::access_time() const
{
  return !this->__inode ? 0 :  this->__inode->access_time;
}

uint32_t	InodeStructure::change_time() const
{
  return !this->__inode ? 0 :  this->__inode->change_time;
}

uint32_t	InodeStructure::modif_time() const
{
  return !this->__inode ? 0 :  this->__inode->modif_time;
}

uint32_t	InodeStructure::delete_time() const
{
  return !this->__inode ? 0 :  this->__inode->delete_time;
}

uint16_t	InodeStructure::lower_gid() const
{
  return !this->__inode ? 0 :  this->__inode->lower_gid;
}

uint16_t	InodeStructure::link_coun() const
{
  return !this->__inode ? 0 :  this->__inode->link_count;
}

uint32_t	InodeStructure::sector_count() const
{
  return !this->__inode ? 0 :  this->__inode->sector_count;
}

uint32_t	InodeStructure::flags() const
{
  return !this->__inode ? 0 :  this->__inode->flags;
}

uint32_t	InodeStructure::unused1() const
{
  return !this->__inode ? 0 :  this->__inode->unused1;
}

const uint32_t*	InodeStructure::block_pointers() const
{
  return !this->__inode ? NULL :  this->__inode->block_pointers;
}

uint32_t	InodeStructure::simple_indirect_block_pointer() const
{
  return !this->__inode ? 0 :  this->__inode->simple_indirect_block_pointer;
}

uint32_t	InodeStructure::double_indirect_block_pointer() const
{
  return !this->__inode ? 0 :  this->__inode->double_indirect_block_pointer;
}

uint32_t	InodeStructure::triple_indirect_block_pointer() const
{
  return !this->__inode ? 0 :  this->__inode->triple_indirect_block_pointer;
}

uint32_t	InodeStructure::generation_number_nfs() const
{
  return !this->__inode ? 0 :  this->__inode->generation_number_nfs;
}

uint32_t	InodeStructure::file_acl_ext_attr() const
{
  return !this->__inode ? 0 :  this->__inode->file_acl_ext_attr;
}

uint32_t	InodeStructure::upper_size_dir_acl() const
{
  return !this->__inode ? 0 :  this->__inode->upper_size_dir_acl;
}

uint32_t	InodeStructure::fragment_addr() const
{
  return !this->__inode ? 0 :  this->__inode->fragment_addr;
}

uint8_t	InodeStructure::fragment_index() const
{
  return !this->__inode ? 0 :  this->__inode->fragment_index;
}

uint8_t	InodeStructure::fragment_size() const
{
  return !this->__inode ? 0 :  this->__inode->fragment_size;
}

uint16_t	InodeStructure::unused2() const
{
  return !this->__inode ? 0 :  this->__inode->unused2;
}

uint16_t	InodeStructure::upper_uid() const
{
  return !this->__inode ? 0 :  this->__inode->upper_uid;
}

uint16_t	InodeStructure::upper_gid() const
{
  return !this->__inode ? 0 :  this->__inode->upper_gid;
}

uint32_t	InodeStructure::unused3() const
{
  return !this->__inode ? 0 :  this->__inode->unused3;
}
