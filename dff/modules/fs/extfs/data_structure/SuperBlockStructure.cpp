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

#include "includes/SuperBlock.h"

SuperBlockStructure::SuperBlockStructure()
{
  try
    {
      this->__sb_array = (uint8_t *)operator new(SUPER_BLOCK_SIZE);
    }
  catch(std::exception)
    {
      throw ;
    }
  this->_super_block = (super_block_t_ *)this->__sb_array;
}

SuperBlockStructure::~SuperBlockStructure()
{
  delete _super_block;
}

super_block_t_ *  SuperBlockStructure::getSuperBlock() const
{
  return _super_block;
}

uint32_t	SuperBlockStructure::inodesNumber() const
{
  return _super_block->inodes_number;
}

uint32_t	SuperBlockStructure::blocks_number() const
{
  return _super_block->blocks_number;
}

uint32_t	SuperBlockStructure::r_blocks_number() const
{
  return _super_block->r_blocks_number;
}

uint32_t	SuperBlockStructure::u_blocks_number() const
{
  return _super_block->u_blocks_number;
}

uint32_t	SuperBlockStructure::u_inodes_number() const
{
  return _super_block->u_inodes_number;
}

uint32_t	SuperBlockStructure::first_block() const
{
  return _super_block->first_block;
}

uint32_t	SuperBlockStructure::block_size() const
{
  uint32_t	blk_size;

  blk_size =  1024 << _super_block->block_size;
  if ((blk_size > MAX_BLK_SIZE) || (blk_size < 1024))
    throw vfsError("SuperBlockStructure::block_size() : invalid block size");
  return blk_size;
}

uint32_t	SuperBlockStructure::fragment_size() const
{
  return 1024 << _super_block->fragment_size;
}

uint32_t	SuperBlockStructure::block_in_groups_number() const
{
  return _super_block->block_in_groups_number;
}

uint32_t	SuperBlockStructure::fragment_in_group_number() const
{
  return _super_block->fragment_in_group_number;
}

uint32_t	SuperBlockStructure::inodes_in_group_number() const
{
  return _super_block->inodes_in_group_number;
}

uint32_t	SuperBlockStructure::last_mount_time() const
{
  return _super_block->last_mount_time;
}

uint32_t	SuperBlockStructure::last_written_time() const
{
  return _super_block->last_written_time;
}

uint16_t	SuperBlockStructure::current_mount_count() const
{
  return _super_block->current_mount_count;
}

uint16_t	SuperBlockStructure::max_mount_count() const
{
  return _super_block->max_mount_count;
}

uint16_t	SuperBlockStructure::signature() const // must be 0xef53
{
  return _super_block->signature;
}

uint16_t	SuperBlockStructure::fs_state() const
{
  return _super_block->fs_state;
}

uint16_t	SuperBlockStructure::error_handling_method() const
{
  return _super_block->error_handling_method;
}

uint16_t	SuperBlockStructure::minor_version() const
{
  return _super_block->minor_version;
}

uint32_t	SuperBlockStructure::l_consistency_ct() const
{
  return _super_block->l_consistency_ct;
}

uint32_t	SuperBlockStructure::consitency_forced_interval() const
{
  return _super_block->consitency_forced_interval;
}

uint32_t	SuperBlockStructure::creator_os() const
{
  return _super_block->creator_os;
}

uint32_t	SuperBlockStructure::major_version() const
{
  return _super_block->major_version;
}

uint16_t	SuperBlockStructure::uid_reserved_block() const
{
  return _super_block->uid_reserved_block;
}

uint16_t	SuperBlockStructure::gid_reserved_block() const
{
  return _super_block->gid_reserved_block;
}

uint32_t	SuperBlockStructure::f_non_r_inodes() const
{
  return _super_block->f_non_r_inodes;
}

uint16_t	SuperBlockStructure::inodes_struct_size() const
{
  return _super_block->inodes_struct_size;
}

uint16_t	SuperBlockStructure::current_block_group() const
{
  return _super_block->current_block_group;
}

uint32_t	SuperBlockStructure::compatible_feature_flags() const
{
  return _super_block->compatible_feature_flags;
}

uint32_t	SuperBlockStructure::incompatible_feature_flags() const
{
  return _super_block->incompatible_feature_flags;
}

uint32_t	SuperBlockStructure::ro_features_flags() const
{
  return _super_block->ro_features_flags;
}

const uint8_t*	SuperBlockStructure::file_system_ID() const
{
  return _super_block->file_system_ID;
}

const uint8_t*	SuperBlockStructure::volume_name() const
{
  return _super_block->volume_name;
}

const uint8_t*	SuperBlockStructure::path_last_mount() const
{
  return _super_block->path_last_mount;
}

uint32_t	SuperBlockStructure::algorithm_bitmap() const
{
  return _super_block->algorithm_bitmap;
}

uint8_t	        SuperBlockStructure::preallocate_blocks_files() const
{
  return _super_block->preallocate_blocks_files;
}

uint8_t		SuperBlockStructure::preallocate_block_dir() const
{
  return _super_block->preallocate_block_dir;
}

uint16_t	SuperBlockStructure::unused() const
{
  return _super_block->unused;
}

const uint8_t*	SuperBlockStructure::journal_id() const
{
  return _super_block->journal_id;
}

uint32_t	SuperBlockStructure::journal_inode() const
{
  return _super_block->journal_inode;
}

uint32_t	SuperBlockStructure::journal_device() const
{
  return _super_block->journal_device;
}

uint32_t	SuperBlockStructure::orphan_node_list() const
{
  return _super_block->orphan_node_list;
}

const uint32_t*	SuperBlockStructure::empty() const
{
  return _super_block->s_reserved;
}
