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

#ifndef __EXTFS_SUPER_BLOCK_HPP__
#define __EXTFS_SUPER_BLOCK_HPP__

#include "types.h"

#include "export.hpp"

PACK_START
typedef struct	__extfs_super_block_s
{
  uint32	inodes_number;	// number of inodes on the fs;
  uint32	blocks_number;	// number of blocks on the fs;
  uint32	r_blocks_number;
  uint32	u_blocks_number;
  uint32	u_inodes_number;
  uint32	first_block;
  uint32	block_size;
  uint32	fragment_size;
  uint32	block_in_groups_number;
  uint32	fragment_in_group_number;
  uint32	inodes_in_group_number;
  uint32	last_mount_time;
  uint32	last_written_time;
  uint16	current_mount_count;
  uint16	max_mount_count;
  uint16	signature;	// must be 0xef53
  uint16	fs_state;
  uint16	error_handling_method;
  uint16	minor_version;
  uint32	l_consistency_ct;
  uint32	consitency_forced_interval;
  uint32	creator_os;
  uint32	major_version;
  uint16	uid_reserved_block;
  uint16	gid_reserved_block;
  uint32	f_non_r_inodes;
  uint16	inodes_struct_size;
  uint16	current_block_group;
  uint32	compatible_feature_flags;
  uint32	incompatible_feature_flags;
  uint32	ro_features_flags;
  uchar		file_system_ID[16];
  uchar		volume_name[16];
  uchar		path_last_mount[64];
  uint32	algorithm_bitmap;
  uchar	        preallocate_blocks_files;
  uchar		preallocate_block_dir;
  uint16	unused;
  uchar		journal_id[16];
  uint32	journal_inode;
  uint32	journal_device;
  uint32	orphan_node_list;
  uint32	empty[197];
}		super_block_t_;
PACK_END

#endif

