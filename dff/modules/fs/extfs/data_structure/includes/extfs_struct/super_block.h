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

#include "node.hpp"
#ifndef WIN32
	#include <stdint.h>
#elif _MSC_VER >= 1600
	#include <stdint.h>
#else
	#include "wstdint.h"
#endif


/*! \def SUPER_BLOCK_SIZE
    \brief Size of the superblock.

    The size is expressed in bytes.
*/
#define SUPER_BLOCK_SIZE    1024

/*! \def __SB_SIG
    \brief The superblock signature.

    Must be 0xEF53.
*/
#define __SB_SIG            0xEF53

/*! \def __BOOT_CODE_SIZE
    \brief The size of the boot code, located at the offset 0 of the file
    system.

    Should always be 1024 bytes.
*/
#define __BOOT_CODE_SIZE    1024

typedef struct	__extfs_super_block_s
{
  /*! \struct __extfs_super_block_s
    \brief The 'raw' structure of the super block.
    \sa SuperBlock
  */

  //! Inodes number on the file system.
  uint32_t	    inodes_number;

  //! Blocks number on the file system.
  uint32_t	    blocks_number;

  //! Reserved block number.
  uint32_t	    r_blocks_number;

  //! Unallocated block number.
  uint32_t	    u_blocks_number;

  //! Unallocated inodes number.
  uint32_t	    u_inodes_number; /* 16 */
  
  //! First data block.
  uint32_t	    first_block;

  //! Size of blocks.
  uint32_t	    block_size;

  //! Size of fragments.
  uint32_t	    fragment_size;

  //! Number of blocks per group.
  uint32_t	    block_in_groups_number;

  //! Number of fragments per groups.
  uint32_t	    fragment_in_group_number; /* 32 */

  //! Number of inodes per group.
  uint32_t	    inodes_in_group_number;

  //! Last mount time.
  uint32_t	    last_mount_time;

  //! Last written time.
  uint32_t	    last_written_time; 

  //! Current mount count.
  uint16_t	    current_mount_count;

  //! Maximum  mount number.
  uint16_t	    max_mount_count;

  //! Signature. Must be \b 0xEF53
  uint16_t	    signature;	// must be 0xef53 

  //! File system state.
  uint16_t	    fs_state;

  //! Error handling method.
  uint16_t	    error_handling_method;

  //! Version.
  uint16_t	    minor_version;

  //! Time of the last consistency check.
  uint32_t	    l_consistency_ct;

  //! Interval between consistency checks.
  uint32_t	    consitency_forced_interval;

  //! OS who created the file system.
  uint32_t	    creator_os;

  //! Version.
  uint32_t	    major_version;

  //! UID.
  uint16_t	    uid_reserved_block;

  //! GID.
  uint16_t	    gid_reserved_block;

  //! First non reserved inode number.
  uint32_t	    f_non_r_inodes;

  //! Size of an inode structure.
  uint16_t	    inodes_struct_size;

  //! Block group number (if we are in a superblock backup).
  uint16_t	    current_block_group;

  //! Compatible features.
  uint32_t	    compatible_feature_flags;

  //! Incompatible features.
  uint32_t	    incompatible_feature_flags;

  //! Read only features.
  uint32_t	    ro_features_flags;

  //! File system ID.
  uint8_t	    file_system_ID[16];

  //! Name of the volume.
  uint8_t	    volume_name[16];

  //! Path to where it was last mounted.
  uint8_t	    path_last_mount[64];

  //! Allocation algorithm.
  uint32_t	    algorithm_bitmap;

  //! Preallocation for file.
  uint8_t	    preallocate_blocks_files;

  //! Preallocation for directories.
  uint8_t	    preallocate_block_dir;

  //! Unused area.
  uint16_t	    unused;

  //! Journal ID.
  uint8_t	    journal_id[16];

  //! Journal inode (usually 8).
  uint32_t	    journal_inode;

  //! Journal device (feature).
  uint32_t	    journal_device;

  //! Orphan inode list number.
  uint32_t	    orphan_node_list;

  uint32_t  s_hash_seed[4];         /* HTREE hash seed */
  uint8_t   s_def_hash_version;     /* Default hash version to use */
  uint8_t   s_reserved_char_pad;
  uint16_t  s_desc_size;            /* size of group descriptor */
  /*100*/
  uint32_t  s_default_mount_opts;
  uint32_t  s_first_meta_bg;        /* First metablock block group */
  uint32_t  s_mkfs_time;            /* When the filesystem was created */
  uint32_t  s_jnl_blocks[17];       /* Backup of the journal inode */
  /* 64bit support valid if EXT4_FEATURE_COMPAT_64BIT */
  /*150*/
  uint32_t  s_blocks_count_hi;      /* Blocks count */
  uint32_t  s_r_blocks_count_hi;    /* Reserved blocks count */
  uint32_t  s_free_blocks_count_hi; /* Free blocks count */
  uint16_t  s_min_extra_isize;      /* All inodes have at least # bytes */
  uint16_t  s_want_extra_isize;     /* New inodes should reserve # bytes */
  uint32_t  s_flags;                /* Miscellaneous flags */
  uint16_t  s_raid_stride;          /* RAID stride */
  uint16_t  s_mmp_interval;         /* # seconds to wait in MMP checking */
  uint64_t  s_mmp_block;            /* Block for multi-mount protection */
  uint32_t  s_raid_stripe_width;    /* blocks on all data disks (N*stride)*/
  uint8_t   s_log_groups_per_flex;  /* FLEX_BG group size */
  uint8_t   s_reserved_char_pad2;
  uint16_t  s_reserved_pad;
  uint64_t  s_kbytes_written;       /* nr of lifetime kilobytes written */
  uint32_t  s_reserved[160];        /* Padding to the end of the block */
}	    super_block_t_;

#endif
