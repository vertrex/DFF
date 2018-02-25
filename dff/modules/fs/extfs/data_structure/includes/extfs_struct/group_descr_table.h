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

#ifndef __GROUP_DESCR_TABLE_H__
#define __GROUP_DESCR_TABLE_H__

#include "node.hpp"
#ifndef WIN32
	#include <stdint.h>
#elif _MSC_VER >= 1600
	#include <stdint.h>
#else
	#include "wstdint.h"
#endif

#define EXT4_BG_INODE_UNINIT    0x0001 /* Inode table/bitmap not in use */
#define EXT4_BG_BLOCK_UNINIT    0x0002 /* Block bitmap not in use */
#define EXT4_BG_INODE_ZEROED    0x0004 /* On-disk itable initialized to zero */

typedef struct	__group_descr_table_s
{
  uint32_t	block_bitmap_addr;
  uint32_t	inode_bitmap_addr;
  uint32_t	inode_table_block_addr;
  uint16_t	unallocated_block_nbr;
  uint16_t      unallocated_inodes_nbr;
  uint16_t	dir_nbr;
  uint16_t	bg_flags;               /* EXT4_BG_flags (INODE_UNINIT, etc) */
  uint32_t	bg_reserved[2];         /* Likely block/inode bitmap checksum*/
  uint16_t	bg_itable_unused_lo;    /* Unused inodes count */
  uint16_t	bg_checksum;            /* crc16(sb_uuid+group+desc) */
}		group_descr_table_t;

typedef	struct	__group_descr_table_64_s
{
  uint32_t	block_bitmap_addr;
  uint32_t	inode_bitmap_addr;
  uint32_t      inode_table_block_addr;
  uint16_t	unallocated_block_nbr;
  uint16_t	unallocated_inodes_nbr;
  uint16_t	dir_nbr;
  uint16_t      bg_flags;               /* EXT4_BG_flags (INODE_UNINIT, etc) */
  uint32_t	bg_reserved[2];         /* Likely block/inode bitmap checksum*/
  uint16_t	bg_itable_unused_lo;    /* Unused inodes count */
  uint16_t	bg_checksum;            /* crc16(sb_uuid+group+desc) */
  uint32_t	bg_block_bitmap_hi;     /* Blocks bitmap block MSB */
  uint32_t	bg_inode_bitmap_hi;     /* Inodes bitmap block MSB */
  uint32_t	bg_inode_table_hi;      /* Inodes table block MSB */
  uint16_t	bg_free_blocks_count_hi;/* Free blocks count MSB */
  uint16_t      bg_free_inodes_count_hi;/* Free inodes count MSB */
  uint16_t      bg_used_dirs_count_hi;  /* Directories count MSB */
  uint16_t      bg_itable_unused_hi;    /* Unused inodes count MSB */
  uint32_t      bg_reserved2[3];
}		group_descr_table_64_t;


#endif
