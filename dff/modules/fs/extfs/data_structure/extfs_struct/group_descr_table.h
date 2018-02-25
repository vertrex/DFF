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

#include "export.hpp"

PACK_START
typedef struct	__group_descr_table_s
{
  uint32	block_bitmap_addr;
  uint32	inode_bitmap_addr;
  uint32	inode_table_block_addr;
  uint16	unallocated_block_nbr;
  uint16	unallocated_inodes_nbr;
  uint16	dir_nbr;
  uchar		unused[14];
}		group_descr_table_t;
PACK_END

#endif
