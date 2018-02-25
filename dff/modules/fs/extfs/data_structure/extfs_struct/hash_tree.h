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

#ifndef __HASH_TREE_HH__
#define __HASH_TREE_HH__

typedef	struct	__hash_tree_node_descriptor_header_s
{
  uint32	unused;
  uchar		hash_version;
  uchar		length;
  uchar		level_leaves;
  uchar		unused2;
}		hash_tree_header;

typedef struct	__hash_tree_node_descriptor_entries_s
{
  uint32	min_hash_value;
  uint32	block_addr;
}		hash_node_descriptor;

typedef struct __first_node_descriptor_entry
{
  uint16	max_nbr;
  uint16	current_nbr;
  uint32	block_addr;
}		first_node_entry;

#endif
