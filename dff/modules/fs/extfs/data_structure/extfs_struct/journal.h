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

#ifndef __JOURNAL_H__
#define __JOURNAL_H__

typedef struct		__journal_standard_header
{
  uint32		signature; //0xC03B33998
  uint32		block_type;
  uint32		sequence_number;
}			journal_header;

typedef struct		__journal_superblock_v1
{
  journal_header	header;
  uint32		block_size;
  uint32		blocks_number;
  uint32		block_starts;
  uint32		first_transaction;
  uint32		block_first_transaction;
  uint32		error_number;
}			journal_superblock_v1;


typedef struct		__journal_superblock_v2_reminder
{
  uint32		compatible_features;
  uint32		incompatible_features;
  uint32		ro_compatible_features;
  uint32		journal_uuid[4];
  uint32		using_by_fs_nbr;
  uint32		superblock_copy;
  uint32		max_block_per_transaction;
  uint32		max_fs_block_per_transation;
  uint32		unused[44];
  uint32		ids_fs[48][4];
}			journal_v2_reminder;

typedef struct		__journal_superblock_v2
{
  journal_header	header;
  uint32		block_size;
  uint32		blocks_number;
  uint32		block_starts;
  uint32		first_transaction;
  uint32		block_first_transaction;
  uint32		error_number;
  journal_v2_reminder	end;
}			journal_superblock_v2;

union			journal_v1_v2
{
  journal_superblock_v1 journal_v1;
  journal_superblock_v2	journal_v2;
}			journal;

typedef	struct		__journal_descriptor_block_entries_s
{
  uint32		file_system_block;
  uint32		entry_flags;
  uint32			uuid[4];
}			block_entries;


typedef struct		__journal_revoke_block_s
{
  journal_header	header;
  uint32		size;
  uint32		*block_addr;
}			revoke_block;

enum	entry_flag
  {
    JOURNAL_BLOCK_ESCAPED = 0x01,
    SAME_UUID = 0x02,
    BLOCK_DELETED = 0x04,
    LAST_ENTRY_BLOCK
  };

enum	type_jounal_header
  {
    DESCRIPTOR_BLOCK = 1,
    COMMIT_BLOCK = 2,
    SUPERBLOCK_V1 = 3,
    SUPERBLOCK_V2 = 4,
    REVOKE_BLOCK = 5
  };

#endif
