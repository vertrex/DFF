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

#ifndef WIN32
	#include <stdint.h>
#elif _MSC_VER >= 1600
	#include <stdint.h>
#else
	#include "wstdint.h"
#endif


/*! \def __J_SIGNATURE
    \brief The journal block signature.
*/
#define		__J_SIGNATURE   (0xC03B3998)

typedef struct		__journal_standard_header_s
{
  uint32_t		signature; //0xC03B33998
  uint32_t		block_type;
  uint32_t		sequence_number;
}			journal_header;

typedef struct		__journal_superblock_v1_s
{
  journal_header	header;
  uint32_t		block_size;
  uint32_t		blocks_number;
  uint32_t		block_starts;
  uint32_t		first_transaction;
  uint32_t		block_first_transaction;
  uint32_t		error_number;
}			journal_superblock;

typedef struct		__journal_superblock_v2_reminder_s
{
  uint32_t		compatible_features;
  uint32_t		incompatible_features;
  uint32_t		ro_compatible_features;
  uint32_t		journal_uuid[4];
  uint32_t		using_by_fs_nbr;
  uint32_t		superblock_copy;
  uint32_t		max_block_per_transaction;
  uint32_t		max_fs_block_per_transation;
  uint32_t		unused[44];
  uint32_t		ids_fs[48][4];
}		        journal_v2_reminder;

typedef	struct		__journal_descriptor_block_entries_s
{
  uint32_t		file_system_block;
  uint32_t		entry_flags;
}		        journal_block_entries;

typedef struct		__journal_revoke_block_s
{
  journal_header	header;
  uint32_t		size;
  uint32_t *		block_addr;
}		        journal_revoke_block;

#endif
