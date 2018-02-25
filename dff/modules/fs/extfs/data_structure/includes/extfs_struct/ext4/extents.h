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

#ifndef __EXTENTS_H__
#define __EXTENTS_H__

#include "node.hpp"
#ifndef WIN32
	#include <stdint.h>
#elif _MSC_VER >= 1600
	#include <stdint.h>
#else
	#include "wstdint.h"
#endif

  /*! \struct __ext4_extents_header_s
    \brief Extents header.
   */
typedef struct	__ext4_extents_header_s
{
  //! Magic : 0xF30A
  uint16_t	magic;

  //! Number of valid entries.
  uint16_t	entries;

  //! Max entry number.
  uint16_t	max_entries;

  //! Depth
  uint16_t	depth;

  //! Tree generation
  uint32_t	generation;
}		ext4_extents_header;

typedef struct	__ext4_extents_index_s
{
  uint32_t	block;
  uint32_t	next_level_low;
  uint16_t	next_level_high;
  uint16_t	unused;
}		ext4_extents_index;

typedef struct	__ext4_extent_s
{
  uint32_t	block;
  uint16_t	length;
  uint16_t	phys_blk_high;
  uint32_t	phys_blk_low;
}		ext4_extent;

#endif
