/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2014 ArxSys
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
 *  Frederic Baguelin <fba@digital-forensic.org>
 */

#ifndef __HFSP_EXTENTS_HPP__
#define __HFSP_EXTENTS_HPP__

#include <iostream>
#include <stdint.h>
#include <vector>

#include "export.hpp"

#include "endian.hpp"


PACK_START
typedef struct	s_hfs_extent_descriptor
{
  uint16_t	startBlock;
  uint16_t	blockCount;  
}		hfs_extent;
PACK_END


PACK_START
typedef struct	s_hfsp_extent_descriptor
{
  uint32_t	startBlock;
  uint32_t	blockCount;  
}		hfsp_extent;
PACK_END


class Extent
{
private:
  uint64_t	__startBlock;
  uint64_t	__blockCount;
  uint64_t	__blockSize;
public:
  Extent(hfs_extent ext, uint64_t block_size);
  Extent(hfsp_extent ext, uint64_t block_size);
  ~Extent();
  uint64_t	startBlock();
  uint64_t	startOffset();
  uint64_t	blockCount();
  uint64_t	size();
  void		dump(std::string tab);
};

typedef std::vector<Extent*> ExtentsList;

#endif
