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

#ifndef __HFSP_FORK_HPP__
#define __HFSP_FORK_HPP__

#include <stdint.h>
#include <vector>

#include "export.hpp"

#include "extent.hpp"

PACK_START
typedef struct s_fork_data 
{
  uint64_t	logicalSize;
  uint32_t	clumpSize;
  uint32_t	totalBlocks;
  hfsp_extent	extents[8];
}		fork_data;
PACK_END

#include "extentstree.hpp"
#include "specialfile.hpp"

class ExtentsTree;

class ForkData
{
public:
  typedef enum
    {
      Data	= 0x00,
      Resource	= 0xFF
    } Type;

private:
  uint32_t		__fileId;
  uint64_t		__blockSize;
  uint64_t		__logicalSize;
  uint64_t		__totalBlocks;
  ForkData::Type	__type;
  class ExtentsTree*	__etree;
  std::vector<Extent* >	__extents;
  void			__clearExtents();
public:
  ForkData(uint32_t fileid, uint64_t blocksize); // special case for ExtentsTree file
  ForkData(uint32_t fileid, ExtentsTree* etree);
  ~ForkData();
  void		process(ExtentsList initial, uint64_t logicalSize, ForkData::Type type) throw (std::string);
  void		dump(std::string tab);
  uint64_t	logicalSize();
  uint32_t	totalBlocks();
  uint64_t	allocatedBytes();
  uint64_t	slackSize();
  Extent*	getExtent(uint32_t id);
  ExtentsList	extents();
};


#endif
