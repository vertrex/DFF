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
 *  MOUNIER Jeremy <jmo@digital-forensic.org>
 *
 */

#ifndef __EXTENT_HPP__
#define __EXTENT_HPP__

#include "vmdk.hpp"

namespace DFF
{
class Node;
class VFile;
}

class	Extent
{
public:

  Extent(Node *nd, uint32_t id);
  ~Extent();

  int	readSparseHeader();
  int	createBackupHeader(int type);

  sparseExtentHeader	header;

  Node		*vmdk;
  VFile		*vfile;

  uint32_t	id;
  uint32_t	version;

  uint32_t	type;

  uint32_t	sectorsPerGDE;
  uint32_t	GDEntries;
  uint32_t	GTEntries;

  uint64_t	sectors;
  uint64_t	sectorsPerGrain;

  uint64_t	sectorGD;
  uint64_t	sectorRGD;

  uint64_t	overheadSectors;

  uint64_t	descriptorSector;
  uint64_t	descriptorSize;

  bool		footer;
  uint16_t	compression;

};

#endif
