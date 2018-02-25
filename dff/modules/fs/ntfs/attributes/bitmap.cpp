/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *  
 * See http: *www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 * 
 * Author(s):
 *  Solal Jacob <sja@digital-forensic.org>
 */
#include "vfile.hpp"

#include "bitmap.hpp"
#include "mftattribute.hpp"

Range::Range(uint64_t start, uint64_t end) : __start(start), __end(end)
{
}

uint64_t Range::start(void) const
{
  return (this->__start);
}

uint64_t Range::end(void) const
{
  return (this->__end);
}

Bitmap::Bitmap(MFTAttribute* mftAttribute) : MFTAttributeContent(mftAttribute)
{
}

MFTAttributeContent*	Bitmap::create(MFTAttribute*	mftAttribute)
{
  return (new Bitmap(mftAttribute));
}

Bitmap::~Bitmap()
{
}

/** 
 *  Return a vector of unallocated cluster offset range 
 *  (merge two consecutive unallocated cluster)
 */
std::vector<Range>      Bitmap::unallocatedRanges(void)
{
  std::vector<Range> unallocated;

  uint8_t* bitmap = new uint8_t[this->size()];
  VFile* vfile = this->open();
  vfile->read(bitmap, this->size());
  delete vfile;
 
  uint64_t clusterStart = 0;
  uint64_t clusterEnd = 0;
  uint64_t currentCluster = 0;

  for (uint64_t index = 0; index < this->size(); ++index) 
  {
    uint8_t byte = *(bitmap + index);
    for (uint8_t i = 0; i < 8; ++i, ++currentCluster)
    {
      if ((byte >> i) & 1)
      {
        if (clusterStart)
        {
          unallocated.push_back(Range(clusterStart, clusterEnd));
          clusterStart = 0;
          clusterEnd = 0;
        }
      }
      else
      {
        if (clusterStart == 0)
          clusterStart = currentCluster;  
        clusterEnd = currentCluster;
      }
    }
  }
  delete[] bitmap;
  return (unallocated);
}

const std::string       Bitmap::typeName(void) const
{
  return (std::string("$BITMAP"));
}
Attributes	Bitmap::_attributes(void)
{
  Attributes	attrs;

  MAP_ATTR("Attributes", MFTAttributeContent::_attributes())
  return (attrs);
}
