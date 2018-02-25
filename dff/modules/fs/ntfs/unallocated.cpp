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
#include "filemapping.hpp"

#include "unallocated.hpp"
#include "bootsector.hpp"
#include "mftmanager.hpp"
#include "ntfs.hpp"
#include "mftnode.hpp"
#include "attributes/mftattributecontenttype.hpp"
#include "ntfsopt.hpp"

/**
 *  Unallocated Node
 */
Unallocated::Unallocated(NTFS* ntfs) : Node("FreeSpace", 0, NULL, ntfs), __ntfs(ntfs)
{
  this->__ranges = this->ranges();
  std::vector<Range>::const_iterator range = this->__ranges.begin();

  uint64_t size = 0;
  for (; range != this->__ranges.end(); ++range)
    size += (1 + (*range).end() - (*range).start()) * this->__ntfs->bootSectorNode()->clusterSize();
  this->setSize(size);
}

std::vector<Range> Unallocated::ranges(void)
{
  std::vector<Range> ranges;
  MFTEntryManager* mftManager = this->__ntfs->mftManager();
  if (mftManager == NULL)
    throw std::string("MFT Manager is null");

  MFTNode* bitmapNode = mftManager->node(6); //$BITMAP_FILE_ID
  if (!bitmapNode) //if no bitmap we carve all the disk ! (except boot sector to avoid infinite loop)
  {
    //if (this->__ntfs->bootSectorNode()->clusterSize() != 0)
      ranges.push_back(Range(1, this->__ntfs->opt()->fsNode()->size() / this->__ntfs->bootSectorNode()->clusterSize()));
    return (ranges);
  }

  std::vector<MFTAttribute*> attributes = bitmapNode->mftEntryNode()->findMFTAttributes($DATA);
  std::vector<MFTAttribute*>::iterator  attribute = attributes.begin();

  if (attributes.size() == 0)
    return (ranges); //return all disk as if no bitmap or we're sure disk is full ?

  MFTAttributeContent* content = (*attribute)->content();
  if (content) 
  {
    Bitmap* bitmap = static_cast<Bitmap*>(content);
    ranges = bitmap->unallocatedRanges();
    delete content;
  }
  for (; attribute != attributes.end(); ++attribute)
    delete (*attribute);

  return (ranges);
}

void    Unallocated::fileMapping(FileMapping* fm)
{
  std::vector<Range>::const_iterator range = this->__ranges.begin();
  uint64_t offset = 0;
  uint64_t clusterSize = this->__ntfs->bootSectorNode()->clusterSize();

  for (; range != this->__ranges.end(); ++range)
  {
    fm->push(offset , (1 + (*range).end() - (*range).start()) * clusterSize, this->__ntfs->fsNode(), (*range).start() * clusterSize);
    offset += (1 + (*range).end() - (*range).start()) * clusterSize;
  }
}
