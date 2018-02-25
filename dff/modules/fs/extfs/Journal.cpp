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

#include <memory>

#include "vfile.hpp"

#include "include/Journal.h"
#include "include/JournalType.h"

Journal::Journal(Extfs * extfs, const SuperBlock * SB, GroupDescriptor * GD)
  : Inode(extfs, SB, GD), __J_SB(NULL), __J_V2_reminder(NULL)
{
  __inode = NULL;
  __inode = (inodes_t *)operator new (sizeof(inodes_t));
}

Journal::~Journal()
{
  delete this->__J_SB;
  delete this->__J_V2_reminder;
  delete __inode;
}

bool	Journal::init()
{
  uint8_t *	read_array = NULL;

  if (!_SB->journal_inode())
    return false;

  /* get the inode address and read it */
  uint64_t addr = getInodeByNumber(_SB->journal_inode());
  _extfs->v_seek_read(addr, (void *)__inode, sizeof(inodes_t));

  /* got to journal first block and read it */
  uint64_t journal_addr = nextBlock();
  journal_addr *= _SB->block_size();
  read_array = (uint8_t *)operator new(sizeof(journal_superblock));
  _extfs->v_seek_read(journal_addr, (void *)read_array,
		      sizeof(journal_superblock));
  __J_SB = (journal_superblock *)read_array;

  /* if there is a reminder, read it */
  if (__J_SB->header.block_type == Journal::__SB_V2)
    {
      read_array = (uint8_t *)operator new(sizeof(journal_v2_reminder));
      _extfs->vfile()->read((void *)read_array, sizeof(journal_v2_reminder));
      __J_V2_reminder = (journal_v2_reminder *)read_array;
    }
  caching();
  return true;
}

void			Journal::caching()
{
  uint64_t		addr;
  JournalType<uint32_t>	j_block_size(__J_SB->block_size);
  uint8_t *		j_block;
  journal_header *      j_header;

  goToBlock(1);
  j_block = (uint8_t *)operator new (j_block_size.value() * sizeof(uint8_t));
  while ((addr = browseBlock(1, __J_SB->blocks_number)))
    {
      _extfs->v_seek_read(addr * _SB->block_size(), (void *)j_block,
			  j_block_size.value());
      j_header = ((journal_header *)j_block);

      JournalType<uint32_t> sig(j_header->signature),
	b_type(j_header->block_type);
      if ((sig.value() == __J_SIGNATURE)
	  && (b_type.value() == Journal::__DESCR_BLOCK))
	parseCommitBlocks(j_block + sizeof(journal_header),
			  j_block_size.value());
    }
  delete j_block;
}

void	Journal::parseCommitBlocks(uint8_t * j_block, uint32_t j_block_size)

{ 
  journal_block_entries *	j_block_descr;
  JournalType<uint32_t>		fs_block, flags;
  std::list<uint32_t>		b_list;

  for (uint32_t offset = 0;
       offset <= (j_block_size - sizeof(journal_header)
		  - sizeof(journal_block_entries));)
    {
      j_block_descr = ((journal_block_entries *)(j_block + offset));
      fs_block.setValue(j_block_descr->file_system_block);
      flags.setValue(j_block_descr->entry_flags);
      b_list.push_back(fs_block.value());
      offset += sizeof(journal_block_entries);
      if (!(flags.value() & 0x02))
	  offset += (4 * sizeof(uint32_t));      
    }
  getBlocksAddr(b_list);
}

void	Journal::getBlocksAddr(const std::list<uint32_t> & b_list)
{
  std::list<uint32_t>::const_iterator it;
  std::map<uint32_t, std::vector<uint64_t> >::iterator c_it;
  uint64_t	addr;

  for (it = b_list.begin(); it != b_list.end(); it++)
    if (*it)
      {
	if ((addr = nextBlock()))
	  {
	    _extfs->vfile()->seek(addr);
	    c_it = __j_cache.find(*it);
	    if (c_it == __j_cache.end())
	      {
		std::vector<uint64_t> tmp;
		tmp.push_back(addr);
		__j_cache.insert(std::make_pair(*it, tmp));
	      }
	    else
	      (*c_it).second.push_back(addr);
	  }
      }
}

const   std::map<uint32_t, std::vector<uint64_t> > &
	Journal::journal_cache() const
{
  return __j_cache;
}


const journal_superblock *    Journal::j_super_block() const
{
  return this->__J_SB;
}
