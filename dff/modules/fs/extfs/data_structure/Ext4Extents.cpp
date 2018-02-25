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
#include "vfile.hpp"
#include "filemapping.hpp"
#include "node.hpp"

#include "../extfs.hpp"
#include "includes/Ext4Extents.h"

Ext4Extents::Ext4Extents(FileMapping * file_mapping) 
  : __offset(0)
{
  this->__mapping = file_mapping;
  this->__c_size = 0;
}

Ext4Extents::~Ext4Extents()
{
}

std::pair<uint16_t, uint64_t>	Ext4Extents::extents(ext4_extent * extent)
{
  if (!extent)
    return std::make_pair(0, 0);
  return std::make_pair(extent->length, concat_uint16_32(extent->phys_blk_high,
							 extent->phys_blk_low));
}

uint64_t	Ext4Extents::next_level(ext4_extents_index * idx)
{
  if (!idx)
    return 0;
  return this->concat_uint16_32(idx->next_level_high, idx->next_level_low);
}

uint64_t	Ext4Extents::concat_uint16_32(uint16_t hi, uint32_t lo)
{
  uint64_t	tot = 0;

  tot = hi;
  tot <<= 32;
  tot += lo;
  return tot;
}

ext4_extents_header *	Ext4Extents::read_header(uint8_t * block)
{
  ext4_extents_header *	header = NULL;

  if (block)
  {
    header = (ext4_extents_header *)block;
    if (header->magic == 0xF30A)
      return header;
  }
  return NULL;
}

void			Ext4Extents::read_indexes(ext4_extents_header * header,
						  uint8_t * block)
{
  ext4_extents_index *	idx;
  uint64_t		addr;
  uint8_t *		current_block;
  ext4_extents_header *	current_header;

  if (!header)
    return ;
  if (header->magic != 0xF30A)
    return ;
  for (int i = 0; i < header->entries; ++i)
    {
      idx = (ext4_extents_index *)(block + i * sizeof(ext4_extents_index));
      addr = concat_uint16_32(idx->next_level_high,
			      idx->next_level_low) * ((uint64_t)__block_size);
      if (!(current_block = read_block(addr)))
	return ;
      current_header = (ext4_extents_header *)current_block;
      if (current_header->depth)
	read_indexes(current_header,
		     current_block + sizeof(ext4_extents_header));
      else
	read_extents(current_header,
		     current_block + sizeof(ext4_extents_header));
      delete current_block;
    }
}

void		Ext4Extents::read_extents(ext4_extents_header * header,
					  uint8_t * block)
{
  uint64_t	b_size;

  if (!header)
    return ;
  if (header->magic != 0xF30A)
    return ;
  for (int i = 0; i < header->entries; ++i)
    {
      ext4_extent * extent
	= (ext4_extent *)(block + i * sizeof(ext4_extent));
      std::pair<uint16_t, uint64_t> p = extents(extent);
      b_size = p.first * ((uint64_t)__block_size);
      if (b_size > __size)
	b_size = __size;
      else
	__size -= b_size;
      if (__mapping)
	__mapping->push(__offset, b_size, __node,
			p.second * ((uint64_t)__block_size)
			+ __inode->SB()->offset() - __BOOT_CODE_SIZE);
      else
	__extents_list.push_back(p);      
      __offset += (p.first * ((uint64_t)__block_size));
    }
}

uint8_t *	Ext4Extents::read_block(uint64_t addr)
{
  uint8_t *	array = NULL;  

  if (!addr)
    return array;
  array = (uint8_t *)operator new (__block_size);
  __extfs->v_seek_read(addr, array, __block_size);
  return array;
}

void		Ext4Extents::push_extended_blocks(Inode * inode)
  throw (vfsError)
{
  if (!inode)
    throw vfsError("Ext4Extents::push_extended_blocks() : inode is NULL.");
  __inode = inode;
  __size = inode->lower_size();
  __block_size = inode->SB()->block_size();
  __node = inode->extfs()->node();
  __extfs = inode->extfs();
  if (!inode->extent_header()->depth)
    read_extents(inode->extent_header(),
		 (uint8_t *)&inode->block_pointers()[3]);
  else
    read_indexes(inode->extent_header(),
		 (uint8_t *)&inode->block_pointers()[3]);
}

const std::list<std::pair<uint16_t, uint64_t> >
	Ext4Extents::extents_list() const
{
  return __extents_list;
}

uint64_t	Ext4Extents::calc_size(Inode * inode)
{
  if (!inode)
    throw vfsError("Ext4Extents::calc_size() : inode is NULL.");
  __inode = inode;
  __size = inode->lower_size();
  __block_size = inode->SB()->block_size();
  __node = inode->extfs()->node();
  __extfs = inode->extfs();
  if (!inode->extent_header())
    __c_size = 0;
  else if (!inode->extent_header()->depth)
    read_extents_x(inode->extent_header(),
		 (uint8_t *)&inode->block_pointers()[3]);
  else
    read_indexes(inode->extent_header(),
		 (uint8_t *)&inode->block_pointers()[3]);
  return __c_size;
}

void		Ext4Extents::read_extents_x(ext4_extents_header * header,
					    uint8_t * block)
{
  if (!header)
    return ;
  
 if (header->magic != 0xF30A)
    return ;

  for (int i = 0; i < header->entries; ++i)
    {
      ext4_extent * extent
	= (ext4_extent *)(block + i * sizeof(ext4_extent));
      std::pair<uint16_t, uint64_t> p = extents(extent);

      //b_size = p.first * ((uint64_t)__block_size);
      __extents_list.push_back(p);
      __c_size += (extent->length * __block_size);
      __offset += (p.first * ((uint64_t)__block_size));
    }
}
