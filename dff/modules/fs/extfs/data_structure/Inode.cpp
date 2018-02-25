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

#include "includes/Inode.h"
#include "includes/GroupDescriptor.h"
#include "includes/Ext4Extents.h"
#include "../include/Directory.h"
#include "../extfs.hpp"
#include "../include/utils/InodeUtils.h"
#include "../include/ExtfsRawDataNode.h"

Inode::Inode(Extfs * extfs, const SuperBlock * SB, GroupDescriptor * GD)
  : InodeUtils(SB, GD)
{
  _extfs = extfs;
  __extents = false;
  _current_block = 0;
  _extent_nb = 0;
  _blk_nb = 0;
  _cur_extent_blk = 0;
  _head = NULL;
  for (int i = 0; i < 4; ++i)
    _blk_nb_l[i] = 0;
  __s_i_blk = __d_i_blk = __t_i_blk = 0;
  __inode_addr = 0;
  __inode_nb = 0;
}

Inode::Inode(const Inode * inode)
  : InodeUtils(inode->SB(), inode->GD()), _extfs(NULL)
{
  __extents = false;
  if (inode)
    _extfs = inode->extfs();
  _current_block = 0;
  _extent_nb = 0;
  _blk_nb = 0;
  _cur_extent_blk = 0;
  _head = NULL;
  for (int i = 0; i < 4; ++i)
    _blk_nb_l[i] = 0;
  __s_i_blk = __d_i_blk = __t_i_blk = 0;
  __inode_addr = 0;
  __inode_nb = 0;
}

Inode::~Inode()
{
}

void	Inode::read(uint64_t addr)
{
  _extfs->v_seek_read(addr, (void *)InodeArray(), sizeof(inodes_t));
  __inode_addr = addr + _SB->offset() - __BOOT_CODE_SIZE;
}

void	Inode::read(uint64_t addr, inodes_t * inode)
{
  _extfs->v_seek_read(addr, (void *)inode, sizeof(inodes_t));
  __inode_addr = addr + _SB->offset() - __BOOT_CODE_SIZE;  
}

void	Inode::setInodeNb(uint32_t inode_nb)
{
  __inode_nb = inode_nb;
}

uint32_t        Inode::singleIndirectBlockContentAddr(uint32_t block_number)
{
  uint64_t	addr;
  uint32_t      blocks;

  block_number -= 12;
  addr = ((uint64_t)simple_indirect_block_pointer()) * _SB->block_size();
  if (!addr)
    return 0;
  addr += (block_number * 4);
  _extfs->v_seek_read(addr, (void *)&blocks, sizeof(uint32_t));
  return blocks;
}

uint32_t	Inode::doubleIndirectBlockContentAddr(uint32_t block_number)
{
  uint64_t	tmp  = 0;
  uint64_t	size = _SB->block_size() / sizeof(uint32_t);
  uint64_t	addr = ((uint64_t)double_indirect_block_pointer())
			* _SB->block_size();
  uint32_t	tmp_block_nb = block_number - 12 - size;
  uint32_t	sub_block    = tmp_block_nb / size;

  if (!addr)
    return 0;
  addr += (sub_block * sizeof(uint32_t));
  _extfs->v_seek_read(addr, &tmp, 4);
  if (!tmp)
    {
      _current_block += ((_SB->block_size() / sizeof(uint32_t)));
      return 0;
    }
  tmp *= ((uint64_t)_SB->block_size());
  sub_block = tmp_block_nb % size;
  tmp += (sub_block * sizeof(uint32_t));
  _extfs->v_seek_read(tmp, &addr, 4);
  if (!addr)
    _current_block++;
  return addr;
}

uint32_t	Inode::tripleIndirectBlockContentAddr(uint32_t block_number)
{
  uint64_t tmp = 0, size = _SB->block_size() / sizeof(uint32_t);
  uint64_t addr = ((uint64_t)double_indirect_block_pointer())
    * _SB->block_size();

  if (!addr)
    return 0;

  uint32_t  tmp_block_nb = block_number - 12 - size * size;
  uint32_t  sub_block = tmp_block_nb / (size * size);
  addr += (sub_block * sizeof(uint32_t));
  _extfs->v_seek_read(addr, &tmp, 4);

  if (!tmp)
    return 0;

  tmp *= ((uint64_t)_SB->block_size());
  tmp += (sub_block / size);
  _extfs->v_seek_read(tmp, &addr, sizeof(uint32_t));
  addr *= _SB->block_size();
  addr += (sub_block % size);
  _extfs->v_seek_read(tmp, &addr, 4);
  return addr;
}

uint32_t	Inode::nextBlock()
{
  uint64_t	addr;

  if (flags() & 0x80000) // uses extents
    {
      if (!_head)
	init();
      if (_head->depth)
	addr = go_to_extent_blk();
      else if (_current_block > _blk_nb)
	addr = 0;
      else
	addr = null_extent_depth(_current_block);
    }
  else
    addr =  goToBlock(_current_block);
  ++_current_block;
  return addr;
}

void	Inode::init()
{
  if (flags() & 0x80000) // uses extents
    {
      // initialisation of extents
      _head = (ext4_extents_header *)&block_pointers()[0];
      if (_head->magic == 0xF30A)
	for (int i = 0; (i < 4) && (i < _head->max_entries); ++i)
	  {
	    // one extent occupies 3 block pointers (12 bytes)
	    ext4_extent * extent
	      = (ext4_extent *)&block_pointers()[3 + (i * 3)];
	    _blk_nb_l[i] = extent->length;
	    _blk_nb += extent->length;
	  }
    }
}

uint32_t	Inode::goToBlock(uint32_t block_number)
{
  uint32_t	tmp = _SB->block_size() / 4;

  _current_block = block_number;
  if (flags() & 0x80000) // uses extents
    {
      if (!_head)
	init();
      if (_head->depth)
	return go_to_extent_blk();
      if (_current_block > _blk_nb)
	return 0;
      return null_extent_depth(block_number);
    }
  if (block_number < 12)
    return block_pointers()[block_number];
  else if ((block_number - 12) < tmp)
    return singleIndirectBlockContentAddr(block_number);
  else if ((block_number - 12 - tmp) < (tmp * tmp))
    return doubleIndirectBlockContentAddr(block_number);
  else if ((block_number - 12 - tmp - tmp * tmp) <
	   (tmp * tmp * tmp))
    return tripleIndirectBlockContentAddr(block_number);
  return 0;
}

uint32_t	Inode::browseBlock(uint32_t begin, uint32_t end)
{
  static  bool	flag = true;
  uint64_t	addr = 0;

  if (flag)
    {
      _current_block = begin;
      flag = false;
    }
  if (!end || (_current_block <= end))
    {
      addr = nextBlock();
      if (!addr)
	flag = true;
      else
	return addr;
    }
  return 0;
}

uint32_t	Inode::currentBlock()
{
  return _current_block;
}

Extfs *		Inode::extfs() const
{
  return _extfs;
}

ext4_extents_header *	Inode::extent_header() const
{
  return _head;
} 

uint64_t	Inode::null_extent_depth(uint32_t block_number)
{
  uint32_t	tot = 0, i;

  for (i = 0; tot <= block_number; ++i)
    tot += _blk_nb_l[i];
  _extent_nb = i - 1;
  if (_extent_nb >= 4)
    return 0;
  _cur_extent_blk = block_number;
  for (int j = 0; j < _extent_nb; ++j)
    {
      block_number -= _blk_nb_l[j];
      _cur_extent_blk = block_number;
    }
  ext4_extent * extent = (ext4_extent *)&block_pointers()[3 + (_extent_nb * 3)];
  if (_cur_extent_blk >= extent->length)
    {
      _extent_nb++;
      _cur_extent_blk = 0;
      if ((_extent_nb >= _head->entries) || (_extent_nb >= 4))
	{
	  _extent_nb = 0;
	  return 0;
	}
      extent = (ext4_extent *)&block_pointers()[3 + (_extent_nb * 3)];
    }
  return extent->phys_blk_low + _cur_extent_blk;
}

uint64_t	Inode::go_to_extent_blk()
{
  uint64_t	t;
  uint16_t	length;
  uint64_t	blk_nb;

  if (!__extents)
    __extents = init_extents();
  length = __extents_list.front().first;
  blk_nb = __extents_list.front().second;
  if (__offset_in_extent >= length)
    {
      __extents_list.pop_front();
      if (__extents_list.empty())
	return 0;
      blk_nb = __extents_list.front().second;
      __offset_in_extent = 0;
    }
  t = __offset_in_extent + blk_nb;
  __offset_in_extent++;
  return t;
}

bool		Inode::init_extents()
{
  Ext4Extents *	ext = new Ext4Extents(NULL);

  ext->push_extended_blocks(this);
  __extents_list = ext->extents_list();
  __offset_in_extent = 0;
  delete ext;
  return true;
}

uint32_t	Inode::s_i_blk() const
{
  return __s_i_blk;
}

uint32_t	Inode::d_i_blk() const
{
  return __d_i_blk;
}

uint32_t	Inode::t_i_blk() const
{
  return __t_i_blk;
}

bool	Inode::is_fucked_up() const
{
  if (!__inode)
    return false;
  if (this->unused2() || this->unused3())
    return true;
  if (_SB->inodes_struct_size() > sizeof(inodes_t))
    {
      __inode_reminder_t * i_reminder;
      uint8_t *	tab 
	= (uint8_t *)operator new(_SB->inodes_struct_size() - sizeof(inodes_t));
      i_reminder = (__inode_reminder_t *)tab;
      _extfs->vfile()->read(tab, _SB->inodes_struct_size() - sizeof(inodes_t));
      if (i_reminder->padding)
	return true;
      else
	for (unsigned int j = sizeof(__inode_reminder_t);
	     j < _SB->inodes_struct_size() - sizeof(inodes_t); ++j)
	  if (tab[j])
	    return true;
    }
  return false;  
}
