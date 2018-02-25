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
#include "includes/GroupDescriptor.h"

GroupDescriptor::GroupDescriptor(SuperBlock * SB, uint32_t block_size)
{
  __bg_checksum = SB->ro_features_flags() & SuperBlockStructure::_GD_CSUM;
  _SB_offset = SB->offset();
  this->__64_bits_field = (SB->getSuperBlock()->s_desc_size <= 32 ?
			   true : false);
  if (block_size == __BOOT_CODE_SIZE)
    _block_addr =  __BOOT_CODE_SIZE * 2;
  else
    _block_addr = block_size;
  _block_addr += (SB->offset() - __BOOT_CODE_SIZE);
  __FS_ID = SB->file_system_ID();
  __SB = SB;
}

GroupDescriptor::~GroupDescriptor()
{
}

uint64_t    GroupDescriptor::groupDescriptorAddr() const
{
  return _block_addr;
}

void    GroupDescriptor::init(uint32_t block_size, VFile * vfile,
			      uint32_t gr_number)
{
  uint64_t	gd_addr = groupDescriptorAddr();
  uint32_t	coeff;

  if (__64_bits_field)
    coeff = 64 * gr_number;
  else
    coeff = 32 * gr_number;
  _gr_descr = (group_descr_table_t * )operator new(coeff);
  _gr_descr_64 = (group_descr_table_64_t *)_gr_descr;
  _gr_descr_array = (uint8_t *)_gr_descr;
  vfile->seek(gd_addr);
  vfile->read((void *)_gr_descr_array, coeff);
  if (__bg_checksum)
    for (unsigned int i = 0; i < gr_number; ++i)
      {
	uint16_t	crc;
	
	crc = crc16(~0, __FS_ID, 16);
	crc = crc16(crc, (uint8_t *)&i, sizeof(uint32_t));
	crc = crc16(crc, (uint8_t *)getGroupTable(i), 
		    sizeof(group_descr_table_t) - 2);
	if (crc != checksum(i))
	  std::cerr << "Group " << i << " : bad checksum = "
		    << checksum(i)
		    << "; should be " << crc << std::endl;
      }
  else
    std::cout << "No group descriptor checksum." << std::endl;
  if (false == true)
    {
      __check_inode_nb(gr_number, block_size, vfile);
      __check_blk_nb(gr_number, block_size, vfile);
    }
}

void		GroupDescriptor::__check_inode_nb(uint32_t gr_number,
						  uint32_t block_size,
						  VFile * vfile)
{
  uint8_t *	tab = (uint8_t *)operator new(block_size);
  uint64_t	tot = 0;

  for (unsigned int i = 0; i < gr_number; ++i)
    {
      uint64_t	addr;
      uint8_t	byte;
      uint64_t	count = 0;

      addr = inode_bitmap_addr(i) * block_size;
      vfile->seek(addr +  _SB_offset - __BOOT_CODE_SIZE);
      vfile->read(tab, block_size);
      if (unused_inodes_low(i) != __SB->inodes_in_group_number())
	{
	  for (unsigned int j = 0; j < (__SB->inodes_in_group_number() / 8); ++j)
	    {
	      byte = tab[j];
	      for (unsigned int k = 0; k < 8; ++k)
		if (!((byte >> k) & 1))
		  count++;
	    }
	  tot += count;
	}
      else
	{
	  tot += unused_inodes_low(i);
	  continue ;
	}

      if (count != unallocated_inodes_nbr(i))
	std::cerr << "Group " << i << " : free inodes number mismatch. " 
		  << unallocated_inodes_nbr(i) << ", counted " << count
		  << std::endl;
    }
  if (tot != __SB->u_inodes_number())
    std::cerr << std::endl << " ******* Total free inodes number mismatch : " 
	      << __SB->u_inodes_number() << ", counted " << tot
	      << " *******" << std::endl;
  else
    std::cout << "Free inodes count seem to be correct." << std::endl;
  delete tab;
}

void		GroupDescriptor::__check_blk_nb(uint32_t gr_number,
						uint32_t block_size,
						VFile * vfile)
{
  uint8_t *	tab = (uint8_t *)operator new(block_size);
  uint64_t	tot = 0;

  for (unsigned int i = 0; i < gr_number; ++i)
    {
      uint64_t	addr;
      uint8_t	byte;
      uint64_t	count = 0;

      addr = block_bitmap_addr(i) * block_size;
      vfile->seek(addr + _SB_offset - __BOOT_CODE_SIZE);
      vfile->read(tab, block_size);
      for (unsigned int j = 0; j < __SB->block_in_groups_number() / 8; ++j)
	{
	  byte = tab[j];
	  for (unsigned int k = 0; k < 8; ++k)
	    if (!((byte >> k) & 1))
	      count++;	      
	}
      tot += count;
      if (count != unallocated_block_nbr(i))
	std::cerr << "Group " << i << " : free blocks number mismatch. " 
		  << unallocated_block_nbr(i) << ", counted " << count
		  << std::endl;
    }
  if (tot != __SB->u_blocks_number())
    std::cerr << std::endl << " ******* Total free blocks number mismatch : "
	      << __SB->u_blocks_number() << ", counted " << tot
	      << " *******" << std::endl;
  else
    std::cout << "Free blocks count seem to be correct." << std::endl;
  delete tab;
}

uint16_t	GroupDescriptor::crc16(uint16_t crc, uint8_t const * buf,
				       size_t len)
{
  while (len--)
    crc = crc16_byte(crc, *buf++);
  return crc;
}

uint16_t	GroupDescriptor::crc16_byte(uint16_t crc, const uint8_t data)
{
  return (crc >> 8) ^ crc16_table[(crc ^ data) & 0xff];
}

const group_descr_table_t *	GroupDescriptor::getGroupTable() const
{
  return _gr_descr;
}

const group_descr_table_t *	GroupDescriptor::getGroupTable(uint32_t group) const
{
  if (!this->__64_bits_field)
    return (group_descr_table_t *)&_gr_descr_64[group];
  return  &_gr_descr[group];
}

uint32_t	GroupDescriptor::block_bitmap_addr(uint32_t group) const
{
  if (!this->__64_bits_field)
    return _gr_descr_64[group].block_bitmap_addr;
  return _gr_descr[group].block_bitmap_addr;
}

uint32_t	GroupDescriptor::inode_bitmap_addr(uint32_t group) const
{
  if (!this->__64_bits_field)
    return _gr_descr_64[group].inode_bitmap_addr;
  return _gr_descr[group].inode_bitmap_addr;
}

uint32_t	GroupDescriptor::inode_table_block_addr(uint32_t group) const
{
  if (!this->__64_bits_field)
      return _gr_descr_64[group].inode_table_block_addr;
  return _gr_descr[group].inode_table_block_addr;
}

uint16_t	GroupDescriptor::unallocated_block_nbr(uint32_t group) const
{
  if (!this->__64_bits_field)
    return _gr_descr_64[group].unallocated_block_nbr;
  return _gr_descr[group].unallocated_block_nbr;
}

uint16_t	GroupDescriptor::unallocated_inodes_nbr(uint32_t group) const
{
  if (!this->__64_bits_field)
    return _gr_descr_64[group].unallocated_inodes_nbr;
  return _gr_descr[group].unallocated_inodes_nbr;
}

uint16_t	GroupDescriptor::dir_nbr(uint32_t group) const
{
  if (!this->__64_bits_field)
    return _gr_descr_64[group].dir_nbr;
  return _gr_descr[group].dir_nbr;
}

uint16_t	GroupDescriptor::GD_size() const
{
  if (__64_bits_field)
    return 32;
  return 64;
}

uint16_t	GroupDescriptor::checksum(uint32_t group) const
{
  if (this->__64_bits_field)
    return _gr_descr[group].bg_checksum;
  return _gr_descr_64[group].bg_checksum;
}

uint16_t	GroupDescriptor::unused_inodes_low(uint32_t group) const
{
  if (this->__64_bits_field)
    return _gr_descr[group].bg_itable_unused_lo;
  return _gr_descr_64[group].bg_itable_unused_lo;
}
