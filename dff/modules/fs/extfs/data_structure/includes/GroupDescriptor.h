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

#ifndef __GROUP_DESCRIPTOR_H__
#define __GROUP_DESCRIPTOR_H__

#include "extfs_struct/group_descr_table.h"
#include "SuperBlock.h"
#include "vfs.hpp"

//! this table is used to calculate the crc16 in group descriptor
uint16_t const crc16_table[256] =
  {
    0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
    0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
    0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
    0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
    0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
    0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
    0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
    0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
    0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
    0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
    0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
    0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
    0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
    0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
    0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
    0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
    0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
    0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
    0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
    0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
    0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
    0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
    0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
    0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
    0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
    0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
    0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
    0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
    0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
    0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
    0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
    0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040
  };

class	GroupDescriptor
{
  /*! \class GroupDescriptor
    \brief A group descriptor structure.

    The ext file system family is composed of blocks (usually 4 kB big on
    ext3, but this can be modified in the Superblock), divided in group blocks.
    In the block following the superblock block is a table containing
    group descriptors (one for each group). Backup of this table can be
    found in all groups, <b>UNLESS the sparse superblock feature
    is enabled</b>.

    There are two versions of the group descriptor table :
    \li one which is 32 bytes big.
    \li the other is 64 bytes big.

    There is a field in the superblock that indicates the size. If
    this size is set to 0, we assume that the group descriptor is
    32 bytes big. The check is made in the constructor and the attributes
    __64_bits_field is set appropriatly.

    \sa SuperBlock
  */

public:
  //! Constructor : do nothing
  GroupDescriptor(SuperBlock * SB, uint32_t block_size);

  //! Desctructor : do nothing.
  ~GroupDescriptor();

  /*! \brief Group descriptor address.
    \return the address of the block descriptor.
  */
  uint64_t		groupDescriptorAddr() const;

  /*! \brief Read a group descriptor.

    Read the content of a group descriptor structure in the descriptor
    table.

    \param block_size the size of a file system block
    \param vfile a pointer to the vfile
    \param gr_number the group number
    \param check_alloc_nb if true, check the allocation number of inodes 
    and blocks.

    \throw vfsError if something goes wrong.
  */
  void			init(uint32_t block_size, VFile * vfile,
			     uint32_t gr_number);
  /*! \brief Descriptor group structure.

    \return a pointer to the \c \b group_descr_table_t.

    \typedef group_descr_table_t
  */
  const group_descr_table_t *	getGroupTable() const;

  /*! \brief Descriptor group table.
      
    \param group the number of the group we need the descriptor.

    \return a pointer to the group_descr_table_t of group \e \b group.
  */
  const group_descr_table_t *	getGroupTable(uint32_t group) const;

  /*! \brief Group descriptor size.
    \return the group descriptor size.
  */
  uint16_t			GD_size() const;
  /*! \brief Block bitmap.
    \return the block bitmap address.
    \sa group_descr_table_t
  */
  uint32_t			block_bitmap_addr(uint32_t group) const;

  /*! \brief Inode bitmap.
    \return the inode bitmap address.
    \sa group_descr_table_t
  */
  uint32_t			inode_bitmap_addr(uint32_t group) const;

  /*! \brief Inode table.
    \return the inode table address.
    \sa group_descr_table_t
  */
  uint32_t			inode_table_block_addr(uint32_t group) const;

  /*! \brief Unallocated blocks.
    \return the number of unallocated blocks in the group.
    \sa group_descr_table_t
  */
  uint16_t			unallocated_block_nbr(uint32_t group) const;

  /*! \brief Unallocated inodes.
    \return the number of unallocated inodes in the group.
    \sa group_descr_table_t
  */
  uint16_t			unallocated_inodes_nbr(uint32_t group) const;

  /*! \brief Directories number.
    \return the number of directories in the group.
    \sa group_descr_table_t
  */
  uint16_t			dir_nbr(uint32_t group) const;

  uint16_t			checksum(uint32_t group) const;

  uint16_t			unused_inodes_low(uint32_t group) const;

private:
  void				__check_inode_nb(uint32_t, uint32_t, VFile *);
  void				__check_blk_nb(uint32_t, uint32_t, VFile *);
  uint16_t			crc16(uint16_t crc, uint8_t const * buf,
				      size_t len);
  inline uint16_t		crc16_byte(uint16_t crc, const uint8_t data);

  group_descr_table_t *		_gr_descr;
  group_descr_table_64_t *	_gr_descr_64;
  uint8_t *			_gr_descr_array;
  uint64_t			_SB_offset;
  uint64_t			_block_addr;
  const uint8_t *		__FS_ID;
  bool				__64_bits_field;
  bool				__bg_checksum;
  SuperBlock *			__SB;
};

#endif
