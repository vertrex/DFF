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

#ifndef __EXT4_EXTENTS__
#define __EXT4_EXTENTS__

#include <utility>
#include <list>
#ifndef WIN32
	#include <stdint.h>
#elif _MSC_VER >= 1600
	#include <stdint.h>
#else
	#include "wstdint.h"
#endif

#include "Inode.h"
#include "data_structure/includes/extfs_struct/ext4/extents.h"

class	Ext4Extents
{
  /*! \class Ext4Extents
    \brief Used to parse extents.

    Extents are only available on ext4. A inode flag indicates if they are
    used by the inode or not.
   
    This class is designed to parse them and get all blocks an inode using
    extents is composed of.
  */

public :

  /*! \brief Constructor.

    \param file_mapping the FileMapping where blocks will be push.
  */
  Ext4Extents(FileMapping * file_mapping = NULL);

  //! Destructor. Do nothing.
  ~Ext4Extents();

  //! \return the address of the next level, or 0 if idx is NULL
  uint64_t	next_level(ext4_extents_index * idx);


  /*! \brief Conversion of uint32_t and uint16_t into uint64_t

    Block numbers are 48 bytes long in extent structures. They occupy :
    \li an uint16_t for the higher bytes.
    \li an uint32_t for the lower bytes

    This method calculate the corresponding uint64_t. It doesn't return an
    uint48_t as far as this type doesn't exits in the standard lib.

    \param hi the higher two bytes
    \param lo the lower two bytes

    \return the concatenation of \e \b hi and \e \b and lo.
  */
  static uint64_t	concat_uint16_32(uint16_t hi, uint32_t lo);

  /*! \brief Extents block range.

    \param an extent structure address.

    \return a std::pair<uint16_t, uint64_t> filled up with the number
    of block and the starting block number of the block range. If \e \b
    extent is NULL, the pair is filed up with 0s.
  */
  std::pair<uint16_t, uint64_t>	extents(ext4_extent * extent);

  /*! \brief Read an extent header.
    
    \param block the block where the header is located.

    \return a pointer to an extent header.
  */
  ext4_extents_header *		read_header(uint8_t * block);


  /*! \brief Read extents indexes.
   \param header the extent header
   \param block the content of the curently read block.
  */
  void				read_indexes(ext4_extents_header * header,
					     uint8_t * block);

  /*! \brief Read extents.
   \param header the extent header
   \param block the content of the curently read block.
  */
  void				read_extents(ext4_extents_header * header,
					     uint8_t * block);

  /*! \brief Read a block on the vfile.
    \param addr the address where the driver musts go read.
    \return a pointer to the allocated area.
  */
  uint8_t *			read_block(uint64_t addr);

  /*! \brief File mapping push
    
    Push the different blocks in the file mapping.
    
    \param inode the inode we are treating.
    \throw vfsError if something goes zrong.
   */
  void				push_extended_blocks(Inode * inode)
    throw (vfsError);

  /*! \brief Block list.
    \return a list of the blocks which compose the current file.
   */
  const std::list<std::pair<uint16_t, uint64_t> >	extents_list() const;

  /*! \brief Calculate a file size.

    Only used for deleted inode, where the size is set to 0. Try to calculate
    the size by counting the number of blocks the inode is composed of.

    \param inode the inode we want to have the size.
  */
  uint64_t	calc_size(Inode * inode);

  /*! \brief Read extents
    
    Read extents, but not based on the file size stored in the inode.
    
    \param header the extents header.
    \param block the area we are currently parsing.
  */
  void		read_extents_x(ext4_extents_header * header,
			       uint8_t * block);
private :

  FileMapping *			__mapping;
  uint64_t			__size;
  uint64_t			__offset;
  uint32_t			__block_size;
  Node *			__node;
  Extfs *			__extfs;
  uint64_t			__c_size;
  Inode *			__inode;
  std::list<std::pair<uint16_t, uint64_t> >
    __extents_list;
};

#endif
