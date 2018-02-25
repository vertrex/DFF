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

#ifndef BLK_LIST_
#define BLK_LIST_

#ifndef WIN32
	#include <stdint.h>
#elif _MSC_VER >= 1600
	#include <stdint.h>
#else
	#include "wstdint.h"
#endif


#include "../data_structure/includes/GroupDescriptor.h"
#include "../data_structure/includes/SuperBlock.h"
#include "vfile.hpp"

class	BlkList
{
  /*!
    \class BlkList
    \brief Display the allocation status of file system blocks.
    
    This class is used when the user uses the \e --blk option. It displays,
    for each block number passed to \e --blk, the allocation status of the
    block.

    \note
    The block's allocation status are in the block bitmap table.

    The display has the following appearance :
    \verbatim
    
    <block bumber> | <status> | <group number> | <Byte address> | <Bit address>

    \endverbatim

    For example :
    \verbatim
    
    42 | Allocated | Group : 0 | Byte addr : 266245 (0x41005)  | Bit position : 2

    \endverbatim

    In the previous example, the block 42 is allocated, it is located in the group 0
    and the bit defining its location status is the second bit of the byte located at
    the address 0x41005.
  */

public :
  //! Setup some variables.
  BlkList(GroupDescriptor * GD, SuperBlock * SB, VFile * vfile);

  //! Free what needs to be freed.
  ~BlkList();

  /*
    \brief Display block allocation status.

    This method parse the arguments of the option \e --blk and display the
    allocation status of the different blocks.

    \param blk_list the list of block number the user wish to know the allocation
    status.
    
  */
  void	stat(const std::string & blk_list);

  /*! 
    \brief block allocation status.

    \param blk_nb a block number
    \display print some information if set to True.
    
    \return true if the block \e \b blk_nb is allocated, false otherwise.
    
  */
  bool	blk_allocation_status(uint64_t blk_nb);

private :
  GroupDescriptor *	__GD;
  VFile *	__vfile;
  SuperBlock *	__SB;
  uint64_t	__begin;
  uint64_t	__end;
  uint64_t	__bit_addr;
  uint8_t	__dec;
  uint16_t	__group;
};

#endif
