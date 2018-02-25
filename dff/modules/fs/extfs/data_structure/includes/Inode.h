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

#ifndef __INODE_H__
#define __INODE_H__

#include <map>

#include "extfs.hpp"
#include "include/utils/InodeStructure.h"
#include "include/utils/InodeUtils.h"
#include "extfs_struct/ext4/extents.h"

class Inode : public InodeStructure, public InodeUtils
{
  /*! \class Inode.
      \brief Extfs metadata.

    This class encapsulate an \c \b inodes_t typedef. Accessors can be
    used to get all the fields. An inode contains metadatas of files. This
    consist of, among other things:
    \li the file size
    \li the file mode (access right)
    \li MAC times
    \li block pointers, to locate the content on the file system.

    It is ineritated by \c \b Directory (which are inodes too).
    <b>'Everything is a file'</b>, so everything has an
    inode, though the content is not the same between a file, a
    directory and other file types.

    The three most important types of files are :
    \li Regular files.
    \li Directories.
    \li Symbolic links.

    The type is defined in the file mode field of the inode structure.
    The other type are stuff like FIFO, devices, socket, etc.

    The file mode also contains informations about the access rights and
    group and user ID (set UID / GID).

    The content of a file is refered by block pointers which can be
    directs or indirect.
    \li 12 direct block pointers, directly stored in the inode.
    \li 1 single indirect block pointer.
    \li 1 double indirect block pointer.
    \li 1 triple indirect block pointer.

    When a file is deleted, the behaviour is different between ext2 and
    ext3 : on ext3 block pointers and the file size are reset to 0. This
    make the recovery harder : one solution is to look into the journal
    to check if the inode can be found in its previous state. But even
    if this is the case we cannot be sure the content blocks haven't been
    reallocated in the mid time.

    \sa inodes_t
  */
 public:

  /*! \enum PERMISSIONS_BITS
    \brief Permissions bits.
  */
  enum PERMISSIONS_BITS
  {
    _ISUID = 0x0004000,
    _ISGID = 0x0002000,
    _ISSTI = 0x0001000
  };

  //! Constructor.
  Inode(Extfs *, const SuperBlock *, GroupDescriptor * GD);

  //! Copy constructor.
  Inode(const Inode *);

  //! Desctructor, free resources.
  ~Inode();

  /*! \brief Read the inode content.
    \param addr the address of the inode on the vfs.
  */
  void		read(uint64_t addr);

  /*! \brief Read an inode content.

    Overload provided for convenience.

    \param addr the address of the inode on the vfs.
    \param inode a pointer to the \c \b inodes_t where the result will be
    stored.
  */
  void		read(uint64_t addr, inodes_t * inode);

  /*! \brief Content blocks number.

    The content of files is stored in file system blocks
    which are 'pointed' by block pointers in the inode:
    \li 12 direct block pointers
    \li 1 single indirect block pointer
    \li 1 double indirect block pointer
    \li 1 triple indirect block pointer

    \warning in those block pointers, BLOCK NUMBERS are stored, not
    addresses. The address on the vfile must be calculated using the
    calculation :
    \verbatim
    block_pointer * SuperBlock->block_size();
    \endverbatim

    The content of the destination block in not read, it is up to the
    caller to perform the reading. Notice that data can be hidden at the
    end of the last content block (the slack). At least one block is
    allocated per file, even if his size is just a few bytes.

    The \c \b nextBlock() method returns the next file system content
    block number (the current content block number can be known by calling
    \c \b currentBlock()).

    This method also increments the value of the current block by 1 each
    time it is called.
    If the current block reaches a value which is out a range, an
    exception is thrown.

    \warning  the current block is a block number IN THE INODE but the
    method \c \b nextBlock() returns a block number ON THE VFS. In other
    words, if the current block is equal to 0, it will refer to the first
    direct block pointer, if it is equal to 1 it will refer to the second
    direct block pointer, if it is equal to 13 it will refer to the first
    single indirect block pointer and so on.

    \return The number of the next content block.

    In the following example \c \b nextBlock() will return all content
    block numbers one after the others.

    \code
    Inode * inode = new Inode;
    uint32_t block_number;

    while (block_number = inode->nextBlock())
	do_something(block_number);
    \endcode
  */
  uint32_t	nextBlock();

  void		init();

  /*! \brief Current block.

    \return the number of the current content block.
  */
  uint32_t	currentBlock();

  /*! \brief Get a file system content block number.

    Set the current block to \e \b block_number and return return the
    corresponding file system block number.

    \param block_number the block number you want to go to.

    \return the file system block number
  */
  uint32_t	goToBlock(uint32_t block_number);

  /*! \brief Browsing several blocks.

    Example of use :
    \code
    uint32_t block_number;
    while (block_number = goToBlock(5, 15))
    doSomething(block_number);
    \endcode

    In the the previous example, \c \b browseBlock() will return one after
    the other the file system block number of inode content blocks 1 to 15.

    The current block is incremented by one at each call.

    \param begin the first block the user wants to go.
    \param end the block where the browsing stops.

    \throw a vfsError if the block \e \b block_number is out of range.

    \return the file system block number of the current block.
  */
  uint32_t	browseBlock(uint32_t begin, uint32_t end);

  /*! \brief EXtfs.
    \return a pointer to an Extfs instance
    \sa Extfs
  */
  Extfs *	extfs() const;

  bool		is_fucked_up() const;

  ext4_extents_header *	extent_header() const;
  uint32_t	s_i_blk() const;
  uint32_t	d_i_blk() const;
  uint32_t	t_i_blk() const;
  inline uint32_t	inodeNb() const { return __inode_nb; }
  void	setInodeNb(uint32_t inode_nb);

protected:
  uint32_t	singleIndirectBlockContentAddr(uint32_t);
  uint32_t	doubleIndirectBlockContentAddr(uint32_t);
  uint32_t	tripleIndirectBlockContentAddr(uint32_t);
  uint64_t	go_to_extent_blk();
  uint64_t	null_extent_depth(uint32_t block_number);
  bool		init_extents();

protected:
  std::list<std::pair<uint16_t, uint64_t> >	__extents_list;
  uint32_t	__inode_nb;
  uint16_t	__offset_in_extent;
  Extfs *	_extfs;
  uint32_t	_current_block;
  uint64_t	_calculated_size;
  
  // extents (only on ext4)
  ext4_extents_header *	_head;
  uint8_t	_extent_nb;
  uint32_t	_blk_nb;
  uint32_t	_blk_nb_l[4];
  uint32_t	_cur_extent_blk;
  bool		__extents;

  uint32_t	__s_i_blk;
  uint32_t	__d_i_blk;
  uint32_t	__t_i_blk;
};

#endif
