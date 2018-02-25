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

#ifndef JOURNAL_H
#define JOURNAL_H

#include <map>
#include <vector>
#include "../data_structure/includes/extfs_struct/journal.h"
#include "../data_structure/includes/Inode.h"

class Journal : public Inode
{
  /*! \class Journal
    \brief The journal of the ext3 file system.

    This class only concern Ext3 file systems. It inheritates the Inode
    class.

    The journal purpose is to make system recoveries faster if it crashes.

    The journal is used (in most cases) to only save metadata blocks
    when they are modified (inodes tables, inode bitmap allocation table,
    etc). By activating I dont remember what option, blocks content can
    also be saved. Having inodes' backups can be very useful to get lost
    pointers back by retrieving inodes in their previous state. Each data
    blocks of the journal contains one file system block, consequently
    journal blocks should have the same size as file system blocks.

    The journal size is defined in the journal superblock. The journal
    acts as round-robin : when the end is reached, it jumps back to the
    beginning so oldest data are removed while inserting new ones.

    To make sure the ext3 journal is enabled, check the corresponding
    compatible-features in the superblock. Usually the journal is located
    in the inode 8, but this can be modified in the superblock.

    All journal's structures are defined in the file
    \e data_structure/extfs_struct/journal.h

    The journal is made of transactions delimited by a sequence descriptor
    and a commit block. Each transaction has a unique sequence number.

    The first block of the journal is the journal superblock (version 1
    or 2). The superblock starts with 12 bytes wich are the standard
    header of the journal. The standard header contains the journal
    signature in his first 4 bytes : \c \b 0xC03B3998. It also contains 
    a block type and a sequence number in the 8 following bytes.

    A journal block type can be :
    \li 1 : a descriptor block
    \li 2 : a commit block
    \li 3 / 4 : a superblock v1 / v2
    \li 5 : a revoke block

    A descriptor block starts with the standard journal header, and is
    followed by descriptors block entries (see the journal_block_entries
    structure). Each descriptor entry corresponds to a file system block.

    Following the superblock are transactions, with, at their beginning a
    descriptor block, followed by blocks backups. The end of a transaction
    is marked with a commit block.

    | superblock | descriptor block | .... some metadata blocks ....
    | commit block |

    \warning
    \verbatim
    The journal data are stored in big endian.
    \endverbatim
  */
 public:

  /*! \enum J_BLOCK_TYPE
    \brief Journal block type.
  */
  enum	__J_BLOCK_TYPE
  {
    __DESCR_BLOCK  = 1, /*!< Descriptor block. */
    __COMMIT_BLOCK = 2, /*!< Commit block */
    __SB_V1        = 3, /*!< Superblock version 1 */
    __SB_V2        = 4, /*!< Superblock version 2 */
    __REVOKE_BLOCK = 5  /*!< Revoke block */
  };

  enum	__J_FLAGS
  {
    __ESCAPED_JBLK = 0x01,
    __SAME_UUID    = 0x02,
    __BLK_DELETED  = 0x04,
    __LAST_ENT_DESCR_BLK = 0x08
  };

  /*! \brief Constructor.

    \param extfs a pointer to the Extfs instance.
    \param SB a pointer to the SuperBlock instance.
    \param GD a pointer to the GroupDescriptor instance.
  */
  Journal(Extfs * extfs, const SuperBlock * SB, GroupDescriptor * GD);

  //! \brief Destructor. Do nothing.
  ~Journal();

  /*! \brief Journal initialization.
    
    Initialize the journal : read the journal superblock, eventually the
    superblock reminder if it a version 2 journal and put some values
    into cache.

    This method does not throw any exceptions because even if the journal
    initializarion didn't go well, the driver still can be runned. It is
    up to the caller to test the return value.

    \return true if no problem occurs, false otherwise.
  */
  bool		init();

  /*! \brief Cache.
    \return a constant reference to the cache map.
   */
  const std::map<uint32_t, std::vector<uint64_t> > &
	journal_cache() const;

  /*! \brief Journal superblock.
    \return a pointer to the journal superblock.
    \sa journal_superblock
  */
  const journal_superblock *    j_super_block() const;

 private: 
  std::map<uint32_t, std::vector<uint64_t> >	__j_cache;
  journal_superblock *		__J_SB;
  journal_v2_reminder *		__J_V2_reminder;

 private:
  void		caching();
  void		parseCommitBlocks(uint8_t * j_block, uint32_t j_block_size);
  void		getBlocksAddr(const std::list<uint32_t> & b_list);

};

#endif // JOURNAL_H
