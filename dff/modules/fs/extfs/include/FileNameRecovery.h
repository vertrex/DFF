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

#ifndef RECOVERY_H
#define RECOVERY_H

#include "data_structure/includes/DirEntry.h"
#include "Directory.h"
#include "../extfs.hpp"

class FileNameRecovery
{
  /*! \class  FileNameRecovery.
    \brief  Recover deleted files.

    The class purpose is to retrieve hidden / deleted file names
    from a given directory.

    Remember that a directory content is composed of directory
    entries, themself composed of :

    \li an inode number

    \li a file name

    \li a size pointing to the next directory entry, or to the end of
    the current content block if it the last allocated directory
    entry. The size is a multiple of 4, at least as big as the
    directory entry structure size + the name length

    When a file is removed, the directory entry containing his name is
    not deleted. The size of the previous directory entry is modified so
    it jumps directly to the directory entry following the deleted one.
    For more precisions, please refer to the \c \b DirEntry class.

    It is possible to 'guess' where deleted dirents might be, and then
    recover some file names. Of course these are just guesses and
    consequently false hits happen sometimes.

    Notice that this class only retrieve file names, not file content.
    Indeed, retrieving data from a non allocated inode is quiet
    different between ext2, ext3 and ext4.

    On ext2 when a file is deleted, the directory entry is 'hidden' as 
    we already explain and the inode is marked as unallocated in the
    inode bitmap table. That's all.

    On ext3, it is the same procedure, but the file size is set to 0 as
    are the block pointers in the inode. The recovery becomes harder but
    the journal can be used in some cases.

    Notice that when a file is deleted MAC time are set to the deletion
    date and the field 'deletion time' is also set to the deletion date.

    \sa DirEntry
    \sa Inode
    \sa Directory
    \sa dir_entry_v1 dir_entry_v2
  */

 public:

  /*! \brief Constructor.
   */
  FileNameRecovery(Journal * journal);

  /*! \brief Destructor.
   */
  ~FileNameRecovery();

  /*! \brief Names recovery.

    Recover files name which have been deleted. This method is called
    only when some directory entries might have been deleted.

    \param tab a pointer to the dir entry block.
    \param content_addr the address where the dir entry is on the VFile.
    \param parent a pointer to the parent node
    \param dir_inode the inode of the parent directory.
    \param dir a \c \b DirEntry struct (the current directory entry).

    \sa DirEntry
  */
  uint8_t    deletedFileNames(uint8_t * tab, uint64_t content_addr,
			   Node * parent, Directory * dir_inode,
			   DirEntry * dir);

  /*! \brief Check a dirent validity.

    The valid_entry method tries to check a dirent validity.
    'tries' because some data could match the condition, without
    being a dirent. Some false hits must be excpected.

    \param dir the dirent we are investigating.

    \return true if the dirent is valid, false otherwise.
  */
  uint8_t    valid_entry(DirEntry * dir);

  /*! \brief Check name validity.

    A name is considered as invalid if it starts with NULL or if it is
    "." or "..". Some other checks using the name length and the entry length
    are done.

    \param name the name that has to be checked.
    \param name_len the length of the name set in the dir entry
    \param entry_len the length of the dir entry

    \return true if the name is valid, false otherwise.
  */
  bool    valid_name(char * name, uint8_t name_len, uint16_t entry_len);

  /*! \brief Data recovery.

    \param block_number the number of the file system block we are
    looking for.
    \param dir a directory
    \param dir_e a dir entry
    \param inode an inode
    \param parent the parent node.

    \return a new node
  */

  ExtfsNode *   recovery(uint32_t block_number,
			 Directory * dir,
			 DirEntry * dir_e,
			 inodes_t * inode,
			 Node * parent);

  bool		retrieve_inode_direct(inodes_t * inode,
				      uint32_t inode_nb);

  std::string	setDirName(DirEntry * del_dirent,
			   uint8_t * tab,
			   uint64_t pos);

  ExtfsNode *	retrieve_inode(Directory * inode_dir,
			       DirEntry * del_dirent,
			       Node * parent,
			       const std::string & name,
			       inodes_t * inode);

  //! \return a pointer to the journal instance, or NULL if there are no journal.
  Journal *	getJournal() const;

 private:
  Journal *	_journal;
  inodes_t *	__inter;
  std::string	__name;
  uint64_t	__addr;
};

#endif // RECOVERY_H
