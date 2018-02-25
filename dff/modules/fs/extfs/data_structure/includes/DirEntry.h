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

#ifndef __DIR_ENTRY__
#define __DIR_ENTRY__

#include "vfs.hpp"

#include "extfs_struct/directory_entry.h"

namespace DFF
{
class VFile;
}


class	DirEntry
{
  /*! \class DirEntry
    \brief Directory entries (or dirents)

    Directories content are made of directory entries, often shortened to
    'dirents'.

    \sa Inode
    \sa Directory
  */

public:
  enum    FILE_TYPE
    {
      _UNKNOWN = 0,
      _REG_FILE = 1,
      _DIRECTORY = 2,
      _CHAR_DEVICE = 3,
      _BLOCK_DEVICE = 4,
      _FIFO = 5,
      _UNIX_SOCKET = 6,
      _SYM_LINK = 7
    };

  //! Constructor.
  DirEntry();

  //! Destructor.
  ~DirEntry();

  /*! \brief File name.
    \return the name of the file of the current dirent, or \c \b NULL if
    it hasn't been allocated.
  */
  uint8_t *         getName();

  /*! \brief Dir entry structure.
    \return the address of the dir_entry structure
    \sa dir_entry_v2
  */
  dir_entry_v2 *  getDir();

  /*! \brief File name allocation.

    Allocate enough space for the file name according to the value returned
    by name_length_v1() or name_length_v2(), depending one the dirent used
    version. It doesn't read the file name though. The reading must be
    performed by the caller.

    \return a pointer to the allocated area, or \c \b NULL if the allocation
    failed.
  */
  uint8_t *	    allocName();

  /*! \brief Read a dirent content.

    Seek at \e \b content_addr, read the dirent content, allocate and read the
    file name (by calling \c \b allocName()).

    \param content_addr the address on the vfs where readName must read.
    \param vfile the vfs, necessary to seek and read
    \sa allocName
  */
  void            read(uint64_t content_addr, DFF::VFile * vfile);

  /*! \brief Next directory entry.
    \return what \e \b SHOULD be the size of the current dir entry.
  */
  uint64_t        next();

  /*! \brief Inode number.
    \return the inode number.
  */
  uint32_t	    inode_value() const;

  /*! \brief Dirent length.
    \return the length of the directory entry.
  */
  uint16_t	    entry_length() const;

  /*! \brief Name's length v1.
    \return the lenght of the name (version 1).
  */
  uint16_t	    name_length_v1() const;

  /*! \brief Name's length v2.
    \return the lenght of the name (version 2).
  */
  uint8_t           name_length_v2() const;

  /*! \brief File type (v2).
    \return the file type (version 2).
  */
  uint8_t           file_type_v2() const;


  /*! \brief Set directory entry.
    \param dir the pointer to the dir_entry_v2 structure we want to use.
  */
  void		setDir(dir_entry_v2 * dir);

  /*! \brief Set a directory name.
    \param name an array containing the name we want to set.
  */
  void	setName(uint8_t * name);

private:
  dir_entry_v2 *   _dir;
  uint8_t *	     _name;
};

#endif
