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

#ifndef INODEUTILS_H
#define INODEUTILS_H

#include "vfs.hpp"

#include "../../data_structure/includes/GroupDescriptor.h"
#include "../../data_structure/includes/SuperBlock.h"

class InodeUtils
{
    /*! \class InodeUtils
      \brief Useful methods.

      This class provides some useful methods relatives to an inode.

      \sa Inode.
    */

public:
    /*! \brief Constructor

      Initialize the instance.

      \param SB a pointer to the SuperBlock instance.
      \param GD a pointer to the GroupDescriptor instance.

      \sa SuperBlock
      \sa GroupDescriptor
    */
    InodeUtils(const SuperBlock * SB = NULL, GroupDescriptor * GD = NULL);

    //! Destructor. Do nothing.
    ~InodeUtils();

    /*! \brief File size.

      Calculate and returned the file size.

      \param l_size the 4 lower bytes of the size.
      \param h_size the 4 higher bytes of the size.
      \param large_file a flag set to \c \b true if the file system supports
      large files, and to \c \b false otherwise.

      \return the size of the file (in bytes).
    */
    uint64_t    getSize(uint32_t l_size, uint32_t h_size = 0,
                        bool large_file = false) const;

    /*! \brief Get an inode address.

      Get an inode address on the vfs according to the inode number \b \e nb.

      \warning The method does not check if the block number is valid.

      \param nb the inode number we are looking for.

      \return the address of the inode on the vfile, or \c \b 0 if \e \b nb
      is equal to \c \b 0.
    */
    uint64_t    getInodeByNumber(uint32_t nb);

    /*! \brief inode allocation status.

      Determine the inode allocation status using the inode bitmap table.
      In this table each bits determine the allocation status of an inode.

      \return true if the inode is allocated, false otherwise.
    */
    bool        isAllocated(uint32_t, VFile * vfile);

    /*! \brief Group number.
      \return the group number of the inode \b \e inode_number.
    */
    uint16_t	groupNumber(uint32_t inode_number);

    /*! \brief File mode.

      Build a human readable string of the access rights on the file.

      Example:
      \verbatim
      wr--r--r-
      \endverbatim
      The notation is the same as the UNIX one.

      \param file_mode the file mode.
      \return access rights on the file.

    */
    std::string mode(uint16_t file_mode);

    /*! \brief Allocation status.
      \param inode_number the inode we want to know the allocation status.
      \param vfile a pointer to the virtual file system.
      \return the string "Allocated" if the inode is allocated,
      "Not allocated" otherwise.
    */
    std::string allocationStatus(uint32_t inode_number, VFile * vfile);

    /*! \brief File type.

      Return a human readable file type:
      \li `-' : regular file
      \li `b' : block special file
      \li `c' : character special file
      \li `d' : directory
      \li `l' : symbolic link
      \li `p' : FIFO (named pipe)
      \li `s' : socket
      \li `?' : some other file type

      \param file_mode the file mode.
      \return the file type.
    */
    std::string type(uint16_t file_mode);

    std::string uid_gid(uint16_t uid, uint16_t gid);

    std::string set_uid_gid(uint16_t file_mode);

    /*! \brief Superblock.
      \return a pointer to a SuperBlock instance
      \sa SuperBlock
    */
    const SuperBlock *  SB() const;

    /*! \brief Group descriptor.
      \return a pointer to a GroupDescriptor instance.
      \sa GroupDescriptor
    */
    GroupDescriptor *   GD() const;

    /*! \brief File type and mode.
      
      \param file_mode the file mode.

      \return a human readable string of the file mode : dwr--r--r- for example.
     */
    std::string	type_mode(uint16_t file_mode);

protected:
    const SuperBlock *  _SB;
    GroupDescriptor *   _GD;
};

#endif // INODEUTILS_H
