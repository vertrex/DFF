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

#ifndef INODESTRUCTURE_H_
#define INODESTRUCTURE_H_

#include <memory>

#include "vfs.hpp"
#include "../../data_structure/includes/extfs_struct/inodes.h"

class InodeStructure
{

public:
    InodeStructure();
    ~InodeStructure();

    void    setInode(const inodes_t * inode);

    /*! \brief Inode structure.

        \return a pointer to the \c \b inodes_t structure.
    */
    const inodes_t  *   inode() const;
    const uint8_t *	InodeArray() const;

    /*! \brief File mode.
        \return the file mode.
        \sa inodes_t
    */
    uint16_t  file_mode() const;


    /*! \brief Lower UID
        \return the lower 16 bits of UID.
        \sa inodes_t
    */
    uint16_t	lower_uid() const;


    /*! \brief Lower size.
        \return the lower 16 bits of size.
        \sa inodes_t
    */
    uint32_t	lower_size() const;

    /*! \brief Access time.
        \return the access time.
        \sa inodes_t
    */
    uint32_t	access_time() const;

    /*! \brief Change time.
        \return the change time.
        \sa inodes_t
    */
    uint32_t	change_time() const;

    /*! \brief Modification time.
        \return the modification time.
        \sa inodes_t
    */
    uint32_t	modif_time() const;

    /*! \brief Deletion time.
        \return the deletion time.
        \sa inodes_t
    */
    uint32_t	delete_time() const;


    /*! \brief Lower GID
        \return The lower 16 bits of GID.
        \sa inodes_t
    */
    uint16_t	lower_gid() const;

    /*! \brief Number of links.
        \return the number of links pointing the inode.
        \sa inodes_t
    */
    uint16_t	link_coun() const;

    /*! \brief Sector count.
        \return the sector count.
        \sa inodes_t
    */
    uint32_t	sector_count() const;


    /*! \brief Flags

        See \c \b inodes_t to have their signification.

        \return flags
        \sa inodes_t
    */
    uint32_t	flags() const;

    //! Unused area.
    uint32_t	unused1() const;

    /*! \brief Direct block pointers.

        There are 12 direct block pointers per inode.

        \return the address of the uint32_t array containing the pointers.

        \sa inodes_t
    */
    const uint32_t * block_pointers() const;

    /*! \brief Simple indirect block pointer.
        \return the block number of the simple indirect block pointer.
        \sa inodes_t
    */
    uint32_t	simple_indirect_block_pointer() const;


    /*! \brief Double indirect block pointer.
        \return the block number of the double indirect block pointer.
        \sa inodes_t
    */
    uint32_t	double_indirect_block_pointer() const;

    /*! \brief Simple indirect block pointer.
        \return the block number of the triple indirect block pointer.
        \sa inodes_t
    */
    uint32_t	triple_indirect_block_pointer() const;

    /*! \brief NFS generation number.
        \return the NFS generation number.
        \sa inodes_t
    */
    uint32_t	generation_number_nfs() const;

    /*! \brief EXtended attribute block.
        \return the block number of the extended attribute.
        \sa inodes_t
    */
    uint32_t	file_acl_ext_attr() const;

    /*! \brief Upper 32 bits of size.
        \return the upper 32 bits of size
        \sa inodes_t
    */
    uint32_t	upper_size_dir_acl() const;

    /*! \brief Fragment block.
        \return the address of the fragment block.
        \sa inodes_t
    */
    uint32_t	fragment_addr() const;

    /*! \brief Fragment index.
        \return the fragment index in block.
        \sa inodes_t
    */
    uint8_t	fragment_index() const;

    /*! \brief Fragment size.
        \return the fragment size.
        \sa inodes_t
    */
    uint8_t	fragment_size() const;

    //! Unused area.
    uint16_t	unused2() const;

    /*! \brief Upper uid.
        \return the upper 16 bits of user ID.
        \sa inodes_t
    */
    uint16_t	upper_uid() const;

    /*! \brief Upper gid.
        \return the upper 16 bits of group ID.
        \sa inodes_t
    */
    uint16_t	upper_gid() const;

    //! Unused area.
    uint32_t	unused3() const;

protected:
    const inodes_t *	__inode;
    const uint8_t *	__inode_array;
    uint64_t		__inode_addr;
};

#endif // INODESTRUCTURE_H_
