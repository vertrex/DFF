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

#ifndef __DIRECTORY_H__
#define __DIRECTORY_H__

#include <list>
#include <string>

#include "vfs.hpp"
#include "data_structure/includes/Inode.h"
#include "data_structure/includes/DirEntry.h"
#include "TwoThreeTree.hpp"
#include "Journal.h"

class FileNameRecovery;
class Directory : public Inode
{
    /*! \class Directory.
        \brief A directory's inode.

        Inherits \b \c Inode, and contains some specific methods about directories.
        A directory is like a regular file, the only difference is the file mode.

        The content of a directory is composed of <b>directory entries
        (dirent)</b>. Dirents contains an inode number and a <b>file name</b>.
        The root directory of an ext file system is usually located in the
        <b>inode 2</b>.

        This class also has a method used to browse the entire FS when the extfs
        driver is launched :  \c \b dirContent(). \c \b dirContent()
        calls an other method, \c \b searchDirEntries(), to discover what is the
        content of the directory. \c \b searchDirEntries() does not look for
        deleted entries, this is up to the \c \b FileNameRecovery class.

        For each file name, a new node is created on the vfs. When the node is
        not a regular file his size is set to \e \b 0.

        \sa DirEntry
        \sa FileNameRecovery
        \sa Inode
    */

public:

    /*! \brief Constructor.

        Initialize the journal to \c NULL. If the compatible feature 'has
        journal' is enabled, instantiate it. Instanciate the recovery class.

        \param extfs a pointer to the \c \b Extfs instance.
        \param SB a pointer to the \c \b SuperBlock instance.
	\param GD a pointer to the GroupsDescripor instance.
    */
    Directory(Extfs * extfs, const SuperBlock * SB, GroupDescriptor * GD);
    Directory(const Directory * dir);

    //! Destructor. Unallocate resources.
    ~Directory();

    /*! \brief Browse a directory content.

        Search the content of a directory by looking in his contents blocks.
        Call \c \b searchDirEntries() for each content block.

        \param parent the parent node
        \param inode the directory inode
    */
    void	dirContent(Node * parent, inodes_t * inode, uint64_t a = 0,
			   uint32_t i_nb = 0);

    /*! \brief Getting dirents.

        Read each dirent contained in a directory. Call a recovery method from
        the class \c \b FileNameRecovery if it discovers some deleted entries.

        \param content_addr the offset on the vfs
        \param end_addr the end of the current content block
        \param parent the parent Node

        \throw vfsError if something goes wrong.
    */
    uint8_t	searchDirEntries(uint64_t content_addr, uint64_t end_addr,
                                 Node * parent);

    /*! \brief Create a new vfs Node.

        \param inode_addr the address of the inode.
        \param parent the parent Node.
        \param name the name of the file.
        \param inter the inode.

        \return a pointer to the new created node.
    */
    ExtfsNode *          createNewNode(uint64_t inode_addr, Node * parent,
				       const std::string & name, inodes_t * inter);

    /*! \brief Recovery.
        \return a pointer to the \c \b FileNameRecovery instance.
    */
    FileNameRecovery *  recovery() const;

    //! Initialization
    void		dir_init();

    //! Clean resources.
    void                clean();

    TwoThreeTree *	i_list() const;

private:
    FileNameRecovery *	_recovery;
    TwoThreeTree *	__i_list;
};

#endif // __DIRECTORY_H__

