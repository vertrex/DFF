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

#ifndef __SUPER_BLOCK_
#define __SUPER_BLOCK_

#include <string>
#include <map>

#include "../../include/utils/SuperblockStructure.h"
#include "../../include/utils/SuperBlockUtils.h"

using namespace DFF;

class	Extfs;
class	SuperBlock : public SuperBlockStructure, public SuperBlockUtils
{
    /*! \class SuperBlock
        \brief The ext file system superblock.

        This block is located at 1024 bytes from the begining of the file
        system. The 1024 previous bytes are dedicated to the boot code and
        are set to 0 if there is no boot code. Some data could be hidden in
        this area. The driver create a node for it.

        The superblock is 1024 bytes big. It can be seen as the main
        configuration of the file system. All the informations stored in it
        are passed to the result class and can be diplayed by the user when
        the extfs driver has finished running.
    */

public:

    /*! \brief Constructor.

        Initialization.
    */
    SuperBlock();

    /*! \brief Desctructor.

        Do nothing.
    */
    ~SuperBlock();

    /*! \brief Super block initilization.

        Initialize the superblock, ie seek at the offset where it should be
        and then read his content. If the signature doesn't match 0xEF53
        the method \c \b sigfind() si called.

        \param fs_size the total size of the file system.
        \param vfile a pointer to the virtual file system.
        \param sb_check an option to indicate if a superblock backup search
        must be done.
	\param sb_force_addr force the adress of the superblock

        \throw vfsError if the initilization failed.
    */
    void    init(VFile * vfile, bool sb_check, uint64_t sb_force_addr);

    void    force_addr(VFile * vfile, uint64_t addr);

    /*! \brief Check the validity of the superblock.
        \return true if it is considered as valid, false otherwise.
    */
    bool    sanity_check() const;

    /*! \brief Find super block backup.

        The method \c \b sigfind() try locating the signature \c \b #__SB_SIG of
        the superblock to find possible backups. I dont know yet how it will
        work though... It looks every 1024 bytes if the signature \c \b
        #__SB_SIG could be found at bytes 56.

        \warning \b \c sigfind() is only called when the superblock seems to be
        corrupted. False hits must be expected.

        \param fs_size the file system size in bytes.
        \param vfile a pointer to the virtual file system, used to perform
        reads and seeks.

        \return false is no backup were, true otherwise.
    */
    bool            sigfind(VFile * vfile);

    /*! \brief Superblock offset on file system.

        The offset is set to #__BOOT_CODE_SIZE by default.

        \return the offset of the superblock on the vfs.
        \warning If the returned value is different from #__BOOT_CODE_SIZE it
        means that this superblock is a backup and can be out of date.
    */
    uint64_t        offset() const;

    /*! \brief Most recent superblock backup.

        Seek and read to the position where the most recent backup
        is located.

        \param vfile a pointer to the virtual file system.

        \return the number of bytes read.

        \throw vfsError when the reading or seeking failed.
    */
    uint64_t        most_recent_backup(VFile * vfile) throw(vfsError);

    /*! \brief Verify file system consistency.

        Verify if the superblock offset indicated in the field
        current_block_group corresponds to the real offset on the file system.
        If no, print a warning message.
    */
    void            file_system_sanity();

    /*! \brief Read superblock.

        Goes to offset \e \b offset and read sizeof(super_block_t_) bytes.

        \param vfile a pointer to the virtual file system.
        \param offset the offset where we want to read.

        \return the number of bytes effectively read.
    */
    uint32_t          read(VFile * vfile, uint64_t offset);

    /*! \brief Group Blocks number.
        \return the number of group blocks on the file system.
    */
    uint32_t          group_number() const;

private:
    uint64_t		_offset;
   // std::auto_ptr<SuperBlockUtils>  _sb_utils;

    //offset, last written time
    std::map<uint64_t, uint32_t>  _backup_list;
};

#endif
