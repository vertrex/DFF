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

#ifndef SUPERBLOCKSTRUCTURE_H_
#define SUPERBLOCKSTRUCTURE_H_

#include <memory>

#include "../../data_structure/includes/extfs_struct/super_block.h"
#include "vfs.hpp"

/*!
  \def MAX_BLK_SIZE
  
  \brief The maximum size of a file system block.
*/
#define MAX_BLK_SIZE	64536

class   SuperBlockStructure
{
public:

    /*! \enum FS_STATE
        \brief File system state.
    */
    enum    FS_STATE
    {
            _FS_STATE_CLEAN  = 0x0001, /*!< The file system is clean. */
            _FS_HAS_ERRORS   = 0x0002, /*!< The file system has errors. */
            _ORPHAN_RECOVERY = 0x0004 /*!< Orphan inodes are being recovered. */
    };

    /*! \enum ERROR_HANDLING_METHOD
        \brief Error handling method.
    */
    enum    ERROR_HANDLING_METHOD
    {
            _ERROR_HANDLING_CONTINUE = 1, /*!< Continue. */
            _RO_REMOUNT = 2, /*!< Remount as read only. */
            _PANIC = 3 /*!< Oh yeeaah. */
    };

    /*! \enum OS_CREATOR
        \brief Operating system who created the file system.
    */
    enum    OS_CREATOR
    {
            _OS_LINUX, /*!< Linux. */
            _OS_GNU_HURD, /*!< GNU Hurd */
            _OS_MASIX, /*!< Masix */
            _OS_FREE_BSD, /*!< Free BSD */
            _OS_LITES /*!< Lites */
    };

    /*! \enum C_FEATURES
        \brief Compatible features flag.
    */
    enum    C_FEATURES
    {
            _COMP_PDIR = 0x0001, /*!< Preallocate directory blocks. Used to
                                    reduce fragmentation. */
            _COMP_AFS_INODE = 0x0002, /*!< Afs server inode. */
            _COMP_HAS_JOURNAL = 0x0004, /*!< The file system uses a journal. */
            _COMP_EXT_ATTR = 0x0008, /*!< Inode have extended attributes. */
            _COMP_CAN_RESIZE = 0x0010, /*!<  File system can resize itself to
                                            use bigger partitions. */
            _COMP_DIR_HASH_INDEX = 0x0020 /*!< Directories use a hash index. */
    };

    /*! \enum INC_FEATURES
        \brief Incompatible features.
    */
    enum    INC_FEATURES
    {
            _COMPRESSION = 0x0001, /*!< Compression. */
            _DIR_FILE_TYPE = 0x0002, /*!< The file type is contained in
                                        dirents. */
            _NEEDS_RECOVERY = 0x0004, /*!< A recovery is needed by the file
                                        system. */
            _JOURNAL_DEVICE = 0x0008, /*!< Use a journal device. */
	    _META_BG = 0x0010,
	    _EXTENTS = 0x0040,
	    _64BITS = 0x0080,
	    _MMP = 0x0100,
	    _FLEX_BG = 0x0200,
	    _EA_INODE = 0x0400,
	    _DIRENT_DATA = 0x1000
    };

    /*! \enum RO_FEATURES
        \brief Read-only features.
    */
    enum    RO_FEATURES
    {
            _SPARSE_SUPERBLOCK = 0x0001, /*!< Sparse group descriptor and
                                            superblock. */
            _LARGE_FILE = 0x0002, /*!< File system can contain large files. */
            _B_TREES = 0x0004, /*!< Directories use b-trees. */
	    _HUGE_FILE = 0x0008,
	    _GD_CSUM = 0x0010,
	    _DIR_NLINK = 0x0020,
	    _EXTRA_ISIZE = 0x0040
    };


    //! Constructor. Do nothing.
    SuperBlockStructure();

    //! Desctructor. Do nothing.
    ~SuperBlockStructure();

    //! return a pointer to the \c super_block_t_.
    super_block_t_* getSuperBlock() const;

    /*! \brief Inodes number on file system.
        \return the number of inodes on the file system.
        \sa super_block_t_
    */
    uint32_t	        inodesNumber() const;

    /*! \brief Blocks number on file system.
        \return the number of blocks in the file system.
        \sa super_block_t_
    */
    uint32_t	        blocks_number() const;

    //! Reserved block number.
    uint32_t	        r_blocks_number() const;

    //! Unallocated block number.
    uint32_t	        u_blocks_number() const;

    //! Unallocated inodes number.
    uint32_t	        u_inodes_number() const;

    //! First data block.
    uint32_t	        first_block() const;

    /*! \brief Size of blocks.

        To get the size, we must shift 1024 to the left. The field block_size
        of the structure contains the number of places 1024 must be shift:
        \code
            uint32_t  block_size;

            block_size = 1024 << _super_block.block_size;
        \endcode

        \return the size of a file system block.
    */
    uint32_t	        block_size() const;

    //! Size of fragments.
    uint32_t	        fragment_size() const;

    //! Number of blocks per groups.
    uint32_t	        block_in_groups_number() const;

    //! Number of fragments per group.
    uint32_t	        fragment_in_group_number() const;

     //! Number of inodes per group.
    uint32_t	        inodes_in_group_number() const;

    //! Last mount time.
    uint32_t	        last_mount_time() const;

    //! Current mount count.
    uint32_t	        last_written_time() const;

    //! Maximum  mount number.
    uint16_t	        current_mount_count() const;

    //! Signature. Must be \b 0xEF53
    uint16_t	        max_mount_count() const;

    /*! \brief Signature.

        The signature must be \c 0xEF53.

        \return the superblock signature.

        \sa inodes_t
    */
    uint16_t	        signature() const;

    /*! \brief File system state.

        Can take the following values :
            \li #_FS_STATE_CLEAN
            \li #_FS_HAS_ERRORS
            \li #_ORPHAN_RECOVERY

        \return the file system state.
    */
    uint16_t	        fs_state() const;

    /*! \brief Error handling method.

        Can take the following values :
            \li #_ERROR_HANDLING_CONTINUE
            \li #_RO_REMOUNT
            \li #_PANIC

        \return the handling method error.
    */
    uint16_t	        error_handling_method() const;

    //! Version.
    uint16_t	        minor_version() const;

    //! Time of the last consistency check.
    uint32_t	        l_consistency_ct() const;

    //! Interval between consistency checks.
    uint32_t	        consitency_forced_interval() const;

    /*! \brief OS creator.

        OS who created the file system.

        Can take the following values:
            \li #_OS_LINUX
            \li #_OS_GNU_HURD
            \li #_OS_MASIX
            \li #_OS_FREE_BSD
            \li #_OS_LITES

        \return the creator OS.
    */
    uint32_t	        creator_os() const;

    //! Version.
    uint32_t	        major_version() const;

    //! UID.
    uint16_t	        uid_reserved_block() const;

    //! GID.
    uint16_t	        gid_reserved_block() const;

    //! First non reserved inode number.
    uint32_t	        f_non_r_inodes() const;

    //! Size of an inode structure.
    uint16_t	        inodes_struct_size() const;

    //! Block group number (if we are in a superblock backup).
    uint16_t	        current_block_group() const;

    /*! \brief Compatible features.

        Can take the following values :
            \li #_COMP_PDIR
            \li #_COMP_AFS_INODE
            \li #_COMP_HAS_JOURNAL
            \li #_COMP_EXT_ATTR
            \li #_COMP_CAN_RESIZE
            \li #_COMP_DIR_HASH_INDEX

        \return the field compatible features.
    */
    uint32_t	        compatible_feature_flags() const;

    /*! \brief Incompatible features.

        Can take the following values:
            \li #_COMPRESSION
            \li #_DIR_FILE_TYPE
            \li #_NEEDS_RECOVERY
            \li #_JOURNAL_DEVICE

        \return the incompatible features flag.
    */
    uint32_t	        incompatible_feature_flags() const;

    /*! \brief Read only features.

        Can take the following values:
            \li #_SPARSE_SUPERBLOCK
            \li #_LARGE_FILE
            \li #_B_TREES

        \return the read only features flag.
    */
    uint32_t	        ro_features_flags() const;

    //! File system ID.
    const uint8_t *	file_system_ID() const;

    //! Name of the volume.
    const uint8_t *	volume_name() const;

    //! Path to where it was last mounted.
    const uint8_t *	path_last_mount() const;

    //! Allocation algorithm.
    uint32_t	        algorithm_bitmap() const;

    //! Preallocation for file.
    uint8_t	        preallocate_blocks_files() const;

    //! Preallocation for directories.
    uint8_t	        preallocate_block_dir() const;

    //! Unused area.
    uint16_t	        unused() const;

    //! Journal ID.
    const uint8_t *	journal_id() const;

    //! Journal inode (usually 8).
    uint32_t	        journal_inode() const;

    //! Journal device (feature).
    uint32_t	        journal_device() const;

    //! Orphan inode list number.
    uint32_t	        orphan_node_list() const;

    //! Unused area.
    const uint32_t *	empty() const;

private:
    super_block_t_ *    _super_block;
    uint8_t *		__sb_array;
};

#endif // SUPERBLOCKSTRUCTURE_H_
