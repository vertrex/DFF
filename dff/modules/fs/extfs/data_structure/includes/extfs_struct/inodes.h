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

#ifndef __INODES__H__
#define __INODES__H__
#ifndef WIN32
	#include <stdint.h>
#elif _MSC_VER >= 1600
	#include <stdint.h>
#else
	#include "wstdint.h"
#endif


/* access rights */
#define _IRUSR  400
#define _IWUSR  200
#define _IXUSR  100
#define _IRGRP  040
#define _IWGRP  020
#define _IXGRP  010
#define _IROTH  004
#define _IWOTH  002
#define _IXOTH  001

/* Encoding of the file mode.  */
#define __IFMT        0170000 /* These bits determine file type. */

/* File types.  */
#define __IFIFO       0010000 /* FIFO.  */
#define __IFCHR       0020000 /* Character device.  */
#define __IFDIR       0040000 /* Directory.  */
#define __IFBLK       0060000 /* Block device.  */
#define __IFREG       0100000 /* Regular file.  */
#define __IFLNK       0120000 /* Symbolic link.  */
#define __IFSOCK      0140000 /* Socket.  */

#define _ISTYPE(mode, mask)  (((mode) & __IFMT) == (mask))

#define _ISDIR(mode)    __ISTYPE((mode), __IFDIR)
#define _ISCHR(mode)    __ISTYPE((mode), __IFCHR)
#define _ISBLK(mode)    __ISTYPE((mode), __IFBLK)
#define _ISREG(mode)    __ISTYPE((mode), __IFREG)
#define _ISFIFO(mode)   __ISTYPE((mode), __IFIFO)
#define _ISLNK(mode)    __ISTYPE((mode), __IFLNK)
#define _ISSOCK(mode)   __ISTYPE((mode), __IFSOCK)

typedef struct	inodes_s
{
    /*! \struct inodes_s
        \brief The 'raw' structure of an inode.
        \sa Inode
    */

    //! the file mode.
    uint16_t	file_mode;

    //! Lower 16 bits of user id.
    uint16_t	lower_uid;

    //! the lower 16 bits of size.
    uint32_t	lower_size;

    //! The last access timestamp.
    uint32_t	access_time;

    //! The last change timestamp.
    uint32_t	change_time;

    //! The last modification time.
    uint32_t	modif_time;

    //! The deletion timestamp.
    uint32_t	delete_time;

    //! The 16 lower bits of group ID.
    uint16_t	lower_gid;

    //! The number of link pointing the inode.
    uint16_t	link_count;

    //! The number of sector.
    uint32_t	sector_count;

    //! Some flags.
    uint32_t	flags;

    //! Unused area. This area is OS dependent.
    uint32_t	unused1;

    //! 12 direct block pointers.
    uint32_t	block_pointers[12];

    //! Single indirect block pointer.
    uint32_t	simple_indirect_block_pointer;

    //! Double indirect block pointer.
    uint32_t	double_indirect_block_pointer;

    //! Triple indirect block pointer.
    uint32_t	triple_indirect_block_pointer;

    //! NFS generation number.
    uint32_t	generation_number_nfs;

    //! Extended attributes.
    uint32_t	file_acl_ext_attr;

    //! Upper 32 bits of size.
    uint32_t	upper_size_dir_acl;

    //! Fragment address. Obsolote on ext4.
    uint32_t	fragment_addr;

    //! Index of fragment.
    uint8_t	fragment_index;

    //! Size of fragments.
    uint8_t	fragment_size;

    //! Unused area.
    uint16_t	unused2;

    //! Upper 16 bits of user ID.
    uint16_t	upper_uid;

    //! Upper 16 bits of group ID.
    uint16_t	upper_gid;

    //! Unused area.
    uint32_t	unused3;

}		inodes_t;

typedef	struct	__ext3_4_inode_reminder
{
  /*! \struct __ext3_4_inode_reminder    
    \brief Inode fields used only on ext4.
  */

  //! Extra inode size
  uint16_t	extra_inode_size;

  //! Padding
  uint16_t	padding;

  //! Extra change time (nanoseconds)
  uint32_t	extra_change_time;

  //! Extra modification time (nanoseconds)
  uint32_t	extra_modif_time;

  //! Extra access time (nanoseconds)
  uint32_t	extra_access_time;

  //! Creation time (seconds)
  uint32_t	creation_time;

  //! Extra creation time (nanoseconds)
  uint32_t	extra_creation_time;

  //! High 32 bits for 64 bit version.
  uint32_t	version_high;
}		__inode_reminder_t;

#endif
