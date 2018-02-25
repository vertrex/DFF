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

#include "export.hpp"

/* permissions bits: */
#define _ISUID  0x0004000
#define _ISGID  0x0002000
#define _ISSTI  0x0001000

/* access rights */
#define _IRUSR 00400
#define _IWUSR 00200
#define _IXUSR 00100
#define _IRGRP 00040
#define _IWGRP 00020
#define _IXGRP 00010
#define _IROTH 00004
#define _IWOTH 00002
#define _IXOTH 00001

/* Encoding of the file mode.  */
#define __IFMT        0170000 /* These bits determine file type.  */

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

PACK_START
typedef struct	inodes_s
{
  uint16	file_mode;
  uint16	lower_uid;
  uint32	lower_size;
  uint32	access_time;
  uint32	change_time;
  uint32	modif_time;
  uint32	delete_time;
  uint16	lower_gid;
  uint16	link_count;
  uint32	sector_count;
  uint32	flags;
  uint32	unused1;
  uint32	block_pointers[12];
  uint32	simple_indirect_block_pointer;
  uint32	double_indirect_block_pointer;
  uint32	triple_indirect_block_pointer;
  uint32	generation_number_nfs;
  uint32	file_acl_ext_attr;
  uint32	upper_size_dir_acl;
  uint32	fragment_addr;
  uchar		fragment_index;
  uchar		fragment_size;
  uint16	unused2;
  uint16	upper_uid;
  uint16	upper_gid;
  uint32	unused3;
}	    inodes_t;
PACK_END

#endif
