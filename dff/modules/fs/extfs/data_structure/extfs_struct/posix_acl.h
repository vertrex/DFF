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

#ifndef __POSIX_ACL_H__
#define __POSIX_ACL_H__

typedef struct	__posix_acl_header_s
{
  uint32	version;
}		posix_acl_header;

typedef posix_acl_header	a;
#define	 acl_version	(a.version)

typedef	struct	__posix_acl_entries
{
  uint16	type;
  uint16	permissions;
  uint32	user_group_id;
}		posix_acl_entries;

enum	posix_acl_values
  {
    USER_INODE = 0x01,
    GROUP_INODE = 0x04,
    OTHERS = 0x20,
    EFFECTIVE_RIGHTS_MASK = 0x10,
    USER_ATTR = 0x02,
    GROUP_ATTR = 0x08
  };

enum	posic_acl_flags
  {
    EXECUTE = 0x01,
    WRITE = 0x02,
    READ = 0x04
  };

#endif
