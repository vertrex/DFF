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

#ifndef __EXT_ATTR_NAME_ENTRIES_H__
#define __EXT_ATTR_NAME_ENTRIES_H__

enum	type
  {
    USER_SPACE_ATTR = 1,
    POSIX_ACL = 2,
    DEFAULT_POSIX_ACL = 3,
    TRUSTED_SPACE_ATTR = 4,
    LUSTRE = 5,
    SECURITY_SPACE_ATTR = 6
  };

typedef	struct	__ext_attr_name_entries_s
{
  uchar		name_length;
  uchar		attr_type;
  uint16	value_offset;
  uint32	block_location;
  uint32	size;
  uint32	hash;
}		ext_attr_name_entries;

#endif
