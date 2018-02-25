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

#ifndef __EXT_ATTR_HEADER_H__
#define __EXT_ATTR_HEADER_H__
#ifndef WIN32
	#include <stdint.h>
#elif _MSC_VER >= 1600
	#include <stdint.h>
#else
	#include "wstdint.h"
#endif


typedef struct	__ext_attr_header_s
{
  /*! \struct __ext_attr_header_s
    \brief The xattr header structure.
    \sa ExtendedAttr
   */

  //! Signature (0xEA020000)
  uint32_t	signature; //0xEA020000

  //! Number of inode using this xattr block.
  uint32_t	reference_count;

  //! Unused.
  uint32_t	blocks_number;

  //! Hash of the attribute.
  uint32_t	hash;

  //! Reserved.
  uint32_t	reserved[4];
}		xattr_header;

typedef	struct	__ext_attr_name_entries_s
{
  /*! \struct __ext_attr_name_entries_s
    \brief The xattr name entries.
    \sa ExtendedAttr
  */

  //! Name length.
  uint8_t		name_length;

  //! Type of extended attr.
  uint8_t		attr_type;

  //! Offset to the value.
  uint16_t	value_offset;

  //! Block number of value (unused)
  uint32_t	block_location;

  //! Value size.
  uint32_t	size;

  //! Value hash.
  uint32_t	hash;
}		xattr_name_entries;

typedef struct	__posix_acl_header_s
{
  /*! \struct __posix_acl_header_s
    \brief acl version
   */

  //! Version number.
  uint32_t	version;
}		posix_acl_header;

typedef	struct	__posix_acl_entries
{
  /*! \struct __posix_acl_entries
    \brief The posix acl structure.
    \sa ExtendedAttr
   */

  //! Type of the ACL.
  uint16_t	type;

  //! Permissions (write, execute or read).
  uint16_t	permissions;
  
  //! User or group id (not always used).
  uint32_t	user_group_id;
}		posix_acl_entries;

#endif
