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

#ifndef __EXTENDED_ATTR__
#define __EXTENDED_ATTR__

#include <map>
#include <list>
#include <string>

#include "../../extfs.hpp"
#include "extfs_struct/xtd_attr.h"

class	ExtendedAttr
{
  /*! \class ExtendedAttr
    \brief Linux xattr (Extended attributes).

    This class purpose is to get the xattr/acl from an inode. The block number
    of the xattr is stored in the inode (the field is set to 0 if they are no
    xattr). A xattr block can be shared by several inodes.

    There are 2 main types of extended attributes:
    \li User attributes
    \li Posix acl.

    \note to set / remove xattr or acl to/from a file, the packages 'attr' and
    'acl' are available on linux.

    \note to use those functionnalyties there are 2 conditions:
    \li your kernel must support it.
    \li your file file system must be mounted with the options user_xattr and/or
    acl (depending if you need acls or xattr).
   */
  
public:

  /*! \enum type
    \brief The xattr type.
   */
  enum	type
    {
      USER_SPACE_ATTR	  = 1, /*!< User xattr. */
      POSIX_ACL		  = 2, /*!< Posix acl. */
      DEFAULT_POSIX_ACL   = 3, /*!< Default acl (for directories) */
      TRUSTED_SPACE_ATTR  = 4, /*!< Trusted space  */
      LUSTRE		  = 5, /*!< Unused */
      SECURITY_SPACE_ATTR = 6  /*!< Security */
    };

  enum	posix_acl_values
    {
      USER_INODE	    = 0x01,
      USER_ATTR		    = 0x02,
      GROUP_INODE	    = 0x04,
      GROUP_ATTR	    = 0x08,
      EFFECTIVE_RIGHTS_MASK = 0x10,
      OTHERS		    = 0x20
    };

  /*! \enum posic_acl_flags
    \brief Permissions.
   */
  enum	posic_acl_flags
    {
      EXECUTE	= 0x01, /*!< Execution. */
      WRITE	= 0x02, /*!< Writing. */
      READ	= 0x04  /*!< Reading. */
    };

  /*! \brief Constructor.
    \param block the block number of the exented attributes.
    \param block_size the size in bytes of one fs block.
   */
  ExtendedAttr(uint32_t block, uint32_t block_size);

  //! Destructor.
  ~ExtendedAttr();

  /*! \brief Initialisation.
    \param extfs a pointer to the Extfs instance.
  */
  void			init(const Extfs * extfs);

  /*! \brief Xattr parsing.
    
    Parse all extended attributes in the block.
    
    \param block_size the size of on fs block.
   */
  void			parse(uint32_t block_size);
  
  /*! \brief Posix acl.

    Get all the posix acl corresponding to the entry \e \b ent.

    \param ent a xattr_name_entries.
    \return a list of acl.
   */
  std::list<posix_acl_entries *> posix_acl(xattr_name_entries * ent);

  /*! \brief Name.
    \return the name of an extended attribute.
   */
  std::string		findName(const xattr_name_entries * ent,
				 uint32_t offset);

  /*! \brief Value.
    \return the value of an extended attribute.
   */
  std::string		findValue(const xattr_name_entries * ent);

  /*! \brief Xattr header.
    \return a pointer to the extended attribute header.
   */
  const xattr_header *	getHeader() const;

  /*! \brief User xattr
    \return a map of all user xattr with their xattr_name_entries,  name and
    value.
   */
  const std::map<xattr_name_entries *, std::pair<std::string, std::string> > &
  getUserXAttr() const;

  /*! \brief Posix acl.
    \return a map containing xattr_name_entries and a list of acl for each of
    them.
   */
  const std::map<xattr_name_entries *, std::list<posix_acl_entries * > > &
  getPosixACL() const;

  /*! \brief Acl structure size.

    \param flag used to determine the size.
    \return the size of an acl.
   */
  uint32_t	acl_size(uint16_t flag);

  /*! \brief Tag.
    \param tag the tag
    \return a human readable string.
   */
  std::string		aclTag(uint16_t tag);

  /*! \brief permissions
    \param permission the permission
    \return a human readable string.
   */
  std::string		aclPermissions(uint16_t permission);

private:
  uint32_t		_block;
  xattr_header *	_header;
  uint8_t *		_xattr_block;
  
  // entry, value
  std::map<xattr_name_entries *, std::pair<std::string, std::string > >
    _user;

  // entry, acl
  std::map<xattr_name_entries *, std::list<posix_acl_entries * > >
    _posix_acl;
};

#endif
