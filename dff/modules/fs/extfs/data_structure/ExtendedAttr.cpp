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

#include "vfile.hpp"

#include "includes/ExtendedAttr.h"

ExtendedAttr::ExtendedAttr(uint32_t block, uint32_t block_size)
{
  _block = block;
  _header = NULL;
  _xattr_block =  (uint8_t *)operator new(block_size * sizeof(uint8_t));
}

ExtendedAttr::~ExtendedAttr()
{
  std::map<xattr_name_entries *, uint8_t *>::iterator	it;
  _user.clear();
  _posix_acl.clear();
  delete _xattr_block;
}

void		ExtendedAttr::init(const Extfs * extfs)
{
  uint64_t	addr;

  if (!extfs || !_block)
      return ;
  addr = _block * extfs->SB()->block_size();
  extfs->vfile()->seek(addr);
  extfs->vfile()->read(_xattr_block,
       extfs->SB()->block_size() * sizeof(uint8_t));
  _header = (xattr_header *)_xattr_block;
  parse(extfs->SB()->block_size());
}

void	ExtendedAttr::parse(uint32_t block_size)
{
  xattr_name_entries * ent = NULL; 
  uint32_t	offset;

  for (offset = sizeof(xattr_header); offset < (block_size / 2);
       offset += (sizeof(xattr_name_entries) + ent->name_length))
    {
      ent = (xattr_name_entries *)(_xattr_block + offset);
      if (ent->attr_type == ExtendedAttr::POSIX_ACL
	  || ent->attr_type == ExtendedAttr::DEFAULT_POSIX_ACL)
	_posix_acl.insert(std::make_pair(ent, posix_acl(ent)));
      else if (ent->attr_type == ExtendedAttr::USER_SPACE_ATTR
	       || ent->attr_type == ExtendedAttr::TRUSTED_SPACE_ATTR
	       || ent->attr_type == ExtendedAttr::SECURITY_SPACE_ATTR)
	{
	  std::pair<std::string, std::string> name_value
	    = std::make_pair(findName(ent, offset), findValue(ent));
	  _user.insert(std::make_pair(ent, name_value));
	}
    }
}

std::string	ExtendedAttr::findName(const xattr_name_entries * ent,
				       uint32_t offset)
{
  return
    std::string((char *)(_xattr_block + offset + sizeof(xattr_name_entries)),
		ent->name_length);
}

std::string	ExtendedAttr::findValue(const xattr_name_entries * ent)
{
  return std::string((char *)(_xattr_block + ent->value_offset), ent->size);
}

std::list<posix_acl_entries *>
ExtendedAttr::posix_acl(xattr_name_entries * ent)
{
  std::list<posix_acl_entries *>	acl_list;

  for (unsigned int offset = sizeof(posix_acl_header); offset < ent->size;)
    {
      posix_acl_entries * acl
	= (posix_acl_entries *)(_xattr_block + ent->value_offset + offset);
      acl_list.push_back(acl);
      offset += acl_size(acl->type);
    }
  return acl_list;
}

const xattr_header *	ExtendedAttr::getHeader() const
{
  return _header;
}

const std::map<xattr_name_entries *, std::pair<std::string, std::string> > &
ExtendedAttr::getUserXAttr() const
{
  return _user;
}

const std::map<xattr_name_entries *, std::list<posix_acl_entries * > > &
ExtendedAttr::getPosixACL() const
{
  return _posix_acl;
}

std::string	ExtendedAttr::aclTag(uint16_t tag)
{
  // TODO
  (void)tag; //to avoid a warning

  return std::string("");
}

std::string	ExtendedAttr::aclPermissions(uint16_t permission)
{
  if (permission == ExtendedAttr::EXECUTE)
    return "x";
  else if (permission == ExtendedAttr::WRITE)
    return "w";
  else if (permission == ExtendedAttr::READ)
    return "r";
  return "?";
}

uint32_t	ExtendedAttr::acl_size(uint16_t flag)
{
  if (flag == ExtendedAttr::USER_INODE
      || flag == ExtendedAttr::GROUP_INODE
      || flag == ExtendedAttr::OTHERS)
    return 2 * sizeof(uint16_t);
  return sizeof(posix_acl_entries);
}
