/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2014 ArxSys
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
 *  Frederic Baguelin <fba@digital-forensic.org>
 */


#include "permissions.hpp"


HfspPermissions::HfspPermissions() : __permissions()
{
}


HfspPermissions::~HfspPermissions()
{
}


void		HfspPermissions::process(Node* origin, uint64_t offset) throw (std::string)
{

}


void		HfspPermissions::process(uint8_t* buffer, uint16_t size) throw (std::string)
{

}


void		HfspPermissions::process(perms permissions) throw (std::string)
{
  memcpy(&this->__permissions, &permissions, sizeof(perms));
}


uint32_t	HfspPermissions::ownerId()
{
  return bswap32(this->__permissions.uid);
}


uint32_t	HfspPermissions::groupId()
{
  return bswap32(this->__permissions.gid);
}


bool		HfspPermissions::isAdminArchived()
{
  return ((this->__permissions.adminFlags & SF_ARCHIVED) == SF_ARCHIVED);
}


bool		HfspPermissions::isAdminImmutable()
{
  return ((this->__permissions.adminFlags & SF_IMMUTABLE) == SF_IMMUTABLE);
}


bool		HfspPermissions::adminAppendOnly()
{
  return ((this->__permissions.adminFlags & SF_APPEND) == SF_APPEND);
}


bool		HfspPermissions::canBeDumped()
{
  return !((this->__permissions.userFlags & UF_NODUMP) == UF_NODUMP);
}


bool		HfspPermissions::isUserImmutable()
{
  return ((this->__permissions.userFlags & UF_IMMUTABLE) == UF_IMMUTABLE);
}

bool		HfspPermissions::userAppendOnly()
{
  return ((this->__permissions.userFlags & UF_APPEND) == UF_APPEND);
}


bool		HfspPermissions::isOpaque()
{
  return ((this->__permissions.userFlags & UF_OPAQUE) == UF_OPAQUE);
}


bool		HfspPermissions::isSuid()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & HFS_ISUID) == HFS_ISUID);
}


bool		HfspPermissions::isGid()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & HFS_ISGID) == HFS_ISGID);
}


bool		HfspPermissions::stickyBit()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & HFS_ISTXT) == HFS_ISTXT);
}


bool		HfspPermissions::isUserReadable()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & HFS_IRUSR) == HFS_IRUSR);
}


bool		HfspPermissions::isUserWritable()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & HFS_IWUSR) == HFS_IWUSR);
}


bool		HfspPermissions::isUserExecutable()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & HFS_IXUSR) == HFS_IXUSR);
}


bool		HfspPermissions::isGroupReadable()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & HFS_IRGRP) == HFS_IRGRP);
}

bool		HfspPermissions::isGroupWritable()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & HFS_IWGRP) == HFS_IWGRP);
}


bool		HfspPermissions::isGroupExecutable()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & HFS_IXGRP) == HFS_IXGRP);
}


bool		HfspPermissions::isOtherReadable()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & HFS_IROTH) == HFS_IROTH);
}


bool		HfspPermissions::isOtherWritable()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & HFS_IWOTH) == HFS_IWOTH);
}


bool		HfspPermissions::isOtherExecutable()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & HFS_IXOTH) == HFS_IXOTH);
}


bool		HfspPermissions::isFifo()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & HFS_IFIFO) == HFS_IFIFO);
}


bool		HfspPermissions::isCharacter()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & HFS_IFCHR) == HFS_IFCHR);
}


bool		HfspPermissions::isDirectory()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & HFS_IFDIR) == HFS_IFDIR);
}


bool		HfspPermissions::isBlock()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & HFS_IFBLK) == HFS_IFBLK);
}


bool		HfspPermissions::isRegular()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & HFS_IFREG) == HFS_IFREG);
}


bool		HfspPermissions::isSymbolicLink()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & HFS_IFLNK) == HFS_IFLNK);
}


bool		HfspPermissions::isSocket()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & HFS_IFSOCK) == HFS_IFSOCK);
}


bool		HfspPermissions::isWhiteout()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & HFS_IFWHT) == HFS_IFWHT);
}


uint32_t	HfspPermissions::linkReferenceNumber()
{
  return bswap32(this->__permissions.special.inodeNum);
}


uint32_t	HfspPermissions::linkCount()
{
  return bswap32(this->__permissions.special.linkCount);
}


uint32_t	HfspPermissions::deviceNumber()
{
  return bswap32(this->__permissions.special.rawDevice);
}


Attributes	HfspPermissions::attributes()
{
  Attributes	attrs;
 
  attrs["uid"] = new Variant(this->ownerId());
  attrs["gid"] = new Variant(this->groupId());
  
  Attributes	aflags;
  aflags["Archived"] = new Variant(this->isAdminArchived());
  aflags["Immutable"] = new Variant(this->isAdminImmutable());
  aflags["Append only"] = new Variant(this->adminAppendOnly());
  attrs["Admin flags"] = new Variant(aflags);

  Attributes	uflags;
  uflags["Dumpable"] = new Variant(this->canBeDumped());
  uflags["Immutable"] = new Variant(this->isUserImmutable());
  uflags["Append only"] = new Variant(this->userAppendOnly());
  attrs["User flags"] = new Variant(uflags);

  Attributes	rights;
  Attributes	umode;
  umode["Read"] = new Variant(this->isUserReadable());
  umode["Write"] = new Variant(this->isUserWritable());
  umode["Execute"] = new Variant(this->isUserExecutable());
  rights["User"] = new Variant(umode);

  Attributes	gmode;
  gmode["Read"] = new Variant(this->isGroupReadable());
  gmode["Write"] = new Variant(this->isGroupWritable());
  gmode["Execute"] = new Variant(this->isGroupExecutable());
  rights["Group"] = new Variant(gmode);

  Attributes	omode;
  omode["Read"] = new Variant(this->isOtherReadable());
  omode["Write"] = new Variant(this->isOtherWritable());
  omode["Execute"] = new Variant(this->isOtherExecutable());
  rights["Other"] = new Variant(gmode);
  attrs["Rights"] = new Variant(rights);

  Attributes	ftype;
  ftype["Named pipe"] = new Variant(this->isFifo());
  ftype["Character"] = new Variant(this->isCharacter());
  ftype["Directory"] = new Variant(this->isDirectory());
  ftype["Block"] = new Variant(this->isBlock());
  ftype["Regular"] = new Variant(this->isRegular());
  ftype["Symbolic link"] = new Variant(this->isSymbolicLink());
  ftype["Socket"] = new Variant(this->isSocket());
  ftype["Whiteout"] = new Variant(this->isWhiteout());
  attrs["File type"] = new Variant(ftype);

  return attrs;
}
