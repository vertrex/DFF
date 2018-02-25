/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *  
 * See http: *www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 * 
 * Author(s):
 *  Solal Jacob <sja@digital-forensic.org>
 */

#include <list>
#include <unicode/unistr.h>

#include "datetime.hpp"
#include "vfile.hpp"

#include "filename.hpp"
#include "mftattributecontent.hpp"
#include "mftattribute.hpp"

#define PUSH_FLAGS(x, y)\
  if ((this->__fileName.flags & x) == x)\
    flagsList.push_back(NEW_VARIANT(std::string(y)));

#define READONLY  	0x0001
#define HIDDEN    	0x0002
#define SYSTEM 	  	0x0004
#define ARCHIVE	  	0x0020
#define DEVICE	  	0x0040
#define NORMAL	  	0x0080
#define TEMPORARY 	0x0100
#define SPARSE	  	0x0200
#define REPARSE	  	0x0400
#define COMPRESSED	0x0800
#define OFFLINE		0x1000
#define INDEXED		0x2000
#define ENCRYPTED	0x4000

FileName::FileName(MFTAttribute* mftAttribute) : MFTAttributeContent(mftAttribute)
{
  VFile* vfile = this->open();
 
  if (vfile->read((void*)&(this->__fileName), sizeof(FileName_s)) != sizeof(FileName_s))
  {
    delete vfile;
    throw std::string("$FILE_NAME can't read FileName_s.");
  }
  uint16_t* name = new uint16_t[this->nameLength()];
  if (vfile->read((void*)name, this->nameLength() * sizeof(uint16_t)) != (int32_t)(this->nameLength() *sizeof(uint16_t)))
  {
    delete[] name;
    delete vfile;
    throw std::string("$FILE_NAME can't read name.");
  }
  UnicodeString((char*)name, this->nameLength() * sizeof(uint16_t), "UTF16-LE").toUTF8String(this->__name);
  delete[] name;
  delete vfile;
}

MFTAttributeContent*	FileName::create(MFTAttribute*	mftAttribute)
{
  return (new FileName(mftAttribute));
}

FileName::~FileName()
{
}

Attributes	FileName::_attributes(void)
{
  Attributes	attrs;

  MAP_ATTR("Attributes", MFTAttributeContent::_attributes())

  MAP_ATTR("Parent MFT entry id", this->parentMFTEntryId())
  MAP_ATTR("Parent sequence", this->parentSequence())
  MAP_ATTR("Creation time", this->creationTime())
  MAP_ATTR("Accessed time", this->accessedTime())
  MAP_ATTR("Modification time", this->modificationTime())
  MAP_ATTR("MFT modification time", this->mftModificationTime())
  MAP_ATTR("Allocated size", this->allocatedSize())
  MAP_ATTR("Real size", this->realSize())
  MAP_ATTR("Reparse value", this->reparseValue())
  MAP_ATTR("Namespace", this->nameSpace())
  MAP_ATTR("Name", this->name())
  MAP_ATTR("Flags", this->flags()) 

  return (attrs);
}

const std::string  FileName::name(void) const
{
  return (this->__name);
}

const std::string  FileName::typeName(void) const
{
  return (std::string("$FILE_NAME_" + this->nameSpace()));
}

uint64_t	FileName::parentMFTEntryId(void) const
{
  uint64_t mftEntryId = 0;

  mftEntryId = *((uint32_t*)&this->__fileName.parentMFTEntryId);
  *((uint32_t*)&mftEntryId + 1) = *((uint16_t*)&this->__fileName.parentMFTEntryId + 2);

  return (mftEntryId);
}

uint16_t        FileName::parentSequence(void) const
{
  return (this->__fileName.parentSequence);
}

DateTime*       FileName::creationTime(void) const
{
  return (new MS64DateTime(this->__fileName.creationTime));
}

DateTime*       FileName::modificationTime(void) const
{
  return (new MS64DateTime(this->__fileName.modificationTime));
}

DateTime*       FileName::mftModificationTime(void) const
{
  return (new MS64DateTime(this->__fileName.mftModificationTime));
}

DateTime*       FileName::accessedTime(void) const
{
  return (new MS64DateTime(this->__fileName.accessedTime));
}

uint64_t	FileName::allocatedSize(void) const
{
  return (this->__fileName.allocatedSize);
}

uint64_t	FileName::realSize(void) const
{
  return (this->__fileName.realSize);
}

uint32_t	FileName::reparseValue(void) const
{
  return (this->__fileName.reparseValue);
}

uint8_t		FileName::nameLength(void) const
{
  return (this->__fileName.nameLength);
}

const std::string	FileName::nameSpace(void) const
{
  if (this->__fileName.nameSpace == FILENAME_NAMESPACE_POSIX)
    return std::string("Posix");
  else if (this->__fileName.nameSpace == FILENAME_NAMESPACE_WIN32)
    return std::string("Win32");
  else if (this->__fileName.nameSpace == FILENAME_NAMESPACE_DOS)
    return std::string("DOS");
  else if (this->__fileName.nameSpace == FILENAME_NAMESPACE_DOS_WIN32)
    return std::string("DOS_Win32");
  return std::string("Unknown");
}

uint8_t	FileName::nameSpaceID(void) const
{
  return (this->__fileName.nameSpace);
}

std::list<Variant_p>	FileName::flags(void) const
{
  std::list<Variant_p > flagsList;

  PUSH_FLAGS(READONLY, "Read only");
  PUSH_FLAGS(HIDDEN, "Hidden");
  PUSH_FLAGS(SYSTEM, "System");
  PUSH_FLAGS(ARCHIVE, "Archive");
  PUSH_FLAGS(DEVICE, "Device");
  PUSH_FLAGS(NORMAL, "Normal");
  PUSH_FLAGS(TEMPORARY, "Temporary");
  PUSH_FLAGS(SPARSE, "Sparse");
  PUSH_FLAGS(REPARSE, "Reparse point");
  PUSH_FLAGS(COMPRESSED, "Compressed");
  PUSH_FLAGS(OFFLINE, "Offline");
  PUSH_FLAGS(INDEXED, "Content will not be indexed");
  PUSH_FLAGS(ENCRYPTED, "Encrypted");

  return (flagsList);
}
