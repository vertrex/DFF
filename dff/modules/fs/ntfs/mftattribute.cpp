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

#include <unicode/unistr.h>

#include "vfile.hpp"
#include "filemapping.hpp"

#include "ntfs_common.hpp"
#include "ntfs.hpp"
#include "mftentrynode.hpp"
#include "attributes/filename.hpp"
#include "attributes/mftattributecontenttype.hpp"

MFTAttribute::MFTAttribute(MFTEntryNode* mftEntryNode, uint64_t offset) : __offset(offset), __mftEntryNode(mftEntryNode), __residentAttribute(NULL), __nonResidentAttribute(NULL)
{
  VFile*  vfile = mftEntryNode->open();
  if (vfile->seek(offset) != offset)
  {
    delete vfile;
    this->destroy();
    throw std::string("MFT Attribute can't seek to attribute offset");
  }

  if (vfile->read(&this->__mftAttribute, sizeof(MFTAttribute_s)) != sizeof(MFTAttribute_s))
  {
    delete vfile;
    this->destroy();
    throw std::string("MFT Attribute can't read enough data");
  }

  if (this->typeId() == 0xffffffff) //XXX check if typeid in our typeid list/attrdef  to enforce ?
  {
    delete vfile;
    this->destroy();
    throw std::string("End of attribute");
  }

  if (this->isResident())
  {
    this->__residentAttribute = new MFTResidentAttribute();
    if (vfile->read((void*) this->__residentAttribute, sizeof(MFTResidentAttribute)) != sizeof(MFTResidentAttribute))
    {
      delete vfile;
      this->destroy();
      throw std::string("MFT can't read resident attribute");
    }
  }
  else
  {
    this->__nonResidentAttribute = new MFTNonResidentAttribute();
    if (vfile->read((void*) this->__nonResidentAttribute, sizeof(MFTNonResidentAttribute)) != sizeof(MFTNonResidentAttribute))
    {
      delete vfile;
      this->destroy();
      throw std::string("MFT can't read non-resident attribute");
    }
  }
  if (this->__mftAttribute.nameSize > 0) 
  {
    if (vfile->seek(offset + this->__mftAttribute.nameOffset) != (offset + this->__mftAttribute.nameOffset))
    {
      delete vfile;
      this->destroy();
      throw std::string("MFT can't seek to name offset");
    }
    uint16_t* name = new uint16_t[this->__mftAttribute.nameSize];
    if (vfile->read((void*)name, this->__mftAttribute.nameSize * sizeof(uint16_t)) != (int32_t)(this->__mftAttribute.nameSize * sizeof(uint16_t)))
    {
      delete vfile;
      delete[] name;
      this->destroy();
      throw std::string("MFT can't read attribute name");
    }
    UnicodeString((char*)name, this->__mftAttribute.nameSize * sizeof(uint16_t), "UTF16-LE").toUTF8String(this->__name);
    delete[] name;
  }
  delete vfile;
}

void MFTAttribute::destroy(void)
{
  if (this->__nonResidentAttribute != NULL)
  {
    delete this->__nonResidentAttribute;
    this->__nonResidentAttribute = NULL;
  }
  if (this->__residentAttribute != NULL)
  {
    delete this->__residentAttribute;
    this->__residentAttribute = NULL;
  }
}

MFTAttribute::~MFTAttribute(void)
{
  this->destroy();
}

MFTEntryNode*		MFTAttribute::mftEntryNode(void) const
{
  return (this->__mftEntryNode);
}

/*
 * Caller must delete returned MFTAttributeContent
 */
MFTAttributeContent*	MFTAttribute::content(void)
{
  for (uint8_t	i = 0; ContentTypes[i].newObject != NULL; i++)
    if (ContentTypes[i].Id == this->typeId())
      return (ContentTypes[i].newObject(this));
  return (new MFTAttributeContent(this));
}

uint64_t 		MFTAttribute::contentSize(void) const
{
  if (this->isResident())
    return (this->__residentAttribute->contentSize);

  if (this->__nonResidentAttribute->contentActualSize > this->__nonResidentAttribute->contentAllocatedSize)
    return (this->__nonResidentAttribute->contentInitializedSize);
  return (this->__nonResidentAttribute->contentActualSize);
}	

uint64_t		MFTAttribute::contentOffset(void) const
{
  if (this->isResident())
    return (this->__offset + this->__residentAttribute->contentOffset);
  return (0);
}

uint16_t		MFTAttribute::runListOffset(void) const
{
  if (!this->isResident())
    return (this->__nonResidentAttribute->runListOffset);
  throw std::string("Try to access non resident attribute on a resident attribute");
}

const std::string       MFTAttribute::name(void) const
{
  if (this->nameSize())
    return (this->__name);
  return std::string("");
}

uint64_t MFTAttribute::offset(void) const
{
  return (this->__offset);
}

bool	MFTAttribute::isResident(void) const
{
  return (!this->nonResidentFlag());
}

NTFS*	MFTAttribute::ntfs(void) const
{
  return (this->__mftEntryNode->ntfs());
}

uint32_t MFTAttribute::typeId(void) const
{
  return (this->__mftAttribute.typeId);
}

uint32_t MFTAttribute::length(void) const
{
  return (this->__mftAttribute.length);
}

uint8_t	MFTAttribute::nonResidentFlag(void) const
{
  return (this->__mftAttribute.nonResidentFlag);
}

uint8_t	MFTAttribute::nameSize(void) const
{
  return (this->__mftAttribute.nameSize);
}

uint16_t MFTAttribute::nameOffset(void) const
{
  return (this->__mftAttribute.nameOffset);
}

///XXX flags() 
uint16_t MFTAttribute::flags(void) const
{
  return (this->__mftAttribute.flags);
}

uint16_t MFTAttribute::id(void) const
{
  return (this->__mftAttribute.id);
}

uint64_t MFTAttribute::VNCStart(void) const
{
  if (this->__nonResidentAttribute)
    return (this->__nonResidentAttribute->VNCStart);
  throw std::string("No VNC start in resident attribute");
}

uint64_t MFTAttribute::VNCEnd(void) const
{
  if (this->__nonResidentAttribute)
    return (this->__nonResidentAttribute->VNCEnd);
  throw std::string("No VNC end in resident attribute");
}

bool    MFTAttribute::isCompressed(void) const
{
  if (!this->__nonResidentAttribute) //Resident can't be compressed event if flag is set
    return (false);
  return ((this->__mftAttribute.flags & 0x0001) == 0x0001);
}

bool    MFTAttribute::isEncrypted(void) const
{
  if (!this->__nonResidentAttribute) //Resident can't be compressed event if flag is set
    return (false);
  return ((this->__mftAttribute.flags & 0x4000) == 0x4000);
}

bool    MFTAttribute::isSparse(void) const
{
  if (!this->__nonResidentAttribute)
    return (false);
  return ((this->__mftAttribute.flags & 0x8000) == 0x8000);
}

uint32_t MFTAttribute::compressionBlockSize(void) const
{
  if (!this->__nonResidentAttribute)
    throw std::string("MFTAttribute can't access non resident attribute :  compression block size");
  return (1 << this->__nonResidentAttribute->compressionBlockSize);
}

uint64_t MFTAttribute::contentAllocatedSize(void) const
{
  if (!this->__nonResidentAttribute)
    throw std::string("MFTAttribute can't access non resident attribute : content allocates size");
  return (this->__nonResidentAttribute->contentAllocatedSize);
}

uint64_t MFTAttribute::contentActualSize(void) const
{
  if (!this->__nonResidentAttribute)
    throw std::string("MFTAttribute can't access non resident attribute : content actual size");
  return (this->__nonResidentAttribute->contentActualSize);
}

uint64_t MFTAttribute::contentInitializedSize(void) const
{
  if (!this->__nonResidentAttribute)
    throw std::string("MFTAttribute can't access non resident attribute : content initialized size");
  return (this->__nonResidentAttribute->contentInitializedSize);
}
