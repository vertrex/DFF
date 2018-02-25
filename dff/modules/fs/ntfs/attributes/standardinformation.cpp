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

#include "datetime.hpp"
#include "vfile.hpp"

#include "standardinformation.hpp"
#include "mftattributecontent.hpp"
#include "mftattribute.hpp"

#define PUSH_FLAGS(x, y)\
  if ((this->__standardInformation.flags & x) == x)\
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

StandardInformation::StandardInformation(MFTAttribute* mftAttribute) : MFTAttributeContent(mftAttribute)
{
  VFile* vfile = this->open();

  if (this->size() == 48)
  {
    if (vfile->read((void*)&(this->__standardInformation), 48) != 48)
    {
      delete vfile;
      throw std::string("Can't read attribute Standard Informations");
    }
  }
  else if(this->size() == 72)
  {
    if (vfile->read((void*)&(this->__standardInformation), sizeof(StandardInformation_s)) != sizeof(StandardInformation_s))
    {
      delete vfile;
      throw std::string("Can't read attribute Standard Informations");
    }
  }
  else
  {
    delete vfile;
    throw std::string("Can't read attribute Standard Informations");
  }
  delete vfile;
}

MFTAttributeContent*	StandardInformation::create(MFTAttribute* mftAttribute) 
{
  return (new StandardInformation(mftAttribute));
}

StandardInformation::~StandardInformation()
{
}

const std::string StandardInformation::typeName(void) const
{
  return (std::string("$STANDARD_INFORMATION"));
}

Attributes	StandardInformation::_attributes(void)
{
  Attributes	attrs;

  MAP_ATTR("Attributes", MFTAttributeContent::_attributes());

  MAP_ATTR("Creation time", this->creationTime())
  MAP_ATTR("Accessed time", this->accessedTime())
  MAP_ATTR("Altered time", this->alteredTime())
  MAP_ATTR("MFT altered time", this->mftAlteredTime())
  MAP_ATTR("Flags", this->flags()) 
  MAP_ATTR("Max versions number", this->versionsMaximumNumber()) 
  MAP_ATTR("Version number", this->versionNumber())
  MAP_ATTR("Class ID", this->classID())
  if (this->size() == 72)
  {
    MAP_ATTR("Owner ID", this->ownerID())
    MAP_ATTR("Security ID", this->securityID())
    MAP_ATTR("Quota charged", this->quotaCharged())
    MAP_ATTR("Update Sequence Number", this->USN())
  }

  return (attrs);
}

DateTime*	StandardInformation::creationTime(void) const
{
  return (new MS64DateTime(this->__standardInformation.creationTime));
}

DateTime*	StandardInformation::alteredTime(void) const
{
  return (new MS64DateTime(this->__standardInformation.alteredTime));
}

DateTime*	StandardInformation::mftAlteredTime(void) const
{
  return (new MS64DateTime(this->__standardInformation.mftAlteredTime));
}

DateTime*	StandardInformation::accessedTime(void) const
{
  return (new MS64DateTime(this->__standardInformation.accessedTime));
}

std::list<Variant_p>	StandardInformation::flags(void) const
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

uint32_t	StandardInformation::versionsMaximumNumber(void) const
{
  return (this->__standardInformation.versionsMaximumNumber);
}

uint32_t	StandardInformation::versionNumber(void) const
{
  return (this->__standardInformation.versionNumber); 
}

uint32_t	StandardInformation::classID(void) const
{
  return (this->__standardInformation.classID); 
}

uint32_t	StandardInformation::ownerID(void) const
{
  return (this->__standardInformation.ownerID); 
}

uint32_t	StandardInformation::securityID(void) const
{
  return (this->__standardInformation.securityID); 
}

uint64_t	StandardInformation::quotaCharged(void) const
{
  return (this->__standardInformation.quotaCharged);
}

uint64_t	StandardInformation::USN(void) const
{
  return (this->__standardInformation.USN); 
}
