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
#include <iostream>

#include "vfile.hpp"

#include "objectid.hpp"
#include "mftattribute.hpp"
#include "mftentrynode.hpp"

ObjectId::ObjectId(MFTAttribute* mftAttribute) : MFTAttributeContent(mftAttribute)
{
  VFile* vfile = this->open();

  if (this->size() == 16)
  {
    if (vfile->read((void*)&this->__objectId, 16) != 16)
    {
      delete vfile;
      throw std::string("$ObjectId can't read ObjectId_s.");
    }
  }
  else if (this->size() == 128)
  {
    if (vfile->read((void*)&this->__objectId, sizeof(ObjectId_s)) != sizeof(ObjectId_s))
    {
      delete vfile;
      throw std::string("$ObjectId can't read ObjectId_s.");
    }
  }
  else 
  {
    delete vfile;
    throw std::string("$ObjectId can't read ObjectId_s.");
  }
  delete vfile;
}

ObjectId::~ObjectId()
{
}

const std::string ObjectId::__objectIdToString(const uint64_t* id) const
{
  std::ostringstream  idStream;

  idStream << *id; 
  idStream << *(id+1);
  return (idStream.str());
}

const std::string ObjectId::objectId(void) const
{
  return (this->__objectIdToString(this->__objectId.objectId));
}

const std::string ObjectId::birthVolumeId(void) const
{
  return (this->__objectIdToString(this->__objectId.birthVolumeId));
}

const std::string ObjectId::birthObjectId(void) const
{
  return (this->__objectIdToString(this->__objectId.birthObjectId));
}

const std::string ObjectId::birthDomainId(void) const
{
  return (this->__objectIdToString(this->__objectId.birthDomainId));
}

Attributes	ObjectId::_attributes(void)
{
  Attributes	attrs;

  MAP_ATTR("Attributes", MFTAttributeContent::_attributes());
  MAP_ATTR("ObjectId", this->objectId());
  if (this->size() == 128)
  {
    MAP_ATTR("BirthVolumeId", this->birthVolumeId());
    MAP_ATTR("BirthObjectId", this->birthObjectId());
    MAP_ATTR("BirthDomainId", this->birthDomainId());
  }
  return (attrs);
}

const std::string ObjectId::typeName(void) const
{
  return (std::string("$OBJECT_ID"));
}

MFTAttributeContent*	ObjectId::create(MFTAttribute* mftAttribute)
{
  return (new ObjectId(mftAttribute));
}
