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

//#include <list>
#include <unicode/unistr.h>

#include "vfile.hpp"

#include "reparsepoint.hpp"
#include "mftattributecontent.hpp"
#include "mftattribute.hpp"

#define PUSH_FLAGS(x, y)\
  if ((this->__reparsePoint.flags & x) == x)\
    flagsList.push_back(NEW_VARIANT(std::string(y)));

//#define READONLY  	0x0001
//#define HIDDEN    	0x0002

ReparsePoint::ReparsePoint(MFTAttribute* mftAttribute) : MFTAttributeContent(mftAttribute)
{
  VFile* vfile = this->open();
 
  if (vfile->read((void*)&(this->__reparsePoint), sizeof(ReparsePoint_s)) != sizeof(ReparsePoint_s))
  {
    delete vfile;
    throw std::string("$REPARSE_POINT can't read ReparsePoint_s.");
  }

  if (targetSize() + printSize() + sizeof(ReparsePoint_s) > this->size())
  {
    delete vfile;
    throw std::string("$REPARSE_POINT size error");
  }
  
  uint64_t offset = this->targetOffset() + sizeof(ReparsePoint_s);
  if (vfile->seek(offset) != offset)
  {
    delete vfile;
    throw std::string("$REPARSE_POINT can't seek to target offset.");
  }
  uint16_t* target = new uint16_t[this->targetSize()];
  if (vfile->read((void*)target, this->targetSize()) != (int32_t)(this->targetSize()))
  {
    delete[] target;
    delete vfile;
    throw std::string("$REPARSE_POINT can't read target name.");
  }
  UnicodeString((char*)target, this->targetSize(), "UTF16-LE").toUTF8String(this->__target);
  delete[] target;

  offset = this->printOffset() + sizeof(ReparsePoint_s);
  if (vfile->seek(offset) != offset)
  {
    delete vfile;
    throw std::string("$REPARSE_POINT can't seek to print offset.");
  }
  uint16_t* print = new uint16_t[this->printSize()];
  if (vfile->read((void*)print, this->printSize()) != (int32_t)(this->printSize()))
  {
    delete[] print;
    delete vfile;
    throw std::string("$REPARSE_POINT can't read print name.");
  }
  UnicodeString((char*)print, this->printSize(), "UTF16-LE").toUTF8String(this->__print);
  delete[] print;

  delete vfile;
}

MFTAttributeContent*	ReparsePoint::create(MFTAttribute*	mftAttribute)
{
  return (new ReparsePoint(mftAttribute));
}

ReparsePoint::~ReparsePoint()
{
}

Attributes	ReparsePoint::_attributes(void)
{
  Attributes	attrs;

  MAP_ATTR("Attributes", MFTAttributeContent::_attributes())

  MAP_ATTR("Target name", this->target())
  MAP_ATTR("Print name", this->print())
  MAP_ATTR("Flags", this->flags()) 

  return (attrs);
}

uint32_t ReparsePoint::dataSize(void) const
{
  return (this->__reparsePoint.dataSize);
}

uint16_t ReparsePoint::targetOffset(void) const
{
  return (this->__reparsePoint.targetOffset);
}

uint16_t ReparsePoint::targetSize(void) const
{
  return (this->__reparsePoint.targetSize);
}

uint16_t ReparsePoint::printOffset(void) const
{
  return (this->__reparsePoint.printOffset);
}

uint16_t ReparsePoint::printSize(void) const
{
  return (this->__reparsePoint.printSize);
}

const std::string  ReparsePoint::target(void) const
{
  return (this->__target);
}

const std::string  ReparsePoint::print(void) const
{
  return (this->__print);
}

const std::string  ReparsePoint::typeName(void) const
{
  return (std::string("$REPARSE_POINT"));
}

std::list<Variant_p>	ReparsePoint::flags(void) const
{
  std::list<Variant_p > flagsList;

  //PUSH_FLAGS(READONLY, "Read only");
  //PUSH_FLAGS(HIDDEN, "Hidden");
  //PUSH_FLAGS(SYSTEM, "System");
  //PUSH_FLAGS(ARCHIVE, "Archive");
  //PUSH_FLAGS(DEVICE, "Device");
  //PUSH_FLAGS(NORMAL, "Normal");
  //PUSH_FLAGS(TEMPORARY, "Temporary");
  //PUSH_FLAGS(SPARSE, "Sparse");
  //PUSH_FLAGS(REPARSE, "Reparse point");
  //PUSH_FLAGS(COMPRESSED, "Compressed");
  //PUSH_FLAGS(OFFLINE, "Offline");
  //PUSH_FLAGS(INDEXED, "Content will not be indexed");
  //PUSH_FLAGS(ENCRYPTED, "Encrypted");

  return (flagsList);
}
