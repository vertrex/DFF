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

#include "ntfsopt.hpp"

NTFSOpt::NTFSOpt(DFF::Attributes args) : __fsNode(NULL), __validateBootSector(false), __recovery(false)
{
  DFF::Attributes::iterator arg;

  if (args.find("file") != args.end())
    this->__fsNode = args["file"]->value<DFF::Node* >();
  else
    throw DFF::envError("NTFS module need a file argument.");
  if (args.find("no-bootsector-check") != args.end())
    this->__validateBootSector = false;
  if (args.find("recovery") != args.end())
    this->__recovery = true;
  if (args.find("advanced-attributes") != args.end())
    this->__advancedAttributes = true;
  arg =args.find("drive-name");
  if (arg != args.end())
    this->__driveName = arg->second->value<std::string>();
  else 
    this->__driveName = "C:";
}

NTFSOpt::~NTFSOpt(void)
{
}

DFF::Node*      NTFSOpt::fsNode(void) const
{
  return (this->__fsNode);
}

bool            NTFSOpt::recovery(void) const
{
  return (this->__recovery);
}

bool            NTFSOpt::validateBootSector(void) const
{
  return (this->__validateBootSector);
}

bool            NTFSOpt::advancedAttributes(void) const
{
  return (this->__advancedAttributes);
}

std::string     NTFSOpt::driveName(void) const
{
  return (this->__driveName);
}
