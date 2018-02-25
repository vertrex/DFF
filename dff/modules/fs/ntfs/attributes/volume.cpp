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
#include <iostream>
#include <list>

#include "vfile.hpp"

#include "volume.hpp"
#include "mftattribute.hpp"
#include "mftentrynode.hpp"

/*
 *  Volume name
 */
VolumeName::VolumeName(MFTAttribute* mftAttribute) : MFTAttributeContent(mftAttribute)
{
  this->__volumeName = NULL;
  if (this->size() == 0)
    return ;

  this->__volumeName = new uint8_t[this->size()];
  VFile* vfile = this->open();

  if ((uint64_t)vfile->read((void*)this->__volumeName, this->size()) != this->size())
  {
    delete vfile;
    delete[] this->__volumeName;
    throw std::string("$VolumeName can't read name.");
  }
  delete vfile;
}

const std::string VolumeName::volumeName(void)
{
  std::string	volumeName;
  UnicodeString((char*)this->__volumeName, this->size(), "UTF16-LE").toUTF8String(volumeName);

  return (volumeName);
}

MFTAttributeContent*	VolumeName::create(MFTAttribute* mftAttribute)
{
  return (new VolumeName(mftAttribute));
}

VolumeName::~VolumeName()
{
  delete[] this->__volumeName;
  this->__volumeName = NULL;
}

const std::string	VolumeName::typeName(void) const
{
  return (std::string("$VOLUME_NAME"));
}

Attributes	VolumeName::_attributes(void)
{
  Attributes	attrs;

  MAP_ATTR("Attributes", MFTAttributeContent::_attributes());
  MAP_ATTR("Volume name", this->volumeName())
  return (attrs);
}

/*
 *  Volume information
 */

#define PUSH_FLAGS(x, y)\
  if ((this->__volumeInformation.flags & x) == x)\
    flagsList.push_back(NEW_VARIANT(std::string(y)));

#define DIRTY           0x0001
#define RESIZE          0x0002
#define UPGRADE_VOLUME  0x0004
#define MOUNTED_NT      0x0020
#define DELETING_CHANGE 0x0040
#define REPAIR_OBJ_ID   0x0080
#define MODIFIED_CHKDSK 0x0100

VolumeInformation::VolumeInformation(MFTAttribute* mftAttribute) : MFTAttributeContent(mftAttribute)
{
  VFile* vfile = this->open();
  if (vfile->read((void*)&this->__volumeInformation, sizeof(VolumeInformation_s)) != sizeof(VolumeInformation_s))
  {
    delete vfile;
    throw std::string("$VolumeInformation can't read volume information.");
  }
  delete vfile;
}

MFTAttributeContent*	VolumeInformation::create(MFTAttribute* mftAttribute)
{
  return (new VolumeInformation(mftAttribute));
}

VolumeInformation::~VolumeInformation()
{
}

const std::string VolumeInformation::typeName(void) const
{
  return (std::string("$VOLUME_INFORMATION"));
}

uint8_t VolumeInformation::major(void) const
{
  return (this->__volumeInformation.major);
}

uint8_t VolumeInformation::minor(void) const
{
  return (this->__volumeInformation.minor);
}

const std::string VolumeInformation::version(void) const
{
  std::ostringstream version;
  uint32_t major = this->major();
  uint32_t minor = this->minor();

  version << major << "." << minor;

  if (major == 1 && (minor == 1 || minor == 2))
    version << " (Windows NT4)";
  else if (major == 2)
    version << " (Windows 2000 Beta)"; 
  else if (major == 3 && minor == 0)
    version << " (Windows 2000)"; 
  else if (major == 3 && minor == 1)
    version << " (Windows XP, 2003, Vista)";

  return (version.str());
}

std::list<Variant_p>	VolumeInformation::flags(void) const
{
  std::list<Variant_p > flagsList;

  PUSH_FLAGS(DIRTY, "Dirty");
  PUSH_FLAGS(RESIZE, "Resize $LogFile");
  PUSH_FLAGS(UPGRADE_VOLUME, "Upgrade volume next time");
  PUSH_FLAGS(MOUNTED_NT, "Mounted in NT");
  PUSH_FLAGS(DELETING_CHANGE, "Deleting change journal");
  PUSH_FLAGS(REPAIR_OBJ_ID, "Repair object IDs");
  PUSH_FLAGS(MODIFIED_CHKDSK, "Modified by chkdsk");

  return (flagsList);
}

Attributes	VolumeInformation::_attributes(void)
{
  Attributes	attrs;

  MAP_ATTR("Attributes", MFTAttributeContent::_attributes());
  MAP_ATTR("Flags", this->flags())
  MAP_ATTR("Version", this->version())
  return (attrs);
}
