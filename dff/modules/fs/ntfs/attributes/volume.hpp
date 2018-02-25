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

#ifndef __VOLUME_HH__
#define __VOLUME_HH__

#include "ntfs_common.hpp"
#include "mftattributecontent.hpp"

class VolumeName : public MFTAttributeContent
{
public:
		                VolumeName(MFTAttribute* mftAttribute);
			        ~VolumeName();
  Attributes		        _attributes(void);
  const std::string             volumeName(void);
  const std::string             typeName(void) const;
  static MFTAttributeContent*	create(MFTAttribute* mftAttribute);
private:
  uint8_t*                      __volumeName;
};


PACK_START
typedef struct s_VolumeInformation_s
{
  uint64_t      unused;
  uint8_t       major;
  uint8_t       minor; 
  uint16_t      flags;
}		VolumeInformation_s;
PACK_END

class VolumeInformation : public MFTAttributeContent
{
public:
		                VolumeInformation(MFTAttribute* mftAttribute);
			        ~VolumeInformation();
  uint8_t                       major(void) const;
  uint8_t                       minor(void) const;
  std::list<Variant_p>          flags(void) const;
  const std::string             version(void) const;
  const std::string             typeName(void) const;
  Attributes		        _attributes(void);
  static MFTAttributeContent*	create(MFTAttribute* mftAttribute);
private:
  VolumeInformation_s           __volumeInformation;
};

#endif
