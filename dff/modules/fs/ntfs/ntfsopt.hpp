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

#ifndef __NTFS_NTFSOPT_HH__
#define __NTFS_NTFSOPT_HH__

#include "ntfs_common.hpp"

class NTFSOpt
{
public:
                NTFSOpt(DFF::Attributes args);
                ~NTFSOpt();
  DFF::Node*    fsNode(void) const;
  bool          recovery(void) const;
  std::string   driveName(void) const;
  bool          validateBootSector(void) const;
  bool          advancedAttributes(void) const;
private:
  DFF::Node*    __fsNode;
  bool          __validateBootSector;
  bool          __recovery;
  std::string   __driveName;
  bool          __advancedAttributes;
};

#endif
