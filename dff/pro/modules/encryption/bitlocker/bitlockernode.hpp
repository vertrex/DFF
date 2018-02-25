/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2013 ArxSys
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
 *  Solal Jacob <sja@digital-forensic.org>
 */

#ifndef __BITLOCKERNODE_HH__
#define __BITLOCKERNODE_HH__

#include <vector>
#include "libbde.h"

#include "fso.hpp"
#include "node.hpp"

using namespace DFF;

class BitLockerVolumeNode : public Node
{
public:
  BitLockerVolumeNode(libbde_volume_t* volume, Node* parent, fso* _fso);
  ~BitLockerVolumeNode(void);

  Attributes                    _attributes(void);
private:
  void                          __setVolumeInfo(void);
  std::string                   __toGuid(uint8_t* guid); 

  libbde_volume_t*              __volume;
  DateTime*                     __creationTime;
  std::string                   __encryptionMethod;
  std::string                   __volumeIdentifier;
  std::string                   __description;
  std::list<Variant_p>          __keyProtector; 
};

#endif
