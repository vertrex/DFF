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

#ifndef __MFT_ATTRIBUTE_CONTENT_HH__
#define __MFT_ATTRIBUTE_CONTENT_HH__

#include <iostream>
#include <vector> 

#include "ntfs_common.hpp"

using namespace DFF;

class MFTAttribute;

struct RunListInfo 
{
  union 
  {
    uint8_t byte;
    struct {
             uint8_t lengthSize:4;
	     uint8_t offsetSize:4;
     	   } info;
  };
};

struct RunList
{
  int64_t    offset; //in cluster
  uint64_t   length;
};

class MFTAttributeContent : public Node
{
public:
  			        MFTAttributeContent(MFTAttribute* mftAttribute);
  virtual                       ~MFTAttributeContent();
  Attributes		        _attributes();
  MFTAttribute*                 mftAttribute(void);
  void			        fileMapping(FileMapping* fm);
  std::string		        attributeName(void) const;
  virtual const std::string	typeName(void) const;
  std::vector<RunList>          runList(void); //private & store for speed ? 
  void                          updateState(void);
  uint64_t	                _attributesState(void);
  uint64_t	                fileMappingState(void);
private:
  MFTAttribute*	                __mftAttribute;
  uint64_t                      __state;
};

#endif
