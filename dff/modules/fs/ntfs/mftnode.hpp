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

#ifndef __NTFS_MFT_HH__
#define __NTFS_MFT_HH__

#include "ntfs_common.hpp"
#include "mftentrynode.hpp"

class NTFS;

class MappingAttributes
{
public:
  MappingAttributes(uint16_t _offset, MFTEntryNode* _entryNode) : offset(_offset), entryNode(_entryNode)  {};
  uint16_t              offset;
  MFTEntryNode*         entryNode; //because of ATTRIBUTE_LIST $data could be describe by different MFT ! 
  bool  operator==(MappingAttributes const& other) 
  {
     if ((other.offset == offset) && (other.entryNode == entryNode))
       return (true);
     return (false);
  }
};

class MappingAttributesInfo
{
public:
  std::list<MappingAttributes> mappingAttributes;
  uint64_t size;
  bool     compressed;
};

class MFTNode : public Node// MFTEntryNode
{
public:
  MFTNode(NTFS* ntfs, MFTEntryNode* mftEntryNode);
  ~MFTNode();
  void                                 setName(const std::string name);
  Attributes	                       _attributes(void);
  void		                       fileMapping(FileMapping* fm);
  void                                 setCompressed(bool isCompressed);
  void                                 setMappingAttributes(MappingAttributesInfo const& mappingAttributesInfo);
  MFTEntryNode*                        mftEntryNode(MFTEntryNode* mftENtryNode = NULL);
  bool                                 isCompressed(void) const;
  int32_t                              readCompressed(void* buff, unsigned int size, uint64_t* offset);
private:
  MFTEntryNode*	                       __mftEntryNode;
  bool                                 __isCompressed;
  std::list<MappingAttributes>         mappingAttributesOffset; 
};

#endif
