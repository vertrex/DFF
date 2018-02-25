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

#ifndef __MFT_ATTRIBUTE_HH__
#define __MFT_ATTRIBUTE_HH__

#include "ntfs_common.hpp"

using namespace DFF;

class NTFS;
class MFTEntryNode;
class MFTAttributeContent;

PACK_START
typedef struct	s_MFTResidentAttribute
{
  uint32_t	contentSize;
  uint16_t	contentOffset;
}		MFTResidentAttribute;
PACK_END

//can use an union between the two struct ?
PACK_START
typedef struct s_MFTNonResidentAttribute
{
  uint64_t	VNCStart;
  uint64_t	VNCEnd;
  uint16_t	runListOffset;
  uint16_t	compressionBlockSize;
  uint32_t	unused1;
  uint64_t	contentAllocatedSize; //size round up to cluster size if compressed multi[ple of compression blocksize
  uint64_t	contentActualSize;   //uncompressed size if compressed
  uint64_t	contentInitializedSize; //compressed size if compressed else actual/real size !
}		MFTNonResidentAttribute;
PACK_END

PACK_START
typedef struct s_MFTAttribute_s
{
  uint32_t	typeId;
  uint32_t	length;
  uint8_t	nonResidentFlag;
  uint8_t	nameSize;
  uint16_t	nameOffset;
  uint16_t	flags;  //compressed flags //XXX
  uint16_t	id;
}		MFTAttribute_s;
PACK_END

class MFTAttribute
{
private:
  std::string                   __name;
  uint64_t			__offset;
  MFTEntryNode*			__mftEntryNode;
  MFTAttribute_s		__mftAttribute;
  MFTResidentAttribute*		__residentAttribute;
  MFTNonResidentAttribute*	__nonResidentAttribute;
public:
		                MFTAttribute(MFTEntryNode* mftEntryNode, uint64_t offset);
		                ~MFTAttribute(void);
  void                          destroy(void);
  MFTEntryNode*		        mftEntryNode(void) const;
  uint64_t		        offset(void) const;
  uint32_t		        typeId(void) const;
  uint32_t		        length(void) const;
  bool			        isResident(void) const;
  uint8_t	        	nonResidentFlag(void) const;
  const std::string             name(void) const; 
  uint8_t		        nameSize(void) const;
  uint16_t		        nameOffset(void) const;
  uint16_t		        flags(void) const; 
  uint16_t		        id(void) const;
  NTFS*			        ntfs(void) const;
  uint64_t		        contentOffset(void) const;
  uint64_t		        contentSize(void) const;
  uint16_t	        	runListOffset(void) const;
  uint64_t                      VNCStart(void) const;
  uint64_t                      VNCEnd(void) const;
  bool                          isCompressed(void) const;
  bool                          isSparse(void) const;
  bool                          isEncrypted(void) const;
  uint32_t                      compressionBlockSize(void) const;
  uint64_t                      contentAllocatedSize(void) const;
  uint64_t                      contentActualSize(void) const;
  uint64_t                      contentInitializedSize(void) const;
  MFTAttributeContent*          content(void);
};

typedef std::vector<MFTAttribute* > MFTAttributes;

#endif
