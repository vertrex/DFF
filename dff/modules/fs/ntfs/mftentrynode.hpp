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

#ifndef __NTFS_MFT_ENTRY_NODE_HH__
#define __NTFS_MFT_ENTRY_NODE_HH__

#include "ntfs_common.hpp"
#include "attributes/indexroot.hpp"

using namespace DFF;

class NTFS;
class MFTAttribute;
typedef std::vector<MFTAttribute* > MFTAttributes;

#define		MFT_SIGNATURE_FILE	0x454C4946
#define		MFT_SIGNATURE_BAAD	0x44414142

PACK_START
typedef struct s_MFTEntry
{
  uint32_t	signature;
  uint16_t	fixupArrayOffset;
  uint16_t	fixupArrayEntryCount;
  uint64_t	LSN;
  uint16_t	sequence;
  uint16_t	linkCount;
  uint16_t	firstAttributeOffset;
  uint16_t	flags;
  uint32_t	usedSize;
  uint32_t	allocatedSize;
  uint64_t	fileReferenceToBaseRecord; //reference to 1 st mft when is multi-mft based 
  uint16_t	nextAttributeID;
}		MFTEntry;
PACK_END

class MFTEntryNode : public Node
{
private:
  NTFS*			        __ntfs; 
  Node*			        __mftNode;
  MFTEntry		        __MFTEntry;
  uint64_t		        __offset;
  uint64_t		        __state;
  void                          readAttributes(void);
public:
			        MFTEntryNode(NTFS* ntfs, Node* mftNode, uint64_t offset, std::string name, Node* parent);
			        ~MFTEntryNode();
  NTFS*			        ntfs(void);
  Node*			        mftNode(void);
  virtual uint64_t	        fileMappingState(void);
  virtual void		        fileMapping(FileMapping* fm);
  virtual uint64_t	        _attributesState(void);
  virtual Attributes 	        _attributes(void);
  void                          updateState(void);
  uint64_t		        offset(void) const;
  uint32_t		        signature(void) const;
  uint32_t		        usedSize(void) const;
  uint32_t		        allocatedSize(void) const;
  void			        validate(void) const;
  uint16_t                      sequence(void) const;
  uint16_t		        firstAttributeOffset(void) const;
  uint16_t		        fixupArrayOffset(void) const;
  uint16_t		        fixupArrayEntryCount(void) const;
  uint16_t		        fixupArraySignature(void) const;
  bool                          isUsed(void) const;
  bool                          isDirectory(void) const;


  virtual class MFTAttribute*	__MFTAttribute(uint16_t offset);
  MFTAttributes	                mftAttributes();
  MFTAttributes	                findMFTAttributes(uint32_t typeId);

  const std::string             findName(void); //const 
  MFTAttributes                 data(void); //const
  MFTAttributes                 data(std::string const& data);
  std::vector<IndexEntry>       indexes(void); // const
};

#endif
