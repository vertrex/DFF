/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2014 ArxSys
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
 *  Frederic Baguelin <fba@digital-forensic.org>
 */

#ifndef __HTREE_HPP__
#define __HTREE_HPP__

#include <stdint.h>
#include <string.h>

#include "export.hpp"
#include "node.hpp"
#include "vfile.hpp"

#include "endian.hpp"
#include "bufferreader.hpp"

#define MaxNodeSize	0x8000
#define MinNodeSize	0x200

using namespace DFF;

PACK_START
typedef struct s_node_descriptor
{
  uint32_t	fLink;
  uint32_t	bLink;
  int8_t	kind;
  uint8_t	height;
  uint16_t	numRecords;
  uint16_t	reserved;
}		node_descriptor;
PACK_END


PACK_START
typedef struct s_header_node
{
  node_descriptor	descriptor;
  uint16_t		treeDepth;
  uint32_t		rootNode;
  uint32_t		leafRecords;
  uint32_t		firstLeafNode;
  uint32_t		lastLeafNode;
  uint16_t		nodeSize;
  uint16_t		maxKeyLength;
  uint32_t		totalNodes;
  uint32_t		freeNodes;
  uint16_t		reserved1;
  uint32_t		clumpSize;
  uint8_t		btreeType;
  uint8_t		keyCompareType;
  uint32_t		attributes;
  uint32_t		reserved3[16];
}			header_node;
PACK_END


class KeyedRecord : public BufferReader
{
private:
  uint8_t	__klenfield;
public:
  KeyedRecord();
  virtual ~KeyedRecord();
  void		setSizeofKeyLengthField(uint8_t klenfield);
  void		process() throw (std::string);
  virtual void	process(uint8_t *buffer, uint16_t size) throw (std::string);
  virtual void	process(Node* origin, uint64_t offset, uint16_t size) throw (std::string);
  bool		isValid();
  uint16_t	keyLength();
  uint16_t	keyDataLength();
  uint8_t*	key();
  uint16_t	dataOffset();
  uint16_t	dataLength();
  uint8_t*	data();
};


typedef std::vector<KeyedRecord* > KeyedRecords;

class HNode
{
private:
  node_descriptor	__descriptor;
  uint16_t*		__createRecordsOffset(uint8_t* buffer);
  void			__clean();
  void			__readBuffer() throw (std::string);
protected:
  uint8_t		_klenfield;
  uint8_t*		_buffer;
  uint16_t*		_roffsets;
  Node*			_origin;
  uint64_t		_uid;
  uint16_t		_size;
public:
  HNode();
  virtual ~HNode();
  void			setSizeofKeyLengthField(uint8_t klenfield);
  void			process();
  void			process(Node* origin, uint64_t uid, uint16_t size) throw (std::string);
  void			dump(std::string tab);

  virtual KeyedRecords	records();

  uint32_t		fLink();
  uint32_t		bLink();
  int8_t		kind();
  uint8_t		height();
  uint16_t		numberOfRecords();
  bool			isLeafNode();
  bool			isIndexNode();
  bool			isHeaderNode();
  bool			isMapNode();
  uint64_t		uid();
  uint64_t		offset();
};


// TODO
// Implement iterator to walk nodes sequentially
class HTree
{
private:
  header_node	__hnode;
protected:
  enum HTreeTypes
    {
      kHFSBTreeType           =   0,
      kUserBTreeType          = 128,
      kReservedBTreeType      = 255
    };
  enum HTreeAttributes
    {
      kBTBadCloseMask           = 0x00000001,
      kBTBigKeysMask            = 0x00000002,
      kBTVariableIndexKeysMask  = 0x00000004
    };
  Node*		_origin;
public:
  HTree();
  virtual ~HTree();
  virtual void		process(Node* node, uint64_t offset) throw (std::string);
  void			dump(std::string tab);
  bool			isBTreeType();
  bool			isUserType();
  bool			isReservedType();
  bool			isCaseSensitive();
  bool			hasVariableIndexKey();
  bool			hasBeenCorrectlyClosed();
  uint8_t		sizeOfKey();
  uint16_t		treeDepth();
  uint16_t		nodeSize();
  uint16_t		maxKeyLength();
  uint32_t		rootNode();
  uint32_t		leafRecords();
  uint32_t		firstLeafNode();
  uint32_t		lastLeafNode();
  uint32_t		totalNodes();
  uint32_t		freeNodes();
  uint32_t		clumpSize();
  //virtual HNode*	getNode(uint32_t uid) {}
};

#endif
