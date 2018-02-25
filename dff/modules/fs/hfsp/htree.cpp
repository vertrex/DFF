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

#include <iostream>
#include "exceptions.hpp"

#include "htree.hpp"

/*
 * Keyed record common implementation
 *
*/

KeyedRecord::KeyedRecord() : __klenfield(2)
{
}


KeyedRecord::~KeyedRecord()
{
}


void		KeyedRecord::setSizeofKeyLengthField(uint8_t klenfield)
{
  this->__klenfield = klenfield;
}


void	KeyedRecord::process(uint8_t *buffer, uint16_t size) throw (std::string)
{
  BufferReader::process(buffer, size);
}


void	KeyedRecord::process(Node* origin, uint64_t offset, uint16_t size) throw (std::string)
{
  BufferReader::process(origin, offset, size);
}


bool		KeyedRecord::isValid()
{
  return ((this->_buffer != NULL) 
	  && (this->_size > 0)
	  && (this->keyDataLength() > 0 && this->keyDataLength() < this->_size)
	  && (this->dataOffset() > 0 && this->dataOffset() < this->_size)
	  && (this->dataOffset() + this->dataLength() <= this->_size));
}


uint16_t	KeyedRecord::keyLength()
{
  uint16_t	keylen;

  if (this->__klenfield == 1)
    memcpy(&keylen, this->_buffer, 1);
  else
    {
      memcpy(&keylen, this->_buffer, 2);
      keylen = bswap16(keylen);
    }
  return keylen;
}


// following method is used to know the alignment of data
uint16_t	KeyedRecord::keyDataLength()
{
  // XXX on HFS+ volumes size of key is always 2 bytes
  // but on HFS volume size is defined by kBTBigKeysMask
  // letting the field keyLength being one byte or 2 bytes.
  return this->keyLength()+this->__klenfield;
}


uint8_t*	KeyedRecord::key()
{
  uint8_t*	key;

  key = NULL;
  if (this->isValid() && ((key = (uint8_t*)malloc(sizeof(uint8_t) * this->keyDataLength())) != NULL))
    memcpy(key, this->_buffer, this->keyDataLength());
  return key;
}

uint16_t	KeyedRecord::dataOffset()
{
  uint16_t	offset;

  offset = 0;
  if ((this->keyDataLength() % 2) == 0)
    offset = this->keyDataLength();
  else // add pad byte offset
    offset = this->keyDataLength() + 1;
  return offset;
}


uint16_t	KeyedRecord::dataLength()
{
  uint16_t	offset;
  uint16_t	size;

  size = 0;
  offset = this->dataOffset();
  if (offset > 0 && offset < this->_size)
    {
      if (((this->_size - offset) % 2) == 0)
	size = this->_size - offset;
      else // remove trailing pad byte
	size = this->_size - offset - 1;
    }
  return size;
}


uint8_t*	KeyedRecord::data()
{
  uint8_t*	data;
  uint16_t	asize;
  uint16_t	offset;

  data = NULL;
  offset = this->dataOffset();
  asize = this->dataLength();
  if (this->isValid() && ((data = (uint8_t*)malloc(sizeof(uint8_t)*asize)) != NULL))
    memcpy(data, (this->_buffer+offset), asize);
  return data;
}


/*
 *
 * BtreeNode implementation
 *
*/

HNode::HNode() : __descriptor(), _klenfield(2), _buffer(NULL), _roffsets(NULL), _origin(NULL), _uid(0), _size(0)
{
}


HNode::~HNode()
{
  if (this->_buffer != NULL)
    free(this->_buffer);
}


void		HNode::__clean()
{
  if (this->_buffer != NULL)
    free(this->_buffer);
  this->_buffer = NULL;
  if (this->_roffsets != NULL)
    free(this->_roffsets);
  this->_roffsets = NULL;
  this->_origin = NULL;
  this->_uid = 0;
  this->_size = 0;
}


void		HNode::process(Node* origin, uint64_t uid, uint16_t size) throw (std::string)
{
  uint32_t	asize;

  this->__clean();
  if (origin == NULL)
    throw std::string("No node set. Cannot read information");
  if (size == 0 || size < sizeof(node_descriptor))
    throw std::string("Size of HNode is too small. Cannot process");
  this->_origin = origin;
  this->_uid = uid;
  this->_size = size;
  this->__readBuffer();
  memcpy(&this->__descriptor, this->_buffer, sizeof(node_descriptor));
  asize = (this->numberOfRecords() + 1) * sizeof(uint16_t);
  if (this->_size < sizeof(node_descriptor) + asize)
    throw std::string("Size of HNode is too small. Cannot process");
  if ((this->_roffsets = (uint16_t*)malloc(asize)) == NULL)
    throw std::string("Cannot allocate record offset array");
  memset(this->_roffsets, 0, asize);
  memcpy(this->_roffsets, this->_buffer+(this->_size-asize), asize);
}


void		HNode::setSizeofKeyLengthField(uint8_t klenfield)
{
  this->_klenfield = klenfield;
}


void		HNode::__readBuffer() throw (std::string)
{
  std::string	error;
  VFile*	vfile;
  
  vfile = NULL;
  if ((this->_buffer = (uint8_t*)malloc(sizeof(uint8_t)*this->_size)) == NULL)
    throw std::string("Cannot allocate node");
  try
    {
      vfile = this->_origin->open();
      vfile->seek(this->offset());
      if (vfile->read(this->_buffer, this->_size) != this->_size)
	error = std::string("Cannot read btree node");
    }
  catch (std::string& err)
    {
      error = err;
    }
  catch (vfsError& err)
    {
      error = err.error;
    }
  if (vfile != NULL)
    {
      vfile->close();
      delete vfile;
    }
  if (!error.empty())
    {
      if (this->_buffer != NULL)
	free(this->_buffer);
      this->_buffer = NULL;
      throw error;
    }
}



KeyedRecords	HNode::records()
{
  std::string	error;
  KeyedRecords	records;
  int		i;

  try
    {
      if (this->numberOfRecords() > 0)
  	{
  	  for (i = this->numberOfRecords(); i > 0; i--)
	    {
  	      //rec = this->__createRecord(buffer, bswap16(roffsets[i]), bswap16(roffsets[i-1]));
  	      //records.push_back(rec);
	    }
  	}
    }
  catch (std::string err)
    {
      error = err;
    }
  return records;
}


void		HNode::dump(std::string tab)
{
  std::cout << tab << "Dumping Node: " << this->uid() << std::endl;
  if (this->isLeafNode())
    std::cout << tab << "Type: Leaf" << std::endl;
  if (this->isIndexNode())
    std::cout << tab << "Type: Index" << std::endl;
  if (this->isHeaderNode())
    std::cout << tab << "Type: Header" << std::endl;
  if (this->isMapNode())
    std::cout << "Type: Map" << std::endl;
  std::cout << tab << "Offset in catalog " << this->offset() << std::endl;
  std::cout << tab << "Current height: " << (int)this->height() << std::endl;
  std::cout << tab << "Forward link: " << this->fLink() << std::endl;
  std::cout << tab << "Backward link: " << this->bLink() << std::endl;
  std::cout << tab << "Number of records: " << this->numberOfRecords() << std::endl;
}

uint32_t	HNode::fLink()
{
  return bswap32(this->__descriptor.fLink);
}


uint32_t	HNode::bLink()
{
  return bswap32(this->__descriptor.bLink);
}


int8_t		HNode::kind()
{
  return this->__descriptor.kind;
}


uint8_t		HNode::height()
{
  return this->__descriptor.height;
}


uint16_t	HNode::numberOfRecords()
{
  return bswap16(this->__descriptor.numRecords);
}


bool		HNode::isLeafNode()
{
  return (this->__descriptor.kind == -1);
}


bool		HNode::isIndexNode()
{
  return (this->__descriptor.kind == 0);
}


bool		HNode::isHeaderNode()
{
  return (this->__descriptor.kind == 1);
}


bool		HNode::isMapNode()
{
  return (this->__descriptor.kind == 2);
}


uint64_t	HNode::uid()
{
  return this->_uid;
}

uint64_t	HNode::offset()
{
  return this->_uid * this->_size;
}


/*
 *
 * HfsBtree implementation
 *
*/

HTree::HTree() : __hnode(), _origin(NULL)
{
}


HTree::~HTree()
{
}

void	HTree::process(Node* node, uint64_t offset) throw (std::string)
{
  std::string	err;
  VFile*	vfile;

  vfile = NULL;
  if (node == NULL)
    throw std::string("Cannot create Btree because provided node does not exist");
  memset(&this->__hnode, 0, sizeof(header_node));
  try
    {
      vfile = node->open();
      vfile->seek(offset);
      if (vfile->read(&this->__hnode, sizeof(header_node)) != sizeof(header_node))
	throw std::string("Cannot read header node");
      if (((this->nodeSize() % 2) != 0) || (this->nodeSize() < 512) || (this->nodeSize() > 32768))
	throw std::string("Size of node is not correct. Must be a power of 2 from 512 through 32768");
      this->_origin = node;
    }
  catch (...)
    {
      throw std::string("");
    }
  if (vfile != NULL)
    {
      vfile->close();
      delete vfile;
    }
}


void		HTree::dump(std::string tab)
{
  std::cout << tab << "HFS Btree Dump" << std::endl;
  std::cout << tab << "Header node information" << std::endl;
  std::cout << tab << "Depth of tree: " << this->treeDepth() << std::endl;
  std::cout << tab << "Root node: " << this->rootNode() << std::endl;
  std::cout << tab << "Leaf records: " << this->leafRecords() << std::endl;
  std::cout << tab << "First leaf node: " << this->firstLeafNode() << std::endl;
  std::cout << tab << "Last leaf node: " << this->lastLeafNode() << std::endl;
  std::cout << tab << "Size of node: " << this->nodeSize() << std::endl;
  std::cout << tab << "Maximum length of key: " << this->maxKeyLength() << std::endl;
  std::cout << tab << "Total nodes: " << this->totalNodes() << std::endl;
  std::cout << tab << "Number of free nodes: " << this->freeNodes() << std::endl;
  std::cout << tab << "Size of clump: " << this->clumpSize() << std::endl;
  std::cout << tab << "Size of key length field" << this->sizeOfKey() << std::endl;
}


uint16_t	HTree::treeDepth()
{
  return bswap16(this->__hnode.treeDepth);
}


uint32_t	HTree::rootNode()
{
  return bswap32(this->__hnode.rootNode);
}


uint32_t	HTree::leafRecords()
{
  return bswap32(this->__hnode.leafRecords);
}


uint32_t	HTree::firstLeafNode()
{
  return bswap32(this->__hnode.firstLeafNode);
}


uint32_t	HTree::lastLeafNode()
{
  return bswap32(this->__hnode.lastLeafNode);
}


uint16_t	HTree::nodeSize()
{
  return bswap16(this->__hnode.nodeSize);
}


uint16_t	HTree::maxKeyLength()
{
  return bswap16(this->__hnode.maxKeyLength);
}


uint32_t	HTree::totalNodes()
{
  return bswap32(this->__hnode.totalNodes);
}


uint32_t	HTree::freeNodes()
{
  return bswap32(this->__hnode.freeNodes);
}


uint32_t	HTree::clumpSize()
{
  return bswap32(this->__hnode.clumpSize);
}


bool		HTree::isBTreeType()
{
  return (this->__hnode.btreeType == HTree::kHFSBTreeType);
}


bool		HTree::isUserType()
{
  return (this->__hnode.btreeType == HTree::kUserBTreeType);
}


bool		HTree::isReservedType()
{
  return (this->__hnode.btreeType == HTree::kReservedBTreeType);
}


bool		HTree::isCaseSensitive()
{
  return (this->__hnode.keyCompareType == 0xBC);
}


uint8_t		HTree::sizeOfKey()
{
  uint32_t	attributes;

  attributes = bswap32(this->__hnode.attributes);
  if ((attributes & HTree::kBTBigKeysMask) == HTree::kBTBigKeysMask)
    return sizeof(uint16_t);
  else
    return sizeof(uint8_t);
}


bool		HTree::hasVariableIndexKey()
{
  uint32_t	attributes;

  attributes = bswap32(this->__hnode.attributes);
  return ((attributes & HTree::kBTVariableIndexKeysMask) == HTree::kBTVariableIndexKeysMask);
}


bool		HTree::hasBeenCorrectlyClosed()
{
  uint32_t	attributes;

  attributes = bswap32(this->__hnode.attributes);
  return ((attributes & HTree::kBTBadCloseMask) == HTree::kBTBadCloseMask);
}
