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

#include "extentstree.hpp"


ExtentsTree::ExtentsTree(uint8_t version) : __version(version), __origin(NULL), __handler(NULL)
{
}


ExtentsTree::~ExtentsTree()
{
}


void	ExtentsTree::setHandler(HfsFileSystemHandler* handler) throw (std::string)
{
  if (handler == NULL)
    throw std::string("Cannot create Extent tree because provided handler does not exist");
  this->__handler = handler;
}


void		ExtentsTree::process(Node* origin, uint64_t offset) throw (std::string)
{
  HTree::process(origin, offset);
}


std::map<uint64_t, Extent*>		ExtentsTree::extentsById(uint32_t fileid, uint8_t type)
{
  uint64_t			idx;
  ExtentTreeNode*		enode;
  std::map<uint64_t, Extent*>	extents;
  std::map<uint64_t, Extent*>	nodeextents;

  enode = NULL;
  if ((enode = new ExtentTreeNode(this->__version, this->__handler->blockSize())) == NULL)
    throw std::string("Cannot create extent node");
  for (idx = 0; idx < this->totalNodes(); idx++)
    {
      try
   	{
   	  enode->process(this->_origin, idx, this->nodeSize());
  	  nodeextents = enode->extentsById(fileid, type);
  	  extents.insert(nodeextents.begin(), nodeextents.end());
  	  nodeextents.clear();
  	}
      catch (std::string err)
  	{
  	  std::cout << "ERROR " << err << std::endl;
  	}
    }
  delete enode;
  return extents;
}


uint64_t				ExtentsTree::blockSize()
{
  return this->__handler->blockSize();
}


ExtentTreeNode::ExtentTreeNode(uint8_t version, uint64_t bsize) : __version(version), __bsize(bsize)
{
  
}


ExtentTreeNode::~ExtentTreeNode()
{
  
}


void	ExtentTreeNode::process(Node* origin, uint64_t uid, uint16_t size) throw (std::string)
{
  HNode::process(origin, uid, size);
}


KeyedRecords	ExtentTreeNode::records()
{
  std::string	error;
  KeyedRecord*	record;
  KeyedRecords	records;
  int		i;
  

  if (this->isLeafNode() && (this->numberOfRecords() > 0))
    {
      for (i = this->numberOfRecords(); i > 0; i--)
	{
	  record = this->__createExtentKey(bswap16(this->_roffsets[i]), bswap16(this->_roffsets[i-1]));
	  records.push_back(record);
	}
    }
  else
    records = HNode::records();
  return records;  
}


std::map<uint64_t, Extent*>	ExtentTreeNode::extentsById(uint32_t fileId, uint8_t type)
{
  int				i;
  ExtentKey*			record;
  std::map<uint64_t, Extent* >	extents;

  if (this->isLeafNode() && (this->numberOfRecords() > 0))
    {
      for (i = this->numberOfRecords(); i > 0; i--)
	{
	  if ((record = this->__createExtentKey(bswap16(this->_roffsets[i]), bswap16(this->_roffsets[i-1]))) != NULL)
	    {
	      if (record->fileId() == fileId && record->forkType() == type)
		extents = record->extents();
	      delete record;
	    }
	}
    }
  return extents;
}


bool	ExtentTreeNode::exists(uint32_t fileId, uint8_t type)
{
  std::string	error;
  ExtentKey*	record;
  KeyedRecords	records;
  int		i;
  bool		found;

  found = false;
  if (this->isLeafNode() && (this->numberOfRecords() > 0))
    {
      for (i = this->numberOfRecords(); i > 0; i--)
	{
	  if ((record = this->__createExtentKey(bswap16(this->_roffsets[i]), bswap16(this->_roffsets[i-1]))) != NULL)
	    {
	      if (record->fileId() == fileId && record->forkType() == type)
		found = true;
	      delete record;
	    }
	}
    }
  return found;
}


ExtentKey*	ExtentTreeNode::__createExtentKey(uint16_t start, uint16_t end)
{
  ExtentKey*	record;
  uint64_t	offset;
  uint16_t	size;

  offset = this->offset() + start;
  size = 0;
  if (start < end)
    size = end - start;
  if (this->__version == 0)
    record = new HfsExtentKey(this->__bsize);
  else //if (this->__version == 1)
    record = new HfspExtentKey(this->__bsize);
  record->process(this->_origin, offset, size);
  return record;
}



HfsExtentKey::HfsExtentKey(uint64_t bsize) : ExtentKey(bsize), __ekey()
{
}


HfsExtentKey::~HfsExtentKey()
{
}


void	HfsExtentKey::process(Node* origin, uint64_t offset, uint16_t size) throw (std::string)
{
  uint8_t*	key;

  KeyedRecord::process(origin, offset, size);
  key = NULL;
  if (((key = this->key()) != NULL) && (this->keyDataLength() >= sizeof(hfs_extent_key)))
    memcpy(&this->__ekey, key, sizeof(hfs_extent_key));
  if (key != NULL)
   free(key);
}


std::map<uint64_t, Extent*>	HfsExtentKey::extents()
{
  uint8_t			i;
  uint64_t			sblock;
  uint8_t*			data;
  hfs_extent			exts[3];
  std::map<uint64_t, Extent* >	extentsmap;

  data = NULL;
  sblock = (uint64_t)this->__ekey.startBlock;
  if ((this->dataLength() >= sizeof(hfs_extent)*3) && ((data = this->data()) != NULL))
    {
      memcpy(&exts, data, sizeof(hfs_extent)*3);
      for (i = 0; i != 3; ++i)
	{
	  if (exts[i].blockCount > 0)
	    {
	      extentsmap[sblock] = new Extent(exts[i], this->_bsize);
	      sblock += extentsmap[sblock]->blockCount();
	    }
	}
    }
  if (data != NULL)
    free(data);
  return extentsmap;
}


uint8_t		HfsExtentKey::forkType()
{
  return this->__ekey.forkType;
}


uint32_t	HfsExtentKey::fileId()
{
  return bswap32(this->__ekey.fileId);
}


uint32_t	HfsExtentKey::startBlock()
{
  return bswap32((uint32_t)this->__ekey.startBlock);
}


HfspExtentKey::HfspExtentKey(uint64_t bsize) : ExtentKey(bsize), __ekey()
{
}


HfspExtentKey::~HfspExtentKey()
{
}


void	HfspExtentKey::process(Node* origin, uint64_t offset, uint16_t size) throw (std::string)
{
  uint8_t*	key;

  KeyedRecord::process(origin, offset, size);
  key = NULL;
  if (((key = this->key()) != NULL) && (this->keyDataLength() >= sizeof(hfsp_extent_key)))
    memcpy(&this->__ekey, key, sizeof(hfsp_extent_key));
  if (key != NULL)
   free(key);
}


std::map<uint64_t, Extent*>	HfspExtentKey::extents()
{
  uint8_t			i;
  uint64_t			sblock;
  uint8_t*			data;
  hfsp_extent			exts[8];
  std::map<uint64_t, Extent* >	extentsmap;

  data = NULL;
  sblock = (uint64_t)this->__ekey.startBlock;
  if ((this->dataLength() >= sizeof(hfsp_extent)*8) && ((data = this->data()) != NULL))
    {
      memcpy(&exts, data, sizeof(hfsp_extent)*8);
      for (i = 0; i != 8; ++i)
	{
	  if (exts[i].blockCount > 0)
	    {
	      extentsmap[sblock] = new Extent(exts[i], this->_bsize);;
	      sblock += extentsmap[sblock]->blockCount();
	    }
	}
    }
  if (data != NULL)
    free(data);
  return extentsmap;
}


uint8_t		HfspExtentKey::forkType()
{
  return this->__ekey.forkType;
}


uint32_t	HfspExtentKey::fileId()
{
  return bswap32(this->__ekey.fileId);
}


uint32_t	HfspExtentKey::startBlock()
{
  return bswap32(this->__ekey.startBlock);
}

