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

#ifndef __HFSP_EXTENTS_TREE_HPP__
#define __HFSP_EXTENTS_TREE_HPP__

#include <stdint.h>

#include "export.hpp"
#include "node.hpp"

#include "endian.hpp"
#include "hfshandlers.hpp"
#include "extent.hpp"
#include "htree.hpp"


PACK_START
typedef struct	s_hfs_extent_key
{
  uint8_t	keyLength;
  uint8_t	forkType;
  uint32_t	fileId;
  uint16_t	startBlock;
}		hfs_extent_key;
PACK_END


PACK_START
typedef struct	s_hfsp_extent_key
{
  uint16_t	keyLength;
  uint8_t	forkType;
  uint8_t	pad;
  uint32_t	fileId;
  uint32_t	startBlock;
}		hfsp_extent_key;
PACK_END


class HfsFileSystemHandler;


class ExtentsTree : public HTree
{
private:
  uint8_t				__version;
  Node*					__origin;
  HfsFileSystemHandler*			__handler;
public:
  ExtentsTree(uint8_t version);
  ~ExtentsTree();
  void					setHandler(HfsFileSystemHandler* handler) throw (std::string);
  virtual void				process(Node* origin, uint64_t offset) throw (std::string);
  std::map<uint64_t, Extent*>	        extentsById(uint32_t fileid, uint8_t type);
  uint64_t				blockSize();
};


class ExtentTreeNode : public HNode
{
private:
  uint8_t				__version;
  uint64_t				__bsize;
  class ExtentKey*			__createExtentKey(uint16_t start, uint16_t end);
public:
  ExtentTreeNode(uint8_t version, uint64_t bsize);
  ~ExtentTreeNode();
  void					process(Node* origin, uint64_t uid, uint16_t size) throw (std::string);
  KeyedRecords				records();
  bool					exists(uint32_t fileId, uint8_t type);
  std::map<uint64_t, Extent* >		extentsById(uint32_t fileId, uint8_t type);
};


class ExtentKey : public KeyedRecord
{
protected:
  uint64_t		_bsize;
public:
  ExtentKey(uint64_t bsize) : _bsize(bsize) {}
  virtual ~ExtentKey() {}
  virtual void		process(Node* origin, uint64_t offset, uint16_t size) throw (std::string) = 0;
  virtual std::map<uint64_t, Extent*>	extents() = 0;
  virtual uint8_t	forkType() = 0;
  virtual uint32_t	fileId() = 0;
  virtual uint32_t	startBlock() = 0;
};


class HfsExtentKey : public ExtentKey
{
private:
  hfs_extent_key	__ekey;
public:
  HfsExtentKey(uint64_t bsize);
  virtual ~HfsExtentKey();
  virtual void		process(Node* origin, uint64_t offset, uint16_t size) throw (std::string);
  virtual std::map<uint64_t, Extent*>	extents();
  virtual uint8_t	forkType();
  virtual uint32_t	fileId();
  virtual uint32_t	startBlock();
};


class HfspExtentKey : public ExtentKey
{
private:
  hfsp_extent_key	__ekey;
public:
  HfspExtentKey(uint64_t bsize);
  virtual ~HfspExtentKey();
  virtual void		process(Node* origin, uint64_t offset, uint16_t size) throw (std::string);
  virtual std::map<uint64_t, Extent*>	extents();
  virtual uint8_t	forkType();
  virtual uint32_t	fileId();
  virtual uint32_t	startBlock();
};


#endif
