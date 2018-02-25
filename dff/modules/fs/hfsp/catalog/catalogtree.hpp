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

#ifndef __CATALOG_TREE_HPP__
#define __CATALOG_TREE_HPP__

#include <stdint.h>

#include "export.hpp"
#include "node.hpp"
#include "vfile.hpp"
#include "TwoThreeTree.hpp"

#include "htree.hpp"

#include "hfshandlers.hpp"
#include "catalogrecords.hpp"

class HfsFileSystemHandler;
class HfsNode;
class CatalogEntry;


class CatalogTreeNode : public HNode
{
private:
  uint8_t	__version;
  KeyedRecord*	__createCatalogKey(uint16_t start, uint16_t end);
public:
  CatalogTreeNode(uint8_t version);
  ~CatalogTreeNode();
  virtual void	process(Node* origin, uint64_t uid, uint16_t size) throw (std::string);
  virtual KeyedRecords	records();
};


typedef std::map<uint32_t, std::vector<HfsNode*> > HfsNodesMapping;


class CatalogTree : public HTree
{
private:
  HfsFileSystemHandler*	__handler;
  TwoThreeTree*		__allocatedBlocks;
  uint8_t		__version;
  uint32_t		__fileCount;
  uint32_t		__folderCount;
  uint32_t		__fileThreadCount;
  uint32_t		__folderThreadCount;
  uint32_t		__leafRecords;
  uint32_t		__indexRecords;
  uint32_t		__effectiveLeafRecords;
  uint64_t		__percent;
  HfsNodesMapping	__nodes;
  void			__makeNodes(Node* catalog, CatalogTreeNode* cnode);
  void			__linkNodes(HfsNode* parent, uint32_t parentId);
  void			__registerAllocatedBlocks(HfsNode* node);
  void			__progress(uint64_t current);
public:
  CatalogTree(uint8_t version);
  ~CatalogTree();
  //void			setSlackNodeCarving(bool state);
  void			setHandler(HfsFileSystemHandler* handler) throw (std::string);
  void			process(Node* catalog, uint64_t offset) throw (std::string);
  CatalogEntry*		catalogEntry(uint64_t offset, uint16_t size);
};

#endif
