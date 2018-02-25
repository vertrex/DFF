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
 *  Frederic Baguelin <fba@digital-forensic.org>
 */

#ifndef __ALLOCATION_HPP__
#define __ALLOCATION_HPP__

#include <stdint.h>

#include "export.hpp"
#include "node.hpp"
#include "vfile.hpp"

#include "endian.hpp"
#include "hfshandlers.hpp"

using namespace DFF;

class HfsFileSystemHandler;

class AllocationFile
{
private:
  uint64_t			__cacheOffset;
  uint64_t			__blocks;
  uint64_t			__percent;
  uint8_t*			__cache;
  HfsFileSystemHandler*		__handler;
  Node*				__allocation;
  VFile*			__vfile;
  std::map<uint64_t, uint64_t>	__freeBlocks;

  void				__progress(uint64_t current);
  void				__initCache();
  void				__clearCache();
  void				__updateCache(uint64_t offset);
public:
  AllocationFile();
  ~AllocationFile();
  void				setHandler(HfsFileSystemHandler* handler) throw (std::string);
  void				process(Node* allocation, uint64_t offset, uint64_t blocks) throw (std::string);
  bool				isBlockAllocated(uint64_t block) throw (std::string);
};


class UnallocatedNode : public Node
{
private:
  std::map<uint64_t, uint64_t>	__freeBlocks;
  Node*				__origin;
  uint64_t			__bsize;
public:
  UnallocatedNode(std::string name, uint64_t size, Node* parent, fso* fsobj);
  ~UnallocatedNode();
  void	setContext(Node* origin, uint64_t bsize, const std::map<uint64_t, uint64_t>& freeBlocks);
  void	fileMapping(FileMapping* fm);
};


#endif 
