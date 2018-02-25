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

#ifndef __FAT_HPP__
#define __FAT_HPP__

#include "node.hpp"
#include "filemapping.hpp"
#include "vfile.hpp"
#include "bootsector.hpp"

#define FATFS_12_MASK   0x00000fff
#define FATFS_16_MASK   0x0000ffff
#define FATFS_32_MASK   0x0fffffff

#define FAT_BUFF_CACHE	8192
#define MAX_FAT_COUNT	255

using namespace DFF;

class FileAllocationTable;

typedef struct	s_fatcache
{
  uint32_t	off;
  void*		cache;
}		fatcache;


// TODO: Implement iterators for chain of clusters, alloc, free and bad
class FileAllocationTable
{
private:
  VFile*			__vfile;
  Node*				__origin;
  BootSector*			__bs;
  fatcache			__fatscache[MAX_FAT_COUNT];
  std::map<uint32_t, uint32_t>	__freeClustCount;
  std::map<uint32_t, uint32_t>	__allocClustCount;
  std::map<uint32_t, uint32_t>	__badClustCount;
  void				__processClustersStatus();
  bool				__isBadCluster(uint32_t clust);
  bool				__initCache();
  void				__clearCache();
  void				__createNodes(Node* parent, fso* fsobj, uint8_t i);
  void				__clustersListToNodes(Node* parent, fso* fsobj, const std::vector<uint32_t>& clusters);
  mutex_def(__mutex);

public:
  FileAllocationTable();
  ~FileAllocationTable();
  void			setBootSector(BootSector* bs) throw (std::string);
  BootSector*		bootSector();
  
  void			process(Node* origin, fso* fsobj) throw (std::string);

  uint32_t		ioCluster12(uint32_t current, uint8_t which);
  uint32_t		ioCluster16(uint32_t current, uint8_t which);
  uint32_t		ioCluster32(uint32_t current, uint8_t which);
  uint32_t		cluster12(uint32_t current, uint8_t which);
  uint32_t		cluster16(uint32_t current, uint8_t which);
  uint32_t		cluster32(uint32_t current, uint8_t which);

  uint32_t		clusterEntry(uint32_t current, uint8_t which=0);

  uint64_t		clusterOffsetInFat(uint64_t cluster, uint8_t which);

  std::vector<uint64_t>	clusterChainOffsets(uint32_t cluster, uint8_t which=0);
  std::vector<uint32_t>	clusterChain(uint32_t start, uint8_t which=0);

  bool			isFreeCluster(uint32_t cluster);
  bool			isBadCluster(uint32_t cluster);
  bool			clusterEntryIsFree(uint32_t cluster, uint8_t which);
  bool			clusterEntryIsBad(uint32_t cluster, uint8_t which);

  std::vector<uint64_t>	listFreeClustersOffset(uint8_t which=0);
  std::vector<uint32_t>	listFreeClusters(uint8_t which=0);
  uint32_t		freeClustersCount(uint8_t which=0);

  std::vector<uint32_t>	listAllocatedClusters(uint8_t which=0);
  uint32_t		allocatedClustersCount(uint8_t which=0);

  std::vector<uint32_t>	listBadClusters(uint8_t which=0);
  uint32_t		badClustersCount(uint8_t which=0);

  uint64_t		clusterToOffset(uint32_t cluster);
  uint32_t		offsetToCluster(uint64_t offset);

  void			diffFats();

  void			fileMapping(FileMapping* fm, uint8_t which);
  Attributes		attributes(uint8_t which);
};

class FileAllocationTableNode: public Node
{
private:
  FileAllocationTable*	__fat;
  uint8_t		__fatnum;
public:
  FileAllocationTableNode(std::string name, uint64_t size, Node* parent, fso* fsobj);
  ~FileAllocationTableNode();
  void				setContext(FileAllocationTable* fat, uint8_t fatnum);
  virtual void			fileMapping(FileMapping* fm);
  virtual Attributes		_attributes(void);
  virtual const std::string	dataType();
};


class ClustersChainNode: public Node
{
private:
  uint32_t		__scluster;
  uint32_t		__count;
  uint64_t		__soffset;
  Node*			__origin;
public:
  ClustersChainNode(std::string name, uint64_t size, Node* parent, fso* fs);
  ~ClustersChainNode();
  void				setContext(uint32_t scluster, uint32_t count, uint64_t offset, Node* origin);
  virtual void			fileMapping(FileMapping* fm);
  virtual Attributes		_attributes(void);
  virtual const std::string	dataType();
};


#endif
