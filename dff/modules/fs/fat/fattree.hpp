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

#ifndef	__FATTREE_HPP__
#define __FATTREE_HPP__

#include "node.hpp"
#include "vfile.hpp"
#include "filemapping.hpp"
#include "TwoThreeTree.hpp"

#include "bootsector.hpp"
#include "fat.hpp"

#include "entries.hpp"


typedef struct	s_deletedItems
{
  Node*	node;
  ctx*	c;
}		deletedItems;

class FatNode;
class FileSlack;

class FatTree
{
private:
  BootSector*			__bs;
  FileAllocationTable*		__fat;
  Node*				__origin;
  fso*				__fsobj;
  VFile*			__vfile;
  EntriesManager*		__emanager;
  TwoThreeTree*			__allocatedClusters;
  uint8_t			__usedfat;
  uint32_t			__depth;
  uint64_t			__allocount;
  uint64_t			__processed;
  std::string			__volname;
  std::vector<Node*>		__rootdir;
  std::vector<deletedItems*>	__deleted;
  std::map<uint32_t, Node*>	__slacknodes;
  void				__reset();
  Node*				__allocNode(ctx* c, Node* parent);
  void				__updateDeletedItems(ctx* c, Node* parent);
  void				__updateAllocatedClusters(uint32_t cluster);
public:
  FatTree();
  ~FatTree();
  void				setBootSector(BootSector* bs) throw (std::string);
  void				setFat(FileAllocationTable* fat) throw (std::string);
  void				setUsedFat(uint8_t usedfat);
  void				process(Node* origin, fso* fsobj, bool metacarve) throw (std::string);
  void				walk(uint32_t cluster, Node* parent);
  void				rootdir(Node* parent);
  void				makeSlackNodes();
  void				processDeleted();
  void				walkDeleted(uint32_t cluster, Node* parent);
  void				walkMissingAlloc(Node* parent);
  void				walkFree(Node* parent);

  void				fileMapping(FileMapping* fm, FatNode* node);
  void				slackMapping(FileMapping* fm, FileSlack* node);
  Attributes			attributes(FatNode* fnode);
};


class FatNode: public Node
{
private:
  FatTree*		__ftree;

public:
  bool			clustrealloc;
  uint64_t		lfnmetaoffset;
  uint64_t		dosmetaoffset;
  uint32_t		cluster;

  FatNode(std::string name, uint64_t size, Node* parent, fso* fso, FatTree* ftree);
  ~FatNode();
  void			setLfnMetaOffset(uint64_t lfnmetaoffset);
  void			setDosMetaOffset(uint64_t dosmetaoffset);
  void			setCluster(uint32_t cluster, bool reallocated=false);
  virtual void		fileMapping(FileMapping* fm);
  virtual Attributes	_attributes(void);
};


class FileSlack: public Node
{
private:
  FatTree*	__ftree;

public:
  uint64_t	ocluster;
  uint64_t	originsize;

  FileSlack(std::string name, uint64_t size, Node* parent, fso* fsobj, FatTree* ftree);
  ~FileSlack();
  void			setContext(uint32_t ocluster, uint64_t osize);
  virtual void		fileMapping(FileMapping* fm);
  virtual Attributes	_attributes();
};

#endif
