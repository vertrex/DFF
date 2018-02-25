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

#include "exceptions.hpp"

#include "fat.hpp"


FileAllocationTable::FileAllocationTable() : __vfile(NULL), __origin(NULL), __bs(NULL), __fatscache(), __freeClustCount(std::map<uint32_t, uint32_t>()), __allocClustCount(std::map<uint32_t, uint32_t>()), __badClustCount(std::map<uint32_t, uint32_t>())
{
  mutex_init(&this->__mutex);
}


FileAllocationTable::~FileAllocationTable()
{
  mutex_destroy(&this->__mutex);
  if (this->__vfile != NULL)
    {
      //XXX VFile dtor must close the opened file...
      this->__vfile->close();
      delete this->__vfile;
    }
  this->__clearCache();
}

void		FileAllocationTable::setBootSector(BootSector* bs) throw (std::string)
{
  if (bs != NULL)
    this->__bs = bs;
  else
    throw std::string("Provided boot sector does not exist");
}

BootSector*	FileAllocationTable::bootSector()
{
  return this->__bs;
}

void		FileAllocationTable::__clearCache()
{
  uint8_t	i;

  for (i = 0; i != this->__bs->numfat; i++)
    {
      if (this->__fatscache[i].cache != NULL)
	{
	  free(this->__fatscache[i].cache);
	  this->__fatscache[i].cache = NULL;
	}
    }
}


bool		FileAllocationTable::__initCache()
{
  uint8_t	i;
  uint64_t	baseoffset;
  
  for (i = 0; i != this->__bs->numfat; i++)
    {
      if ((this->__fatscache[i].cache = (void*)malloc(FAT_BUFF_CACHE*sizeof(uint8_t))) != NULL)
	{
	  this->__fatscache[i].off = 0;
	  baseoffset = this->__bs->firstfatoffset + (uint64_t)i * (uint64_t)this->__bs->fatsize;
	  try
	    {
	      this->__vfile->seek(baseoffset);
	      if (this->__vfile->read(this->__fatscache[i].cache, FAT_BUFF_CACHE) != FAT_BUFF_CACHE)
		return false;
	    }
	  catch (vfsError e)
	    {
	      return false;
	    }
	}
      else
	return false;
    }
  return true;
}


void	FileAllocationTable::process(Node* origin, fso* fsobj) throw (std::string)
{
  std::stringstream	sstr;
  uint8_t		i;

  if (origin == NULL || fsobj == NULL)
    return;
  this->__origin = origin;
  try
    {
      this->__vfile = origin->open();
    }
  catch(vfsError e)
    {
      this->__vfile = NULL;
      throw(std::string("Fat module: FileAllocationTable error while opening node") + e.error);
    }
  if (!this->__initCache())
    {
      this->__clearCache();
      throw(std::string("Fat module: FileAllocationTable cannot allocate cache"));
    }
  for (i = 0; i != this->__bs->numfat; i++)
    {
      sstr << "gathering information for FAT " << i+1 << " / " << this->__bs->numfat;
      fsobj->stateinfo = sstr.str();
      try
	{
	  this->__createNodes(origin, fsobj, i);
	}
      catch (vfsError err)
	{
	  throw std::string(err.error);
	}
      sstr.str("");
    }
}

uint64_t	FileAllocationTable::clusterOffsetInFat(uint64_t cluster, uint8_t which)
{
  uint64_t	baseoffset;
  uint64_t	idx;
  uint64_t	fatsectnum;
  uint64_t	fatentryoffset;

  baseoffset = this->__bs->firstfatoffset + (uint64_t)which * (uint64_t)this->__bs->fatsize;
  idx = 0;
  if (this->__bs->fattype == 12)
    idx = cluster + cluster / 2;
  if (this->__bs->fattype == 16)
    idx = cluster * 2;
  if (this->__bs->fattype == 32)
    idx = cluster * 4;
  fatsectnum = idx / this->__bs->ssize;
  fatentryoffset = idx % this->__bs->ssize;
  idx = fatsectnum * this->__bs->ssize + fatentryoffset;
  return (baseoffset + idx);
}

uint32_t	FileAllocationTable::ioCluster12(uint32_t current, uint8_t which)
{
  uint16_t	next;
  uint64_t	offset;

  offset = this->clusterOffsetInFat((uint64_t)current, which);
  this->__vfile->seek(offset);
  if (this->__vfile->read(&next, 2) == 2)
    return (uint32_t)next;
  else
    return 0;
}

uint32_t	FileAllocationTable::ioCluster16(uint32_t current, uint8_t which)
{
  uint16_t	next;
  uint64_t	offset;

  offset = this->clusterOffsetInFat((uint64_t)current, which);
  this->__vfile->seek(offset);
  if (this->__vfile->read(&next, 2) == 2)
    return (uint32_t)next;
  else
    return 0;
}

uint32_t	FileAllocationTable::ioCluster32(uint32_t current, uint8_t which)
{
  uint32_t	next;
  uint64_t	offset;

  offset = this->clusterOffsetInFat((uint64_t)current, which);
  this->__vfile->seek(offset);
  if (this->__vfile->read(&next, 4) == 4)
    return next;
  else
    return 0;
}

uint32_t	FileAllocationTable::cluster12(uint32_t current, uint8_t which)
{
  uint64_t	absoffset;
  uint64_t	idx;
  uint16_t	next;
  fatcache	fc;

  next = 0;
  if (which < this->__bs->numfat && (this->__fatscache[which].cache != NULL))
    {
      fc = this->__fatscache[which];
      idx = current + current / 2;
      idx = ((idx / this->__bs->ssize) * this->__bs->ssize) + (idx % this->__bs->ssize);
      if (fc.off <= idx && (idx <= fc.off + FAT_BUFF_CACHE-2))
	{
	  idx = (FAT_BUFF_CACHE - (fc.off+FAT_BUFF_CACHE-idx));
	  memcpy(&next, (uint8_t*)fc.cache+idx, 2);
	}
      else
	{
	  absoffset = this->clusterOffsetInFat((uint64_t)current, which);
	  this->__vfile->seek(absoffset);
	  if (this->__vfile->read(this->__fatscache[which].cache, FAT_BUFF_CACHE) == FAT_BUFF_CACHE)
	    {
	      this->__fatscache[which].off = idx;
	      memcpy(&next, (uint8_t*)fc.cache, 2);
	    }
	}
      if (current & 0x0001)
	next = next >> 4;
      else
	next &= 0x0FFF;
    }
  return (uint32_t)next;
}

uint32_t	FileAllocationTable::cluster16(uint32_t current, uint8_t which)
{
  uint64_t	absoffset;
  uint64_t	idx;
  uint16_t	next;
  fatcache	fc;

  next = 0;
  if (which < this->__bs->numfat && (this->__fatscache[which].cache != NULL))
    {
      fc = this->__fatscache[which];
      idx = current * 2;
      if (fc.off <= idx && (idx <= fc.off + FAT_BUFF_CACHE-2))
	{
	  idx = (FAT_BUFF_CACHE - (fc.off+FAT_BUFF_CACHE-idx)) / 2;
	  next = *((uint16_t*)fc.cache+idx);
	}
      else
	{
	  absoffset = this->clusterOffsetInFat((uint64_t)current, which);
	  this->__vfile->seek(absoffset);
	  if (this->__vfile->read(this->__fatscache[which].cache, FAT_BUFF_CACHE) == FAT_BUFF_CACHE)
	    {
	      this->__fatscache[which].off = idx;
	      next = *((uint16_t*)fc.cache);
	    }
	}
    }
  return (uint32_t)next;
}

uint32_t	FileAllocationTable::cluster32(uint32_t current, uint8_t which)
{
  uint64_t	absoffset;
  uint64_t	idx;
  uint32_t	next;
  fatcache	fc;

  next = 0;
  if (which < this->__bs->numfat && (this->__fatscache[which].cache != NULL))
    {
      fc = this->__fatscache[which];
      idx = current * 4;
      if (fc.off <= idx && (idx <= fc.off + FAT_BUFF_CACHE-4))
	{
	  idx = (FAT_BUFF_CACHE - (fc.off+FAT_BUFF_CACHE-idx)) / 4;
	  next = *((uint32_t*)fc.cache+idx);
	}
      else
	{
	  absoffset = this->clusterOffsetInFat((uint64_t)current, which);
	  this->__vfile->seek(absoffset);
	  if (this->__vfile->read(this->__fatscache[which].cache, FAT_BUFF_CACHE) == FAT_BUFF_CACHE)
	    {
	      this->__fatscache[which].off = idx;
	      next = *((uint32_t*)fc.cache);
	    }
	}
      next &= 0x0FFFFFFF;
    }
  return next;
}

uint32_t	FileAllocationTable::clusterEntry(uint32_t current, uint8_t which)
{
  uint32_t	next;

  next = 0;
  if (which >= this->__bs->numfat)
    throw(vfsError(std::string("Fat module: provided fat number for reading is too high")));
  else if (current > this->__bs->totalcluster)
    throw(vfsError(std::string("Fat module: provided cluster is too high")));
  else
    {
      if (this->__bs->fattype == 12)
	next = this->cluster12(current, which);
      if (this->__bs->fattype == 16)
	next = this->cluster16(current, which);
      if (this->__bs->fattype == 32)
	next = this->cluster32(current, which);
    }
  return next;
}

std::vector<uint64_t>	FileAllocationTable::clusterChainOffsets(uint32_t cluster, uint8_t which)
{
  std::vector<uint64_t>	clustersoffset;
  std::vector<uint32_t>	clusters;
  uint64_t		offset;
  uint32_t		i;


  
  clusters = this->clusterChain(cluster, which);
  for (i = 0; i != clusters.size(); i++)
    {
      offset = this->clusterToOffset(clusters[i]);
      clustersoffset.push_back(offset);
    }
  return clustersoffset;
}

std::vector<uint32_t>	FileAllocationTable::clusterChain(uint32_t cluster, uint8_t which)
{
  std::vector<uint32_t>	clusters;
  std::set<uint32_t>	parsed;
  uint64_t		max;
  uint32_t		eoc;

  if (which >= this->__bs->numfat)
    throw(vfsError(std::string("Fat module: provided fat number for reading is too high")));
  else if (cluster > this->__bs->totalcluster)
    throw(vfsError(std::string("Fat module: provided cluster is too high")));
  else
    {
      eoc = 2;
      if (this->__bs->fattype == 12)
	eoc = 0x0FF8;
      if (this->__bs->fattype == 16)
	eoc = 0xFFF8;
      if (this->__bs->fattype == 32)
	eoc = 0x0FFFFFF8;
      max = 0;
      mutex_lock(&this->__mutex);
      while ((cluster > 1) && (cluster < eoc) && (max < 0xFFFFFFFFL) && !this->isBadCluster(cluster) && (parsed.find(cluster) == parsed.end()))
	{
	  clusters.push_back(cluster);
	  parsed.insert(cluster);
	  max += this->__bs->csize;
	  try
	    {
	      cluster = this->clusterEntry(cluster);
	    }
	  catch(vfsError e)
	    {
	      break;
	    }
	}
      mutex_unlock(&this->__mutex);
    }
  return clusters;
}

/*
/=========================================================\
| For each list*Clusters(uint8_t which), compute a bitmap |
\=========================================================/
*/

bool			FileAllocationTable::isFreeCluster(uint32_t cluster)
{
  return cluster == 0 ? true : false;
}

bool			FileAllocationTable::isBadCluster(uint32_t cluster)
{
  if (this->__bs->fattype == 12)
    return cluster == 0x0FF7 ? true : false;
  if (this->__bs->fattype == 16)
    return cluster == 0xFFF7 ? true : false;
  if (this->__bs->fattype == 32)
    return cluster == 0x0FFFFFF7 ? true : false;
  return false;
}


bool			FileAllocationTable::clusterEntryIsFree(uint32_t cluster, uint8_t which)
{
  if (this->__bs->fattype == 12)
    return (this->cluster12(cluster, which) == 0 ? true : false);
  if (this->__bs->fattype == 16)
    return (this->cluster16(cluster, which) == 0 ? true : false);
  if (this->__bs->fattype == 32)
    return (this->cluster32(cluster, which) == 0 ? true : false);
  return false;
}


bool			FileAllocationTable::clusterEntryIsBad(uint32_t cluster, uint8_t which)
{
  if (this->__bs->fattype == 12)
    return (this->cluster12(cluster, which) == 0x0FF7 ? true : false);
  if (this->__bs->fattype == 16)
    return (this->cluster16(cluster, which) == 0xFFF7 ? true : false);
  if (this->__bs->fattype == 32)
    return (this->cluster32(cluster, which) == 0x0FFFFFF7 ? true : false);
  return false;
}


std::vector<uint64_t>	FileAllocationTable::listFreeClustersOffset(uint8_t which)
{
  uint32_t		cidx;
  std::vector<uint64_t>	freeclusters;

  if (which >= this->__bs->numfat)
    throw(vfsError(std::string("Fat module: provided fat number for reading is too high")));
  else
    for (cidx = 0; cidx != this->__bs->totalcluster; cidx++)
      if (this->clusterEntryIsFree(cidx, which))
	freeclusters.push_back(this->clusterToOffset(cidx));
  return freeclusters;
}

std::vector<uint32_t>	FileAllocationTable::listFreeClusters(uint8_t which)
{
  uint32_t		cidx;
  std::vector<uint32_t>	freeclusters;

  if (which >= this->__bs->numfat)
    throw(vfsError(std::string("Fat module: provided fat number for reading is too high")));
  else
    for (cidx = 0; cidx != this->__bs->totalcluster; cidx++)
      if (this->clusterEntryIsFree(cidx, which))
	freeclusters.push_back(cidx);
  return freeclusters;
}

uint32_t		FileAllocationTable::freeClustersCount(uint8_t which)
{
  uint32_t					freeclust;
  uint32_t					cidx;
  std::map<uint32_t, uint32_t>::iterator	it;

  freeclust = 0;
  if (which >= this->__bs->numfat)
    throw(vfsError(std::string("Fat module: provided fat number for reading is too high")));
  else
    {
      if ((it = this->__freeClustCount.find(which)) != this->__freeClustCount.end())
	freeclust = it->second;
      else
	{
	  for (cidx = 0; cidx != this->__bs->totalcluster; cidx++)
	    if (this->clusterEntryIsFree(cidx, which))
	      freeclust++;
	  this->__freeClustCount[which] = freeclust;
	}
    }
    return freeclust;
}

std::vector<uint32_t>	FileAllocationTable::listAllocatedClusters(uint8_t which)
{
  std::vector<uint32_t>	allocated;
  uint32_t		cidx;
  uint32_t		clustent;

  if (which >= this->__bs->numfat)
    throw(vfsError(std::string("Fat module: provided fat number for reading is too high")));
  else
    {
      for (cidx = 0; cidx != this->__bs->totalcluster; cidx++)
	{
	  clustent = this->clusterEntry(cidx, which);
	  if (!this->isFreeCluster(clustent) && !this->isBadCluster(clustent))
	    allocated.push_back(cidx);
	}
    }
  return allocated;
}

uint32_t		FileAllocationTable::allocatedClustersCount(uint8_t which)
{
  uint32_t					cidx;
  uint32_t					alloc;
  std::map<uint32_t, uint32_t>::iterator	it;
  uint32_t					clustent;

  alloc = 0;
  if (which >= this->__bs->numfat)
    throw(vfsError(std::string("Fat module: provided fat number for reading is too high")));
  else
    {
      if ((it = this->__allocClustCount.find(which)) != this->__allocClustCount.end())
	alloc = it->second;
      else
	{
	  for (cidx = 0; cidx != this->__bs->totalcluster; cidx++)
	    {
	      clustent = this->clusterEntry(cidx, which);
	      if (!this->isFreeCluster(clustent) && !this->isBadCluster(clustent))
		alloc++;
	    }
	  this->__allocClustCount[which] = alloc;
	}
    }
  return alloc;
}


std::vector<uint32_t>	FileAllocationTable::listBadClusters(uint8_t which)
{
  std::vector<uint32_t>	badclust;
  uint32_t		cidx;

  if (which >= this->__bs->numfat)
    throw(vfsError(std::string("Fat module: provided fat number for reading is too high")));
  else
    for (cidx = 0; cidx != this->__bs->totalcluster; cidx++)
      if (this->clusterEntryIsBad(cidx, which))
	badclust.push_back(cidx);
  return badclust;
}

uint32_t					FileAllocationTable::badClustersCount(uint8_t which)
{
  uint32_t					badclust = 0;
  uint32_t					cidx;
  std::map<uint32_t, uint32_t>::iterator	it;


  if (which >= this->__bs->numfat)
    throw(vfsError(std::string("Fat module: provided fat number for reading is too high")));
  else
    {
      if ((it = this->__badClustCount.find(which)) != this->__badClustCount.end())
	badclust = it->second;
      else
	{
	  for (cidx = 0; cidx != this->__bs->totalcluster; cidx++)
	    if (this->clusterEntryIsBad(cidx, which))
	      badclust++;
	  this->__badClustCount[which] = badclust;
	}
    }
  return badclust;
}

uint64_t		FileAllocationTable::clusterToOffset(uint32_t cluster)
{
  uint64_t	offset;

  if (this->__bs->fattype == 12)
    cluster &= FATFS_12_MASK;
  if (this->__bs->fattype == 16)
    cluster &= FATFS_16_MASK;
  if (this->__bs->fattype == 32)
    cluster &= FATFS_32_MASK;
  offset = ((uint64_t)cluster - 2) * this->__bs->csize * this->__bs->ssize + this->__bs->dataoffset;
  return offset;
}

uint32_t		FileAllocationTable::offsetToCluster(uint64_t offset)
{
  //FIXME
  return 0;
}

void			FileAllocationTable::diffFats()
{
}

void			FileAllocationTable::__createNodes(Node* parent, fso* fsobj, uint8_t fatnum)
{
  FileAllocationTableNode*	fnode;
  uint32_t			cidx;
  uint32_t			clustent;
  std::stringstream		sstr;
  std::vector<uint32_t>		lfree;
  std::vector<uint32_t>		lbad;
  uint32_t			alloc;

  alloc = 0;
  for (cidx = 0; cidx != this->__bs->totalcluster; cidx++)
    {
      clustent = this->clusterEntry(cidx, fatnum);
      if (this->isFreeCluster(clustent))
	lfree.push_back(cidx);
      else if (this->isBadCluster(clustent))
	lbad.push_back(cidx);
      else
	alloc++;
    }
  this->__freeClustCount[fatnum] = (uint32_t)lfree.size();
  this->__badClustCount[fatnum] = (uint32_t)lbad.size();
  this->__allocClustCount[fatnum] = alloc;
  sstr << "FAT " << (fatnum + 1);
  fnode = new FileAllocationTableNode(sstr.str(), this->__bs->fatsize, NULL, fsobj);
  fnode->setContext(this, fatnum);
  if (!lfree.empty())
    {
      Node* unalloc = new Node(std::string("unallocated space"), 0, fnode, fsobj);
      this->__clustersListToNodes(unalloc, fsobj, lfree);
    }
  if (!lbad.empty())
    {
      Node* bad = new Node(std::string("bad clusters"), 0, fnode, fsobj);
      this->__clustersListToNodes(bad, fsobj, lbad);
    }
  sstr.str("");
  fsobj->registerTree(parent, fnode);
}

void			FileAllocationTable::__clustersListToNodes(Node* parent, fso* fsobj, const std::vector<uint32_t>& clusters)
{
  uint32_t		cidx;
  uint32_t		start;
  uint32_t		count;
  uint64_t		size;
  ClustersChainNode*	unode;
  std::stringstream	sstr;

  start = count = (uint32_t)-1;
  for (cidx = 0; cidx != clusters.size(); cidx++)
    {
      if (clusters[cidx] != 0)
	{
	  if (start == (uint32_t)-1)
	    {
	      start = clusters[cidx];
	      count = 1;
	    }	
	  else
	    {
	      // Current cluster starts another area. 
	      // Push the current context and start another one
	      if (clusters[cidx] != start+count)
		{
		  sstr << start << "--" << start+count;
		  size = (uint64_t)count*this->__bs->ssize*this->__bs->csize;
		  unode = new ClustersChainNode(sstr.str(), size, parent, fsobj);
		  sstr.str("");
		  unode->setContext(start, count, this->clusterToOffset(start), this->__origin);
		  start = clusters[cidx];
		  count = 1;
		}
	      else
		count++;
	    }
	}
    }
  if (start != (uint32_t)-1)
    {
      sstr << start << "--" << start+count;
      size = (uint64_t)count*this->__bs->ssize*this->__bs->csize;
      unode = new ClustersChainNode(sstr.str(), size, parent, fsobj);
      sstr.str("");
      unode->setContext(start, count, this->clusterToOffset(start), this->__origin);
    }
}

void			FileAllocationTable::fileMapping(FileMapping* fm, uint8_t which)
{
  uint64_t		offset;
  
  offset = this->__bs->firstfatoffset + (uint64_t)which * (uint64_t)this->__bs->fatsize;
  fm->push(0, this->__bs->fatsize, this->__origin, offset);
}

Attributes			FileAllocationTable::attributes(uint8_t which)
{
  Attributes		attrs;
  uint64_t		clustsize;
  uint32_t		badclust;
  
  
  clustsize = (uint64_t)this->__bs->csize * this->__bs->ssize;
  if (which < this->__bs->numfat)
    {
      attrs["free clusters"] = Variant_p(new Variant(this->freeClustersCount(which)));
      attrs["free space"] = Variant_p(new Variant(clustsize * this->freeClustersCount(which)));
      attrs["allocated clusters"] = Variant_p(new Variant(this->allocatedClustersCount(which)));
      attrs["used space"] = Variant_p(new Variant(clustsize * this->allocatedClustersCount(which)));
      if ((badclust = this->badClustersCount(which)) != 0)
	{
	  attrs["bad clusters"] = Variant_p(new Variant(this->badClustersCount(which)));
	  attrs["bad clusters space"] = Variant_p(new Variant(clustsize * badclust));
	}
      else
	attrs["bad clusters"] = Variant_p(new Variant(0));
    }
  return attrs;
}


FileAllocationTableNode::FileAllocationTableNode(std::string name, uint64_t size, Node* parent, fso* fsobj) : Node(name, size, parent, fsobj), __fat(NULL), __fatnum(0)
{
}

FileAllocationTableNode::~FileAllocationTableNode()
{
}

void			FileAllocationTableNode::setContext(class FileAllocationTable* fat, uint8_t fatnum)
{
  this->__fat = fat;
  this->__fatnum = fatnum;
}

void			FileAllocationTableNode::fileMapping(FileMapping* fm)
{
  this->__fat->fileMapping(fm, this->__fatnum);
}

Attributes		FileAllocationTableNode::_attributes(void)
{
  return this->__fat->attributes(this->__fatnum);
}

const std::string	FileAllocationTableNode::dataType(void)
{
  return std::string("fat/file-allocation-table");
}


ClustersChainNode::ClustersChainNode(std::string name, uint64_t size, Node* parent, fso* fsobj): Node(name, size, parent, fsobj), __scluster(0), __count(0), __soffset(0), __origin(NULL)
{
}

ClustersChainNode::~ClustersChainNode()
{
}

void		ClustersChainNode::setContext(uint32_t scluster, uint32_t count, uint64_t offset, Node* origin)
{
  this->__scluster = scluster;
  this->__count = count;
  this->__soffset = offset;
  this->__origin = origin;
}

void		ClustersChainNode::fileMapping(FileMapping* fm)
{
  fm->push(0, this->size(), this->__origin, this->__soffset);
  return;
}

Attributes	ClustersChainNode::_attributes(void)
{
  Attributes	attrs;

  attrs["starting cluster"] = Variant_p(new Variant(this->__scluster));
  attrs["total clusters"] = Variant_p(new Variant(this->__count));
  return attrs;
}


const std::string	ClustersChainNode::dataType()
{
  return std::string("fat/unallocated-space");
}
