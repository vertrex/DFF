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

#include "datetime.hpp"
#include "exceptions.hpp"

#include "fattree.hpp"
#include <unicode/unistr.h>

FatTree::FatTree() :  __bs(NULL), __fat(NULL), __origin(NULL), __fsobj(NULL), __vfile(NULL), __emanager(NULL), __allocatedClusters(NULL),
		      __usedfat(0), __depth(0), __allocount(0), __processed(0),	__volname(), __rootdir(), __deleted(), __slacknodes()

{
}


FatTree::~FatTree()
{
  delete this->__vfile;
  delete this->__emanager;
  delete this->__allocatedClusters;
}


void	FatTree::setBootSector(BootSector* bs) throw (std::string)
{
  if (bs != NULL)
    {
      delete this->__bs;
      this->__bs = bs;
    }
  else
    {
      this->__bs = NULL;
      throw std::string("Boot sector is not defined");
    }
}


void	FatTree::setFat(FileAllocationTable* fat) throw (std::string)
{
  if (fat != NULL)
    {
      delete this->__fat;
      this->__fat = fat;
    }
  else
    {
      this->__fat = NULL;
      throw std::string("Fat is not defined");
    }
}


void		FatTree::setUsedFat(uint8_t usedfat)
{
  if (usedfat > 0 && this->__bs != NULL && (usedfat - 1) < this->__bs->numfat)
     this->__usedfat = usedfat - 1;
  else
    this->__usedfat = 0;
}


void	FatTree::process(Node* origin, fso* fsobj, bool metacarve) throw (std::string)
{
  Node*		fsroot;
  uint32_t	i;

  if (this->__bs == NULL || this->__fat == NULL)
    throw std::string("Missing boot sector or fat");
  if (origin == NULL || fsobj == NULL)
    return;
  this->__origin = origin;
  this->__fsobj = fsobj;
  try
    {
      this->__reset();
      this->__vfile = this->__origin->open();
      this->__allocount = this->__fat->allocatedClustersCount(this->__usedfat);
      this->__fsobj->stateinfo = std::string("processing regular tree 0%");
      if (this->__bs->fattype == 32)
	this->walk(this->__bs->rootclust, NULL);
      else
	this->rootdir(NULL);
      if (!this->__volname.empty())
	fsroot = new Node(this->__volname, 0, NULL, fsobj);
      else
	fsroot = new Node("NONAME", 0, NULL, fsobj);
      this->__fsobj->stateinfo = std::string("processing regular tree 100%");
      this->makeSlackNodes();
      this->processDeleted();
      for (i = 0; i != this->__rootdir.size(); i++)
	fsroot->addChild(this->__rootdir[i]);
      fsobj->registerTree(origin, fsroot);
      if (this->__allocount > 0)
	this->walkMissingAlloc(origin);
      if (metacarve)
	this->walkFree(origin);
    }
  catch(...)
    {
      throw(std::string("Cannot process fat tree"));
    }
}


void	FatTree::walk(uint32_t cluster, Node* parent)
{
  std::vector<uint64_t>		clusters;
  uint32_t			cidx;
  uint32_t			bpos;
  uint8_t*			buff;
  Node*				node;
  ctx*				c;

  buff = NULL;
  try
    {
      if (this->__allocatedClusters->exists(cluster))
	return;
      this->__updateAllocatedClusters(cluster);
      clusters = this->__fat->clusterChainOffsets(cluster, this->__usedfat);
      if ((buff = (uint8_t*)malloc(this->__bs->csize * this->__bs->ssize)) == NULL)
	return;
      for (cidx = 0; cidx != clusters.size(); cidx++)
	{
	  this->__vfile->seek(clusters[cidx]);
	  if (this->__vfile->read(buff, this->__bs->csize * this->__bs->ssize) != (this->__bs->csize * this->__bs->ssize))
	    {
	      free(buff);
	      return;
	    }
	  for (bpos = 0; bpos != this->__bs->csize * this->__bs->ssize; bpos += 32)
	    {
	      if (this->__emanager->push(buff+bpos, clusters[cidx]+bpos))
		{
		  c = this->__emanager->fetchCtx();
		  if ((c->valid) && (c->cluster < this->__bs->totalcluster))
		    {
		      if (c->volume && this->__depth == 0)
			this->__volname = c->dosname;
		      else
			{
			  if (!c->deleted)
			    {
			      node = this->__allocNode(c, parent);
			      if (c->dir)
				{
				  this->__depth++;
				  this->walk(c->cluster, node);
				  this->__depth--;
				}
			      delete c;
			    }
			  else
			    this->__updateDeletedItems(c, parent);
			}
		    }
		  else
		    delete c;
		}
	    }
	}
      free(buff);
    }
  catch(...)
    {
      if (buff != NULL)
	free(buff);
    }
}


void	FatTree::rootdir(Node* parent)
{
  uint32_t			bpos;
  uint8_t*			buff;
  Node*				node;
  ctx*				c;

  buff = NULL;
  try
    {
      if ((buff = (uint8_t*)malloc(this->__bs->rootdirsize)) == NULL)
	return;
      this->__vfile->seek(this->__bs->rootdiroffset);
      if (this->__vfile->read(buff, this->__bs->rootdirsize) != (int32_t)this->__bs->rootdirsize)
	{
	  free(buff);
	  return;
	}
      for (bpos = 0; bpos != this->__bs->rootdirsize; bpos += 32)
	{
	  if (this->__emanager->push(buff+bpos, this->__bs->rootdiroffset + bpos))
	    {
	      c = this->__emanager->fetchCtx();
	      if ((c->valid) && (c->cluster < this->__bs->totalcluster))
		{
		  if (!c->deleted)
		    {
		      if (c->volume)
			this->__volname = c->dosname;
		      else
			{
			  node = this->__allocNode(c, parent);
			  if (c->dir)
			    {
			      this->__depth++;
			      this->walk(c->cluster, node);
			      this->__depth--;
			    }
			  delete c;
			}
		    }
		  else
		    this->__updateDeletedItems(c, parent);
		}
	      else
		delete c;
	    }
	}
      free(buff);
    }
  catch(...)
    {
      if (buff != NULL)
	free(buff);
    }
}


void	FatTree::makeSlackNodes()
{
  std::map<uint32_t, Node*>::iterator	mit;
  uint64_t				clustsize, slackcount;

  slackcount = this->__slacknodes.size();
  clustsize = (uint64_t)this->__bs->csize * this->__bs->ssize;
  if (slackcount != 0)
    {
      uint64_t			sprocessed, percent, prevpercent, size, clistsize;
      std::stringstream		sstr;
      std::vector<uint32_t>	clusters;
      sprocessed = percent = prevpercent = 0;
      for (mit = this->__slacknodes.begin(); mit != this->__slacknodes.end(); mit++)
	{
	  clusters = this->__fat->clusterChain(mit->first, this->__usedfat);
	  clistsize = clusters.size();
	  if (mit->second->size() < clistsize * clustsize)
	    {
	      size = clistsize * clustsize - mit->second->size();
	      FileSlack* fslack = new FileSlack(mit->second->name() + ".SLACK", size, mit->second->parent(), this->__fsobj, this);
	      if (mit->second->parent() == NULL)
		this->__rootdir.push_back(fslack);
	      fslack->setContext(mit->first, mit->second->size());
	    }
	  percent = (sprocessed * 100) / slackcount;
	  if (prevpercent < percent)
	    {
	      sstr << "processing slack space for each regular files " << percent << "%";
	      this->__fsobj->stateinfo = sstr.str();
	      sstr.str("");
	      prevpercent = percent;
	    }
	  sprocessed += 1;
	}
    }
}


void	FatTree::processDeleted()
{
  uint32_t	i;
  Node*		node;
  deletedItems*	d;
  std::stringstream	sstr;
  uint32_t		dsize;

  dsize = this->__deleted.size();
  for (i = 0; i != dsize; i++)
    {
      d = this->__deleted[i];
      sstr << "processing deleted entries " << ((i * 100) / dsize) << "%";
      this->__fsobj->stateinfo = sstr.str();
      sstr.str("");
      node = this->__allocNode(d->c, d->node);
      if (d->c->dir)
	this->walkDeleted(d->c->cluster, node);
      delete d->c;
      delete d;
    }
  this->__fsobj->stateinfo = std::string("processing deleted entries 100%");
}


void	FatTree::walkDeleted(uint32_t cluster, Node* parent)
{
  std::vector<uint32_t>		clusters;
  uint64_t			coffset;
  uint32_t			cidx;
  uint32_t			bpos;
  uint8_t*			buff;
  Node*				node;
  ctx*				c;

  buff = NULL;
  if ((!this->__allocatedClusters->find(cluster)) && (cluster != 0))
    {
      try
	{
	  clusters = this->__fat->clusterChain(cluster, this->__usedfat);
	  if ((buff = (uint8_t*)malloc(this->__bs->csize * this->__bs->ssize)) == NULL)
	    return;
	  for (cidx = 0; cidx != clusters.size(); cidx++)
	    {
	      if ((!this->__allocatedClusters->find(clusters[cidx])) && (clusters[cidx] != 0))
		{
		  coffset = this->__fat->clusterToOffset(clusters[cidx]);
		  this->__vfile->seek(coffset);
		  if (this->__vfile->read(buff, this->__bs->csize * this->__bs->ssize) != this->__bs->csize * this->__bs->ssize)
		    {
		      free(buff);
		      return;
		    }
		  for (bpos = 0; bpos != this->__bs->csize * this->__bs->ssize; bpos += 32)
		    {
		      if (this->__emanager->push(buff+bpos, coffset+bpos))
			{
			  c = this->__emanager->fetchCtx();
			  if ((c->valid) && (c->cluster < this->__bs->totalcluster))
			    {
			      if (c->deleted)
				{
				  node = this->__allocNode(c, parent);
				  this->__updateAllocatedClusters(cluster);
				  if ((c->dir) && (!this->__allocatedClusters->find(c->cluster)))
				    {
				      this->walkDeleted(c->cluster, node);
				      ctx* tricky;
				      if ((tricky = this->__emanager->fetchCtx()) != NULL)
					delete tricky;//std::cout << "Trciky Case: " << tricky->lfnname << " -- "  << tricky->dosname << std::endl;
				    }
				  this->__updateAllocatedClusters(c->cluster);
				}
			    }
			  delete c;
			}
		    }
		}
	    }
	  free(buff);
	}
      catch(...)
	{
	  if (buff != NULL)
	    free(buff);
	}
    }
}


void	FatTree::walkMissingAlloc(Node* parent)
{
  std::vector<uint32_t>		clusters;
  uint32_t			bpos;
  uint8_t*			buff;
  Node*				rootunalloc;
  ctx*				c;
  uint64_t			clustoff;
  uint32_t			fcsize;
  std::stringstream		sstr;

  buff = NULL;
  try
    {
      rootunalloc = NULL;
      if ((buff = (uint8_t*)malloc(this->__bs->csize * this->__bs->ssize)) == NULL)
	return;
      clusters = this->__fat->listAllocatedClusters(this->__usedfat);
      fcsize = clusters.size();
      uint32_t i;
      for (i = 0; i != fcsize; i++)
	{
	  sstr << "carving entries in not parsed allocated clusters " << ((i * 100) / fcsize) << "%";
	  this->__fsobj->stateinfo = sstr.str();
	  sstr.str("");
	  if (!this->__allocatedClusters->find(i))
	    {
	      this->__allocatedClusters->insert(i);
	      clustoff = this->__fat->clusterToOffset(i);
	      this->__vfile->seek(clustoff);
	      if (this->__vfile->read(buff, this->__bs->csize * this->__bs->ssize) != (this->__bs->csize * this->__bs->ssize))
		{
		  free(buff);
		  return;
		}
	      for (bpos = 0; bpos != this->__bs->csize * this->__bs->ssize; bpos += 32)
		{
		  if (this->__emanager->push(buff+bpos, clustoff+bpos))
		    {
		      c = this->__emanager->fetchCtx();
		      if (c->valid)
			{
			  if (rootunalloc == NULL)
			    rootunalloc = new Node("$OrphanedFiles", 0, NULL, this->__fsobj);
			  if ((c->size < this->__bs->totalsize) && (c->cluster < this->__bs->totalcluster))
			    this->__allocNode(c, rootunalloc);
			}
		      delete c;
		    }
		}
	    }
	}
      this->__fsobj->stateinfo = std::string("carving entries in free clusters 100%");
      free(buff);
      if (rootunalloc != NULL)
      	this->__fsobj->registerTree(parent, rootunalloc);
    }
  catch(...)
    {
      if (buff != NULL)
	free(buff);
    }  
}


void	FatTree::walkFree(Node* parent)
{
  uint32_t			bpos;
  uint64_t			clustoff;
  uint8_t*			buff;
  uint32_t			i;
  Node*				rootcarved;
  ctx*				c;
  std::stringstream		sstr;

  buff = NULL;
  try
    {
      rootcarved = NULL;
      if ((buff = (uint8_t*)malloc(this->__bs->csize * this->__bs->ssize)) == NULL)
	return;
      for (i = 0; i != this->__bs->totalcluster; i++)
	{
	  sstr << "carving entries in free clusters " << ((i * 100) / this->__bs->totalcluster) << "%";
	  this->__fsobj->stateinfo = sstr.str();
	  sstr.str("");
	  if (!this->__allocatedClusters->find(i))
	    {
	      clustoff = this->__fat->clusterToOffset(i);
	      this->__vfile->seek(clustoff);
	      if (this->__vfile->read(buff, this->__bs->csize * this->__bs->ssize) != (this->__bs->csize * this->__bs->ssize))
		{
		  free(buff);
		  return;
		}
	      for (bpos = 0; bpos != this->__bs->csize * this->__bs->ssize; bpos += 32)
		{
		  if (this->__emanager->push(buff+bpos, clustoff+bpos))
		    {
		      c = this->__emanager->fetchCtx();
		      if (c->valid)
			{
			  if (rootcarved == NULL)
			    rootcarved = new Node("$CarvedEntries", 0, NULL, this->__fsobj);
			  if ((c->size < this->__bs->totalsize) && (c->cluster < this->__bs->totalcluster))
			    this->__allocNode(c, rootcarved);
			}
		      delete c;
		    }
		}
	    }
	}
      this->__fsobj->stateinfo = std::string("carving entries in free clusters 100%");
      free(buff);
      if (rootcarved != NULL)
      	this->__fsobj->registerTree(parent, rootcarved);
    }
  catch(...)
    {
      if (buff != NULL)
	free(buff);
    }
}


void	FatTree::fileMapping(FileMapping* fm, FatNode* fnode)
{
  std::vector<uint64_t>	clusters;
  unsigned int		i;
  uint64_t		voffset;
  uint64_t		clustsize;
  uint64_t		rsize;

  voffset = 0;
  rsize = fnode->size();
  clustsize = (uint64_t)this->__bs->csize * this->__bs->ssize;
  if (!fnode->clustrealloc || (fnode->clustrealloc && !fnode->isDeleted()))
    {
      clusters = this->__fat->clusterChainOffsets(fnode->cluster, this->__usedfat);
      uint64_t	clistsize = clusters.size();
      //cluster chain is not complete
      if (clistsize > 0)
	{
	  if ((clistsize*clustsize) < fnode->size())
	    {
	      for (i = 0; i != clistsize; i++)
		{
		  fm->push(voffset, clustsize, this->__origin, clusters[i]);
		  voffset += clustsize;
		}
	      uint64_t	gap = fnode->size() - clistsize*clustsize;
	      //last chunk corresponds to the last gap between last cluster and the size and is
	      //based on the following blocks of the last cluster
	      fm->push(voffset, gap, this->__origin, clusters[clistsize-1]+clustsize);
	    }
	  else
	    {
	      //manage the mapping based on cluster chain untill node->size() is reached
	      for (i = 0; i != clusters.size(); i++)
		{
		  if (rsize < clustsize)
		    fm->push(voffset, rsize, this->__origin, clusters[i]);
		  else
		    fm->push(voffset, clustsize, this->__origin, clusters[i]);
		  rsize -= clustsize;
		  voffset += clustsize;
		}
	    }
	}
    }
}


void			FatTree::slackMapping(FileMapping* fm, FileSlack* snode)
{
  std::vector<uint64_t>	clusters;
  uint64_t		idx;
  uint64_t		remaining;
  uint64_t		voffset;
  uint64_t		clustsize;

  voffset = 0;
  clustsize = (uint64_t)this->__bs->csize * this->__bs->ssize;
  clusters = this->__fat->clusterChainOffsets(snode->ocluster, this->__usedfat);
  if (clusters.size() > 0)
    {
      idx = snode->originsize / clustsize;
      remaining = snode->originsize % clustsize;
      //first chunk can be truncated
      fm->push(voffset, clustsize - remaining, this->__origin, clusters[idx] + remaining);
      voffset += (clustsize - remaining);
      idx++;
      while (idx < clusters.size())
	{
	  fm->push(voffset, clustsize, this->__origin, clusters[idx]);
	  voffset += clustsize;
	  idx++;
	}
    }
}


Attributes		FatTree::attributes(FatNode* fnode)
{
  Attributes		attr;
  VFile*		vf;
  std::vector<uint32_t>	clusters;
  uint8_t*		entry;
  EntriesManager*	em;
  dosentry*		dos;

  vf = NULL;
  em = NULL;
  dos = NULL;
  try
    {
      em = new EntriesManager(this->__bs->fattype);
      vf = this->__origin->open();
      attr["lfn entries start offset"] =  Variant_p(new Variant(fnode->lfnmetaoffset));
      attr["dos entry offset"] = Variant_p(new Variant(fnode->dosmetaoffset));
      if ((entry = (uint8_t*)malloc(sizeof(dosentry))) != NULL)
	{
	  vf->seek(fnode->dosmetaoffset);
	  if (vf->read(entry, sizeof(dosentry)) != sizeof(dosentry))
	    {
	      free(entry);
	      delete em;
	      return attr;
	    }
	  dos = em->toDos(entry);
	  free(entry);
	  attr["modified"] = Variant_p(new Variant(new DosDateTime(dos->mtime, dos->mdate)));
	  attr["accessed"] = Variant_p(new Variant(new DosDateTime(0, dos->adate)));
	  attr["created"] = Variant_p(new Variant(new DosDateTime(dos->ctime, dos->cdate)));
	  attr["dos name (8+3)"] = Variant_p(new Variant(em->formatDosname(dos)));
	  attr["Read Only"] = Variant_p(new Variant(bool(dos->attributes & ATTR_READ_ONLY)));
	  attr["Hidden"] = Variant_p(new Variant(bool(dos->attributes & ATTR_HIDDEN)));
	  attr["System"] = Variant_p(new Variant(bool(dos->attributes & ATTR_SYSTEM)));
	  attr["Archive"] = Variant_p(new Variant(bool(dos->attributes & ATTR_ARCHIVE)));
	  attr["Volume"] = Variant_p(new Variant(bool(dos->attributes & ATTR_VOLUME)));
	  uint64_t clustsize = (uint64_t)this->__bs->csize * this->__bs->ssize;
	  if (fnode->clustrealloc)
	    attr["first cluster (!! reallocated to another existing entry)"] = Variant_p(new Variant(fnode->cluster));
	  else
	    {
	      if (!fnode->isDeleted() && fnode->size())
		{
		  clusters = this->__fat->clusterChain(fnode->cluster, this->__usedfat);
		  uint64_t clistsize = clusters.size();
		  attr["allocated clusters"] = Variant_p(new Variant(clistsize));
		  if (fnode->size() < clistsize * clustsize)
		    {
		      uint64_t	ssize = clistsize * clustsize - fnode->size();
		      attr["slack space size"] = Variant_p(new Variant(ssize));
		    }
		  else
		    {
		      uint32_t	missclust;
		      uint64_t	gap;
		      gap = fnode->size() - clistsize * clustsize;
		      missclust = gap / clustsize;
		      attr["file truncated"] = Variant_p(new Variant(true));
		      attr["missing cluters"] = Variant_p(new Variant(missclust));
		      attr["missing size"] = Variant_p(new Variant(gap));
		    }
		}
	      //for (i = 0; i != clusters.size(); i++)
	      //clustlist.push_back(new Variant(clusters[i]));
	      attr["first cluster"] = Variant_p(new Variant(fnode->cluster));
	      //attr["allocated clusters"] = new Variant(clustlist);
	    }
	}
    }
  catch(vfsError e)
    {
    }
  delete vf;
  delete em;
  delete dos;
  return attr;
}


// void	FatTree::CheckSlackNode()
// {
//   void*					zeroed;
//   void*					buff;

//   if ((zeroed = malloc(clustsize)) != NULL)
//     memset(zeroed, 0, clustsize);
//   else
//     return;
//   if ((buff = malloc(clustsize)) == NULL)
//     {
//       free(zeroed);
//       return;
//     }
//   this->__vfile->seek(offset);
//   if ((uint64_t)this->__vfile->read(buff, size) == size)
//     if (memcmp(zeroed, buff, size) != 0)
//       {
// 	FileSlack* fslack = new FileSlack(mit->second->name() + ".SLACK", size, mit->second->parent(), this->__fsobj);
// 	fslack->setContext(mit->first, mit->second->size());
//       }
//   free(buff);
//   free(zeroed);
// }

void	FatTree::__reset()
{
  delete this->__vfile;
  this->__vfile = NULL;
  delete this->__emanager;
  this->__emanager = new EntriesManager(this->__bs->fattype);
  delete this->__allocatedClusters;
  this->__allocatedClusters = new TwoThreeTree();
  this->__depth = 0;
  this->__allocount = 0;
  this->__processed = 0;
  this->__volname = "";
  this->__rootdir.clear();
  this->__deleted.clear();
  this->__slacknodes.clear();
}


Node*	FatTree::__allocNode(ctx* c, Node* parent)
{
  FatNode*	node;
  std::string	name;
  
  if (!c->lfnname.empty())
    {
      UnicodeString	us(c->lfnname.data(), c->lfnname.size(), "UTF-16LE");
      std::string	utf8 = "";
      std::string ret = us.toUTF8String(utf8);
      name = std::string(utf8.data(), utf8.size());
    }
  else
    name = c->dosname;
  node = new FatNode(name, c->size, parent, this->__fsobj, this);
  if (parent == NULL)
    this->__rootdir.push_back(node);
  if (!this->__allocatedClusters->find(c->cluster))
    node->setCluster(c->cluster);
  else
    node->setCluster(c->cluster, true);
  if (c->deleted)
    node->setDeleted();
  if (c->dir)
    node->setDir();
  else
    {
      node->setFile();
      if (!c->deleted)
	{
	  this->__updateAllocatedClusters(c->cluster);
	  this->__slacknodes[c->cluster] = node;
	}
    }
  node->setLfnMetaOffset(c->lfnmetaoffset);
  node->setDosMetaOffset(c->dosmetaoffset);
  return node;
}

void	FatTree::__updateAllocatedClusters(uint32_t cluster)
{
  std::vector<uint32_t>		clusters;
  uint32_t			cidx;
  std::stringstream		sstr;
  double			percent;

  if (cluster != 0 && !this->__fat->isBadCluster(cluster) && this->__allocount > 0)
    {
      this->__allocatedClusters->insert(cluster);
      clusters = this->__fat->clusterChain(cluster, this->__usedfat);
      this->__processed += clusters.size();
      percent = (this->__processed * 100) / this->__allocount;
      if (percent <= 100)
	{
	  sstr << "processing regular tree " << percent << "%";
	  this->__fsobj->stateinfo = sstr.str();
	}
      for (cidx = 0; cidx != clusters.size(); cidx++)
	if (clusters[cidx] != 0)
	  this->__allocatedClusters->insert(clusters[cidx]);
    }
}

void	FatTree::__updateDeletedItems(ctx* c, Node* parent)
{
  deletedItems*	d;

  d = new deletedItems;
  d->c = c;
  d->node = parent;
  this->__deleted.push_back(d);
}


FatNode::FatNode(std::string name, uint64_t size, Node* parent, fso* fsobj, FatTree* ftree): Node(name, size, parent, fsobj), clustrealloc(false), lfnmetaoffset(0), dosmetaoffset(0), cluster(0)			  
{
  this->__ftree = ftree;
}


FatNode::~FatNode()
{
}


Attributes	FatNode::_attributes()
{
  return this->__ftree->attributes(this);
}

void		FatNode::fileMapping(FileMapping* fm)
{
  return this->__ftree->fileMapping(fm, this);
}


void		FatNode::setLfnMetaOffset(uint64_t lfnmetaoffset)
{
  this->lfnmetaoffset = lfnmetaoffset;
}


void		FatNode::setDosMetaOffset(uint64_t dosmetaoffset)
{
  this->dosmetaoffset = dosmetaoffset;
}


void		FatNode::setCluster(uint32_t cluster, bool reallocated)
{
  this->clustrealloc = reallocated;
  this->cluster = cluster;
}


FileSlack::FileSlack(std::string name, uint64_t size, Node* parent, fso* fsobj, FatTree* ftree) : Node(name, size, parent, fsobj), ocluster(0), originsize(0)
{
  this->__ftree = ftree;
}


FileSlack::~FileSlack()
{
}


void		FileSlack::setContext(uint32_t ocluster, uint64_t originsize)
{
  this->ocluster = ocluster;
  this->originsize = originsize;
}


void		FileSlack::fileMapping(FileMapping* fm)
{
  this->__ftree->slackMapping(fm, this);
}


Attributes	FileSlack::_attributes()
{
  Attributes	attrs;

  //attrs["starting offset"] = new Variant(this->__offset);
  return attrs;
}
