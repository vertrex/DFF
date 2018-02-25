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
 *  Solal Jacob <sja@digital-forensic.org>
 */

#include "vfile.hpp"
#include "filemapping.hpp"
#include "cache.hpp"
#include "node.hpp"

namespace DFF
{

VFilePool& poolInit = VFilePool::instance();
Cache<Attributes>& attributeInit = AttributeCache::instance();
Cache<Attributes>& dynamicAttributeInit = DynamicAttributesCache::instance();

VFilePool& VFilePool::instance(void)
{
  static VFilePool      pool(100);
  return pool;
}

VFilePool::VFilePool(void)
{
  mutex_init(&this->__mutex);
  this->__allocate(20);
}

VFilePool::VFilePool(uint32_t poolSize)
{
  mutex_init(&this->__mutex);
  this->__allocate(poolSize);
}

VFilePool::~VFilePool()
{
  uint32_t i;

  for (i = 0; i < this->__poolSize; i++)
  {
    //Can't delete vfile after exit, because Py_Exit was called, interpreter finshed
    //and swig will try to lock the GIL if a mfso/fso create the vfile from python 
    //-> mfso.close is called via swig -> lock the gil already delete -> segfault
    //if (this->__poolSlot[i]->content)
    //{
      //VFile* vfile = (VFile*)this->__poolSlot[i]->content;
      //delete vfile;
    //}
    free(this->__poolSlot[i]);
  }
  free(this->__poolSlot);
}

void VFilePool::__allocate(uint32_t poolSize)
{
  uint32_t	i;

  this->__poolSize = poolSize;
  this->__poolSlot = (CacheContainer**)malloc(sizeof(CacheContainer*) * poolSize);
  for (i = 0; i < this->__poolSize; i++)
  {
     CacheContainer*	container;
     container = (CacheContainer*)malloc(sizeof(CacheContainer));
     memset(container, 0, sizeof(CacheContainer));
     this->__poolSlot[i] = container;
  } 
}

CacheContainer*	VFilePool::find(Node *node)
{
  uint32_t	i;
  VFile*	vfile;

  mutex_lock(&this->__mutex);
  for (i = 0; i < this->__poolSize; i++)
  {
     if (this->__poolSlot[i]->content != NULL)
     {
        vfile = (VFile*)this->__poolSlot[i]->content;
        if ((this->__poolSlot[i]->used == false) && (vfile->node() == node))
        {
	  this->__poolSlot[i]->cacheHits++;
	  this->__poolSlot[i]->used = true;
	  mutex_unlock(&this->__mutex);
	  return (this->__poolSlot[i]);
        }
     }
  }
  mutex_unlock(&this->__mutex);
  return (NULL);
}

void	VFilePool::unused(CacheContainer* container)
{
  mutex_lock(&this->__mutex);
  container->used = false;
  mutex_unlock(&this->__mutex); 
}

bool	VFilePool::insert(VFile *vfile)
{
  uint32_t	i;

  mutex_lock(&this->__mutex);
  for (i = 0; i < this->__poolSize; i++)
  {
     if (this->__poolSlot[i]->content == NULL)
     {
	this->__poolSlot[i]->content = vfile;
	this->__poolSlot[i]->cacheHits++;
	this->__poolSlot[i]->used = false;
	mutex_unlock(&this->__mutex);
	return (true);
     }
  }

  uint64_t  oldest = ((int64_t)-1);
  int32_t   oldestIt = 0;
  VFile*    toClose = NULL;

  for (i = 0; i < this->__poolSize; i++)
  {
     if (this->__poolSlot[i]->used == false && this->__poolSlot[i]->cacheHits < oldest)
     {
	  oldest = this->__poolSlot[i]->cacheHits;
	  oldestIt = i;
     }
  }
  if (this->__poolSlot[oldestIt]->used == false && (oldest != (uint64_t((int64_t)-1)) ))
  {
    toClose = (VFile*)this->__poolSlot[oldestIt]->content;
    this->__poolSlot[oldestIt]->cacheHits = 1;
    this->__poolSlot[oldestIt]->used = false;
    this->__poolSlot[oldestIt]->content = vfile;
  }
  else
    toClose = vfile;
  mutex_unlock(&this->__mutex);
  delete toClose;
  return false;
}

/* Attributes Cache
*
*/

Cache<Attributes>& AttributeCache::instance(void)
{
  static Cache<Attributes>  attributeCache(200);
  return attributeCache;
}

/**
*  Dynamic Attributes Cache
*/

Cache<Attributes>& DynamicAttributesCache::instance(void)
{
  static Cache<Attributes> dynamicAttributesCache(200);
  return dynamicAttributesCache;
}

/**
 * FileMapping Cache
*/
FileMappingCache::FileMappingCache(uint32_t cacheSize) : Cache(cacheSize)
{
}

FileMapping*	FileMappingCache::find(Node* node, uint64_t state)
{
  mutex_lock(&this->__mutex);
  uint32_t	i;
  FileMapping*  fm;

  for (i = 0; i < this->__cacheSize; i++)
  {
    if (this->__cacheSlot[i]->used == true)
    {
      fm = (FileMapping*)this->__cacheSlot[i]->content;
      if ((node == fm->node()) && (this->__cacheSlot[i]->state == state))
      {
        this->__cacheSlot[i]->cacheHits++;
        fm->addref();
	mutex_unlock(&this->__mutex);
	return (fm);
      }
    }
  }
  mutex_unlock(&this->__mutex);
  fm = new FileMapping(node);//recursive lock //node method director lock python interpreter
  node->fileMapping(fm);
  this->insert(fm, state);

  return (fm);
}

bool		FileMappingCache::insert(FileMapping* fm, uint64_t state)
{
  uint32_t	i;

  mutex_lock(&this->__mutex);
  for (i = 0; i < this->__cacheSize; i++)
  {
    if (this->__cacheSlot[i]->used == false)
    {
      this->__cacheSlot[i]->content = (void*)fm;
      this->__cacheSlot[i]->state = state;
      this->__cacheSlot[i]->used = true;
      this->__cacheSlot[i]->cacheHits = 1;
      fm->addref();
      mutex_unlock(&this->__mutex);
      return (true);
     }
  }

  uint64_t  oldest = this->__cacheSlot[0]->cacheHits;
  int32_t   oldestIt = 0;

  for (i = 1; i < this->__cacheSize; i++)
  {
     if (this->__cacheSlot[i]->cacheHits < oldest)
     {
          oldest = this->__cacheSlot[i]->cacheHits;
	  oldestIt = i;
     }
  }
  ((FileMapping*)this->__cacheSlot[oldestIt]->content)->delref();
  this->__cacheSlot[oldestIt]->content = (void*)fm;
  this->__cacheSlot[oldestIt]->state = state;
  this->__cacheSlot[oldestIt]->cacheHits = 1;
  fm->addref();
  mutex_unlock(&this->__mutex);

  return (false);
}

void    FileMappingCache::remove(Node* node)
{
  mutex_lock(&this->__mutex);
  uint32_t	i;
  FileMapping*  fm;

  for (i = 0; i < this->__cacheSize; i++)
  {
    if (this->__cacheSlot[i]->used == true)
    {
      fm = (FileMapping*)this->__cacheSlot[i]->content;
      if (node == fm->node())
      {
        fm->delref();
	this->__cacheSlot[i]->content = NULL;
	this->__cacheSlot[i]->state = 0;
	this->__cacheSlot[i]->cacheHits = 0;
	this->__cacheSlot[i]->used = false;
      }
    }
  }
  mutex_unlock(&this->__mutex);
  return;
}

}
