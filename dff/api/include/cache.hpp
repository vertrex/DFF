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

#ifndef __CACHE_HPP__
#define __CACHE_HPP__

#ifndef WIN32
  #include <stdint.h>
#elif _MSC_VER >= 1600
  #include <stdint.h>
#else
  #include "wstdint.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "export.hpp"
#include "threading.hpp"
#include "rc.hpp"

namespace DFF
{

class Node;
class VFile;
class FileMapping;
class Variant;

typedef std::map<std::string, RCPtr< class Variant > > Attributes;

struct CacheContainer
{
  void*		content;
  void*         key;
  uint64_t      state;
  uint64_t	cacheHits;
  bool		used;
};

class VFilePool
{
private:
			        mutex_def(__mutex);
  EXPORT		        VFilePool();
  EXPORT		        VFilePool(uint32_t pool);
  VFilePool&		        operator=(VFilePool&);
			        VFilePool(const VFilePool&);
  EXPORT		        ~VFilePool();
  uint32_t		        __poolSize;
  CacheContainer**	        __poolSlot;
  void                          __allocate(uint32_t poolSize);
public:
  EXPORT static VFilePool&      instance();
  EXPORT CacheContainer*        find(Node* node);
  EXPORT bool                   insert(VFile* vfile);
  EXPORT void                   unused(CacheContainer* container);
};

template< class T > class Cache
{
public:
   		                mutex_def(__mutex);
  uint32_t                      __cacheSize;
  CacheContainer**              __cacheSlot;
  void                          __allocCache(uint32_t cacheSize)
  {
    uint32_t      i;

    this->__cacheSize = cacheSize;
    this->__cacheSlot = (CacheContainer**)malloc(sizeof(CacheContainer*) * cacheSize); 
    for (i = 0; i < this->__cacheSize; i++)
    {
      CacheContainer*     container;

      container = (CacheContainer*)malloc(sizeof(CacheContainer));
      memset(container, 0, sizeof(CacheContainer));
      this->__cacheSlot[i] = container;
    }
  };

  EXPORT                        Cache()
  {
    mutex_init(&this->__mutex);
    this->__allocCache(20); 
  };

  EXPORT                        Cache(uint32_t cacheSize)
  {
    mutex_init(&this->__mutex);
    this->__allocCache(cacheSize); 
  };

  EXPORT virtual                ~Cache()
  {
    for (uint32_t i = 0; i < this->__cacheSize; i++)
    {
      delete ((T*)this->__cacheSlot[i]->content);
      free (this->__cacheSlot[i]);
    }
    free(this->__cacheSlot);
    mutex_destroy(&this->__mutex);
  };

  EXPORT T                      find(Node* node, uint64_t state = 0)
  {
    uint32_t	i;

    mutex_lock(&this->__mutex);
    for (i = 0; i < this->__cacheSize; i++)
    {
       if (this->__cacheSlot[i]->used == true)
       {
         if (this->__cacheSlot[i]->key == (void*)node && this->__cacheSlot[i]->state == state)
         {
           this->__cacheSlot[i]->cacheHits++;
           T attributes = *((T*)this->__cacheSlot[i]->content);
           mutex_unlock(&this->__mutex);
           return (attributes);
         }
       }

    }
    mutex_unlock(&this->__mutex);
    throw std::string("can't find attribute");
  };

  EXPORT bool                   insert(Node* node, T content, uint64_t state = 0)
  {
    uint32_t	i;

    mutex_lock(&this->__mutex);
    for (i = 0; i < this->__cacheSize; i++)
    {
       if (this->__cacheSlot[i]->used == false)
       {
          T*  newContent = new T(content);
	  this->__cacheSlot[i]->content = (void*)newContent;
          this->__cacheSlot[i]->key = (void*)node;
          this->__cacheSlot[i]->state = state;
          this->__cacheSlot[i]->used = true;
	  this->__cacheSlot[i]->cacheHits = 1; 
	  mutex_unlock(&this->__mutex);

	  return (true);
       }
    }

    uint64_t  oldest = (this->__cacheSlot[0])->cacheHits;
    int32_t   oldestIt = 0;

    for (i = 1; i < this->__cacheSize; i++)
    {
       if (this->__cacheSlot[i]->cacheHits < oldest)
       {
          oldest = this->__cacheSlot[i]->cacheHits;
	  oldestIt = i;
       }
    }
    T*   newContent = new T(content);
    delete ((T*)this->__cacheSlot[oldestIt]->content);
    this->__cacheSlot[oldestIt]->content = (void*)newContent;
    this->__cacheSlot[oldestIt]->key = (void*)node;
    this->__cacheSlot[oldestIt]->state = state;
    this->__cacheSlot[oldestIt]->cacheHits = 1;
    mutex_unlock(&this->__mutex);

    return (false);
  };
};

class AttributeCache : private Cache< Attributes >
{
private:
  AttributeCache&               operator=(AttributeCache&);
                                AttributeCache(const AttributeCache&);
                                ~AttributeCache();
public:
  EXPORT static Cache<Attributes>& instance();
};

class DynamicAttributesCache : private Cache < Attributes > 
{
private:
  DynamicAttributesCache&       operator=(DynamicAttributesCache&);
                                DynamicAttributesCache(const DynamicAttributesCache&);
                                ~DynamicAttributesCache();
public:
  EXPORT static Cache<Attributes>&          instance();
};

class FileMappingCache : private Cache < FileMapping* >
{
public:
  EXPORT                        FileMappingCache(uint32_t CacheSize);
  EXPORT FileMapping*           find(Node* node, uint64_t state);
  EXPORT bool		        insert(FileMapping* fm, uint64_t state);
  EXPORT void                   remove(Node* node);
};

}
#endif
