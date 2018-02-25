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

#ifndef __FILEMAPPING_HPP__
#define __FILEMAPPING_HPP__

#ifndef WIN32
#include <stdint.h>
#elif _MSC_VER >= 1600
	#include <stdint.h>
#else
#include "wstdint.h"
#endif

#include "threading.hpp"
#include "rc.hpp"
#include "export.hpp"
#include <vector>

namespace DFF
{

typedef struct
{
public:
  uint64_t      offset;
  uint64_t      size;
  class Node*   origin;
  uint64_t	originoffset;
}               chunk;

class FileMapping
{
private:
		     mutex_def(__fm_mutex);
  uint64_t			__refcount;
  Node*				__node;
  std::vector<chunk *>		__chunks;
  uint64_t			__maxOffset;
  chunk*			__makeChunk(uint64_t offset, uint64_t size, class Node* origin, uint64_t originoffset);
  void				__manageConflicts(uint32_t idx, uint64_t offset, uint64_t size, class Node* origin, uint64_t originoffset);
  uint32_t			__bsearch(uint64_t offset, uint32_t leftbound, uint32_t rightbound, bool* found);
  void				allocChunk(uint64_t offset, uint64_t size, class Node* origin, uint64_t originoffset);
  void				forceAllocChunk(uint64_t offset, uint64_t size, class Node* origin, uint64_t originoffset);
  chunk*			chunkFromIdx(uint32_t idx);
  std::vector<chunk *>		chunksFromIdxRange(uint32_t begidx, uint32_t endidx);
public:
  EXPORT 			FileMapping(Node* node);
  EXPORT 			~FileMapping();
  EXPORT void			addref();
  EXPORT void			delref();
  EXPORT uint64_t		refcount();
  EXPORT Node*			node(void);
  EXPORT uint64_t		maxOffset();
  EXPORT chunk*			chunkFromOffset(uint64_t offset);
  EXPORT void			push(uint64_t offset, uint64_t size, class Node* origin=NULL, uint64_t originoffset=0, bool force=false);
  EXPORT uint32_t		chunkCount(void);
  EXPORT chunk*			firstChunk(void);
  EXPORT chunk*			lastChunk(void);
  EXPORT uint32_t			chunkIdxFromOffset(uint64_t offset, uint32_t begidx=0);
  EXPORT std::vector<chunk *>		chunksFromOffsetRange(uint64_t begoffset, uint64_t endoffset);
  EXPORT std::vector<chunk *>		chunks(void);
};

}
#endif
