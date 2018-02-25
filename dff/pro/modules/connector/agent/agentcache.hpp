/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *  
 * See http: *www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 * 
 * Author(s):
 *  Solal Jacob <sja@digital-forensic.org>
 */

#ifndef __AGENTCACHE_HH__
#define __AGENTCACHE_HH__

#include <time.h>
#include <map>
#include <queue>
#include <stdint.h>

#include "threading.hpp"
#include "export.hpp"
#include "drealvalue.hpp"

/*
#ifndef WIN32
#ifdef __i386
extern __inline__ uint64_t rdtsc(void) {
  uint64_t x;
  __asm__ volatile ("rdtsc" : "=A" (x));
  return x;
}
#elif defined __amd64
extern __inline__ uint64_t rdtsc(void) {
  uint64_t a, d;
  __asm__ volatile ("rdtsc" : "=a" (a), "=d" (d));
  return (d<<32) | a;
}
#endif
#else
__declspec(naked)
unsigned __int64 __cdecl rdtsc(void)
{
   __asm
   {
      rdtsc
      ret       ; valeur de retour dans EDX:EAX
   }
}
#endif
*/

namespace Destruct
{
class DObject;
}

bool operator <(const timespec& lhs, const timespec& rhs);

class CacheSlot
{
public:
  CacheSlot();
  ~CacheSlot();
  uint8_t*      buffer;
  timespec      cacheHits;
};

class BufferCache //XXX et si y a 2 device on fait quoi ?????? il faut un cache par device ou un cache qui peut contenir les pages de plusieur de vices ...  
{
public:
  EXPORT        static BufferCache&     instance();

  //            read(offset, size, buff);
  //            read et pre-cache ds une thread ....

  uint8_t*      find(uint64_t page);
  uint8_t*      insert(uint8_t* buffer, uint64_t page); //USE dbuffer directly ? buff + size so different size can be cached !
  uint32_t      slotCount() const;
  uint32_t      bufferSize() const;
private:
  BufferCache(uint32_t slotCount, uint32_t bufferSize);
  BufferCache(BufferCache const&);
  ~BufferCache();

  uint32_t      __slotCount;
  uint32_t      __bufferSize;

  std::map<uint64_t, CacheSlot*>  __cacheSlots;
  std::map<timespec, uint64_t>    __oldest;

  mutex_def(__mutex); 
};

#endif
