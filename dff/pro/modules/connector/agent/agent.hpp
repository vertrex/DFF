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

#ifndef __AGENTCONNECTOR_HH__
#define __AGENTCONNECTOR_HH__

#include "fso.hpp"
#include "threading.hpp"
#include "fdmanager.hpp"
#include "drealvalue.hpp"

#include "agentcache.hpp"

namespace DFF
{
class Node;
class FdManager;
}

class ReadWork 
{
public:
  ReadWork(Destruct::DObject* astream,  uint64_t apage);
  Destruct::DObject*      stream;
  uint64_t                page;
};

ThreadResult   CacheWorker(ThreadData rq);

class DeviceFdInfo : public DFF::fdinfo
{
public:
  Destruct::DObject* stream;
  uint64_t           __lastOffset;
};

class Agent : public DFF::fso
{
public:
  Agent();
  ~Agent();

  void                  start(DFF::Attributes args);
  void                  parseArguments(DFF::Attributes args);
  void                  connect(void);
  void                  createNode(void);
  void                  setStateInfo(const std::string& info);
  DFF::Node*            rootNode(void) const;
  std::string           host(void) const;
  uint32_t              port(void) const;

  int32_t		vopen(DFF::Node* handle);
  int32_t 		vread(int fd, void *buff, unsigned int size);
  int32_t       	vreadSmall(Destruct::DObject* stream, void *buff, unsigned int size);
  int32_t 		vclose(int fd);
  uint64_t 		vseek(int fd, uint64_t offset, int whence);
  int32_t		vwrite(int fd, void *buff, unsigned int size) { return 0; };
  uint32_t		status(void);
  uint64_t		vtell(int32_t fd);
private:
  DFF::Node*            __rootNode;
  DFF::FdManager*       __fdm;
  std::string           __host;
  uint32_t              __port;
  Destruct::DObject*    __agentObject;
  BufferCache&          __cache;
  const uint64_t        __cacheBufferSize;
  uint64_t              __lastOffset;
  DFF::WorkQueue<ReadWork*>* __readQueue;
  ThreadStruct          __workerThread;
};

#endif
