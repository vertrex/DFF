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

#include "variant.hpp"
#include "node.hpp"
#include "exceptions.hpp"
#include "dstructs.hpp"
#include "dstruct.hpp"

#include "agent.hpp"
#include "agentnode.hpp"
#include "agentcache.hpp"
#include "fdmanager.hpp"
#include "vfs.hpp"

#include "dexception.hpp"

using namespace Destruct;
using namespace DFF;

mutex_def(gmutex);

ReadWork::ReadWork(Destruct::DObject* astream,  uint64_t apage) : stream(astream), page(apage)
{
}

ThreadResult   CacheWorker(ThreadData rq) //pass this Cache(this) end inherit cache
{
  WorkQueue<ReadWork*>* queue = static_cast<WorkQueue<ReadWork*>* >(rq);
  BufferCache& cache = BufferCache::instance();
  uint64_t   pageSize = cache.bufferSize();

  uint64_t  lastSeek = 0;
  while (1)
  {
    ReadWork* work = queue->remove();

    mutex_lock(&gmutex);
    for (DUInt64 i = 0; i < 4; ++i)
    {
      if (cache.find(work->page + i) == NULL) 
      {
        try
        {
          uint64_t toSeek = (work->page + i) * pageSize;
          if (toSeek != lastSeek)
          {
            work->stream->call("seek", RealValue<DUInt64>(toSeek));
            lastSeek = toSeek;
          }
          DBuffer dbuffer = work->stream->call("read", RealValue<DInt64>(pageSize));
          lastSeek += pageSize;
          cache.insert(dbuffer.data(), (work->page + i));
        }
        catch (Destruct::DException const& e)
        {
          std::cout << "Agent::CacheWorker " << e.error() << std::endl;
        }
      }
    }
    mutex_unlock(&gmutex);
    delete work;
  }
}

/**
 *  Agent
 */
Agent::Agent() : fso("agent"), __rootNode(NULL), __fdm(new FdManager), __host("127.0.0.1"), __port(3583), __cache(BufferCache::instance()), __cacheBufferSize(BufferCache::instance().bufferSize()), __lastOffset(0)
{
  std::cout << "agent init" << std::endl;
  mutex_init(&gmutex);
  this->__readQueue = new WorkQueue<ReadWork*>();
  createThread(CacheWorker, this->__readQueue, this->__workerThread);
}

Agent::~Agent()
{
}

Node*                   Agent::rootNode(void) const
{
  return (this->__rootNode);
}

void    Agent::createNode(void)
{
  Node* agentNode = new AgentNode(this->__agentObject, this);

  DObject* devices = this->__agentObject->call("list");
  
  DUInt64 size = devices->call("size");
  for (DUInt64 i = 0; i < size; ++i)
  {
    DObject* deviceObject = devices->call("get", RealValue<DUInt64>(i));

    new AgentDeviceNode(deviceObject, agentNode, this); 
  }

  this->registerTree(this->__rootNode, agentNode);
}

void    Agent::parseArguments(Attributes args)
{
  if (args.find("host") != args.end())
    this->__host = args["host"]->value<std::string >();
  else
    throw envError("Agent module need a host argument.");

  if (args.find("port") != args.end())
    this->__port = args["port"]->value<uint32_t >();
  else
    throw envError("Agent module need a port argument.");

  if (args.find("parent") != args.end())
    this->__rootNode = args["parent"]->value<Node* >();
  else
    this->__rootNode =  VFS::Get().GetNode("/");
}

void    Agent::start(Attributes args)
{
  this->parseArguments(args);

  this->setStateInfo("Connecting to host");

  try
  {
    this->connect(); 
    this->createNode();
    this->setStateInfo("Finished successfully");
    this->res["Result"] = Variant_p(new DFF::Variant(std::string("Agent module applyied successfully.")));
 }
 catch (Destruct::DException const& exception)
 {
   this->res["Result"] = Variant_p(new DFF::Variant(std::string(exception.error())));
   throw DFF::envError(exception.error());
 }
}

void    Agent::connect(void)
{
  mutex_lock(&gmutex);
  DObject* argument = DStructs::instance().generate("ClientArgument");

  argument->setValue("address", RealValue<DUnicodeString>(this->__host));
  argument->setValue("port", RealValue<DUInt32>(this->__port));

  DObject*  client = DStructs::instance().generate("Client", RealValue<DObject*>(argument));

  //client = DStructs::instance().generate("RecursiveThreadSafeObject", RealValue<DObject*>(client));

  DObject* serverLoader = client->call("generate", RealValue<DUnicodeString>("Import"));
  //if not found
  if (serverLoader->call("file", RealValue<DUnicodeString>("../modules/libdestruct_device.so")).get<DUInt8>() == 0)
    serverLoader->call("file", RealValue<DUnicodeString>("destruct_device.dll"));
  this->__agentObject = client->call("generate", RealValue<DUnicodeString>("DeviceList"));
  mutex_unlock(&gmutex);
}

std::string    Agent::host(void) const
{
  return (this->__host);
}

uint32_t        Agent::port(void) const
{
  return (this->__port);
}

void    Agent::setStateInfo(const std::string& info)
{
  this->stateinfo = info;
}

int     Agent::vopen(Node *node)
{
  DeviceFdInfo* fi = new DeviceFdInfo();

  fi->node = node;
  fi->offset = 0;
  DObject* device = static_cast<AgentDeviceNode*>(node)->device();
  
  try
  {
    mutex_lock(&gmutex);
    DObject* stream = device->call("open"); //CONNECTE HERE ? :) == MULTI THREAD ? but one cache ? donc lastOffset sert pu a rien ... 
    mutex_unlock(&gmutex);
    fi->stream = stream;
    mutex_unlock(&gmutex); 
  }
  catch (Destruct::DException const & exception)
  {
    std::cout << "Agent::vopen error " << exception.error() << std::endl;
    mutex_unlock(&gmutex);
    return (-1);
  }
  //fi->stream = DStructs::instance().generate("ThreadSafeObject", RealValue<DObject*>(stream));
  return (this->__fdm->push(fi));
}

int     Agent::vread(int fd, void *buff, unsigned int size)
{
  DeviceFdInfo*		fi = NULL;

  try
  {
    fi = static_cast<DeviceFdInfo*>(this->__fdm->get(fd));
  }
  catch (...)
  {
    return (0);
  }

  if (size > this->__cache.bufferSize()) //XXX cout pour voir si fait souvent si non augmenter et mettre en multi page cache
  {
    mutex_lock(&gmutex);
    int32_t               returnSize = 0;
    std::cout << "Agent::large read " << size << std::endl;
    //if (this->__lastOffset != fi->offset)
    //{
      fi->stream->call("seek", RealValue<DUInt64>(fi->offset)); //optimize for lot of contigous read (flag offset change XXX check ret 
      this->__lastOffset = fi->offset * this->__cacheBufferSize;
      //}
    DBuffer dbuffer = ((DObject*)fi->stream)->call("read", RealValue<DInt64>(size));
    this->__lastOffset += this->__cacheBufferSize;
    returnSize = dbuffer.size();
    if (returnSize != (int32_t)size)
       std::cout << "agent::vread large read " << dbuffer.size() << " instead of " << size << std::endl;
    if (returnSize == -1)
      return -1;
    fi->offset += returnSize;
    memcpy(buff, dbuffer.data(), size);
    mutex_unlock(&gmutex);
    return (returnSize);
  }

  uint64_t readed = 0;
  while (readed < size) 
  {
    uint64_t page = fi->offset / this->__cacheBufferSize;
    uint64_t pageStartOffset = fi->offset % this->__cacheBufferSize;
       
    if (fi->offset > fi->node->size())
      return (0);
 
    uint8_t* pageBuff = this->__cache.find(page);
    if (pageBuff == NULL)
    {
      this->__readQueue->add(new ReadWork(fi->stream, page));
      //problem de seek ???? cat on avance de 2 page ?
      while (pageBuff == NULL)
      {
        pageBuff = this->__cache.find(page);
      }

      //fi->stream->call("seek", RealValue<DUInt64>(page * this->__cacheBufferSize)); 
      //this->__lastOffset = page * this->__cacheBufferSize;
      //DBuffer dbuffer = ((DObject*)fi->stream)->call("read", RealValue<DInt64>(this->__cacheBufferSize)); //mecpy 
      //this->__lastOffset += this->__cacheBufferSize;
      //pageBuff = this->__cache.insert(dbuffer.data(), page);
    }

    uint32_t sizeToRead = this->__cacheBufferSize - pageStartOffset;
    if (sizeToRead > (size - readed))
      sizeToRead = size - readed; // read de 2 on va pas copy de 4096 le buff est pas assez gros 

    memcpy((uint8_t*)buff + readed, pageBuff + pageStartOffset, sizeToRead);
    readed += sizeToRead;
    fi->offset += sizeToRead;
  }

  //uint64_t nextPage = (fi->offset / this->__cacheBufferSize) + 1; //car ca met trop de temps cheloou a mort  // +1 ? vraiemnt utile car on a deja fait le + offset
    //std::cout << "puting next page " << nextPage << std::endl;
    //this->__readQueue->add(new ReadWork(fi->stream, nextPage));// page ++ : if not in cache !!!!!)

  return (size);

}

uint64_t        Agent::vseek(int fd, uint64_t offset, int whence)
{
  Node*	node;
  DeviceFdInfo * fi;

  try
  {
    fi = static_cast<DeviceFdInfo*>(this->__fdm->get(fd));
    node = fi->node;

    if (whence == 0)
    {
      if (offset <= node->size())
      {
        fi->offset = offset;
        return (fi->offset);
      } 
    }
    else if (whence == 1)
    {
      if (fi->offset + offset <= node->size())
      {
        fi->offset += offset;
	return (fi->offset);
      }
    }
    else if (whence == 2)
    {
      fi->offset = node->size();
      return (fi->offset);
    }
  }
  catch (...)
  {
  }

  return ((uint64_t) -1);
}

uint64_t	Agent::vtell(int32_t fd)
{
  fdinfo*		fi;

  try 
  {
    fi = this->__fdm->get(fd);
    return fi->offset;
  }
  catch (...)
  {
    return (-1);
  }
}

int Agent::vclose(int fd)
{
  DeviceFdInfo*  fi = static_cast<DeviceFdInfo*>(this->__fdm->get(fd));
  mutex_lock(&gmutex);
  fi->stream->call("close");
  mutex_unlock(&gmutex);
  this->__fdm->remove(fd);

  return (0);
}

uint32_t        Agent::status(void)
{
  return (0);
}
