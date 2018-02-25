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

#include "devices.hpp"
#include "typesconv.hpp"
#include "path.hpp"
#include <String>
#include <windows.h>
#include <shlwapi.h>

DeviceBuffer::DeviceBuffer(HANDLE hndl, uint32_t size,  uint32_t bps, uint64_t devSize) : __handle(hndl), __offset(0), __BPS(bps), __currentSize(0), __devSize(devSize), __size(size * bps) 
{
  this->__buffer = (uint8_t *)malloc(this->__size);
  this->fillBuff(0);
}

DeviceBuffer::~DeviceBuffer()
{
   CloseHandle(this->__handle);
   free(this->__buffer);
}

void DeviceBuffer::fillBuff(uint64_t offset)
{
  LARGE_INTEGER sizeConv;
  LARGE_INTEGER newOffset;
	
  if (this->__offset > this->__devSize)
  {
    this->__currentSize = 0;
    return;
  }
  this->__offset = ((offset / this->__BPS) * this->__BPS);
  sizeConv.QuadPart = this->__offset;
  SetFilePointerEx(this->__handle, sizeConv, &newOffset, 0);
  DWORD gsize;
  if (this->__offset + this->__size > this->__devSize)
    gsize = (DWORD)(this->__devSize - this->__offset);
  else
    gsize = this->__size;
  ReadFile(this->__handle, (void*)(this->__buffer), gsize,  &(this->__currentSize) ,0);
}

uint32_t	DeviceBuffer::getData(void *buff, uint32_t size, uint64_t offset)
{
  if ((offset < this->__offset) || (offset > this->__offset + this->__currentSize) 
      ||(offset + size > this->__offset + this->__currentSize))
  {
    this->fillBuff(offset);
  }

  uint64_t leak = offset - this->__offset;
  if (size > this->__currentSize - leak)
    size = (uint32_t)(this->__currentSize - leak);
  memcpy(buff, (((char*)this->__buffer) + leak), size);

  return (size);
}


devices::devices() : fso("devices"), __parent(NULL), __root(NULL), __fdm(new FdManager)
{
}

devices::~devices()
{
  delete this->__fdm;
}

void                    devices::start(std::map<std::string, Variant_p > args)
{
  std::string		path;
  Path*                 lpath;
  s_ull			sizeConverter;
  uint64_t		size =0;
  std::string		nname;

  if (args.find("parent") == args.end())
    throw envError("Device module requires a parent argument.");
  else
    this->__parent = args["parent"]->value<Node* >();

  if (args.find("path") == args.end())
    throw envError("Device module require a device path argument.");
  else
    lpath = args["path"]->value<Path *>();
  
  if (args.find("size") == args.end())
    size = 0;
  else 
    size = args["size"]->value<uint64_t >();

  if (args.find("name") == args.end())
    nname = "";
  else
    nname = args["name"]->value<std::string >();

  this->devicePath = lpath->path;
  sizeConverter.ull = size;

  HANDLE hnd = CreateFile(this->devicePath.c_str(), GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE,
			   NULL, OPEN_EXISTING, 0, NULL);
  if (((HANDLE)hnd) == INVALID_HANDLE_VALUE)
  {
    res["error"] = Variant_p(new Variant(std::string("Can't open devices.")));	
    return ;
  }
  else
  {
    DWORD bytes;
    GET_LENGTH_INFORMATION diskSize;
    if (DeviceIoControl(hnd, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &diskSize, sizeof(diskSize), &bytes, NULL))
      size = (uint64_t)diskSize.Length.QuadPart;
    CloseHandle(hnd);
    this->__root = new DeviceNode(this->devicePath, sizeConverter.ull,  this, nname);
    this->__root->setFile();
    this->registerTree(this->__parent, this->__root);
  }	
}

int     devices::vopen(Node *node)
{
  fdinfo*	fi;
  int32_t	fd;

  if (node != NULL) 
  {
    fi = new fdinfo;
    int hnd = (int)CreateFile(((DeviceNode*)node)->__devname.c_str(), GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE,
			       NULL, OPEN_EXISTING, 0, NULL);
    fi->id = new Variant((void*) (new DeviceBuffer((HANDLE)hnd, 100 * sizeof(uint8_t), 4096, node->size())));
    fi->node = node;
    fi->offset = 0;
    fd = this->__fdm->push(fi);
    return (fd);
  }
  else
    return (-1);
}

int     devices::vread(int fd, void *buff, unsigned int origSize)
{ 
  fdinfo*               fi;
  DeviceBuffer*         dbuff;
  uint32_t              readed;
  uint32_t              aReaded = 0;
	
  try
  {
    fi = this->__fdm->get(fd);
    dbuff = (DeviceBuffer*)fi->id->value<void *>();
  }
  catch (...)
  {
    return (0); 
  }

  while (aReaded < origSize)
  {
    readed = dbuff->getData(((uint8_t *)buff + aReaded), origSize - aReaded, fi->offset);
    fi->offset += ((uint64_t)readed);
    aReaded += readed;
    if (fi->offset > this->__root->size())
    {
      fi->offset = this->__root->size();
      return (aReaded);
    }
    if (readed < dbuff->__size)
      return (aReaded); 
  }
  return aReaded;
}

int     devices::vclose(int fd)
{
  try
  {
    fdinfo* fi = this->__fdm->get(fd);
    delete ((DeviceBuffer*)fi->id->value<void *>());
    this->__fdm->remove(fd);
    return (0);
  }
  catch (...)
  {
    return (-1);
  }
}

uint64_t        devices::vseek(int fd, uint64_t offset, int whence)
{
  fdinfo*	fi;
  Node*	node;

  try
  {
    fi = this->__fdm->get(fd);
    node = dynamic_cast<Node*>(fi->node);
	 
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
    return ((uint64_t) -1);
  }
  return ((uint64_t) -1);
}

uint64_t	devices::vtell(int32_t fd)
{
  fdinfo*	fi;

  try
  {
    fi = this->__fdm->get(fd);
    return (fi->offset);
  }
  catch (...)
  {
    return (uint64_t)-1; 
  }
}

unsigned int    devices::status(void)
{
  return (1);
}

