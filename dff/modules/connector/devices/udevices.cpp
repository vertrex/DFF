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

#include "path.hpp"
#include "devices.hpp"

#include <fcntl.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <iostream>
#include <sstream>
#include <errno.h>


devices::devices(): fso("devices"), __parent(NULL), __root(NULL), __fdm()
{
}

devices::~devices()
{
}

void devices::start(std::map<std::string, Variant_p > args)
{
  std::map<std::string, Variant_p >::iterator	argit;
  std::string 					path;
  std::string					name;
  uint64_t					size;

  if (args["parent"] == NULL)
    throw envError("Device module requires a parent argument.");
  else
    this->__parent = args["parent"]->value<Node* >();

  if (args["path"] == NULL)
    throw envError("Device module require a device path argument.");
  else
    path = args["path"]->value<Path *>()->path;
  
  if (args["size"] == NULL)
    size = 0;
  else 
    size = args["size"]->value<uint64_t >();

  if (args["name"] == NULL)
    name = path.substr(path.rfind('/') + 1);
  else
    name = args["name"]->value<std::string >();

  DeviceNode* dev = new DeviceNode(path, size, this, name);
  this->registerTree(this->__parent, dev);
}

int devices::vopen(Node *node)
{
  int n;
  struct stat 	stbuff;
  std::string	file;

  DeviceNode* dev = dynamic_cast<DeviceNode *>(node);
  if (!dev)
    throw std::string("devies::open error can't dynamic cast node");

#if defined(__FreeBSD__)
  if ((n = open(dev->__devname.c_str(), O_RDONLY)) == -1)
#elif defined(__linux__)
  if ((n = open(dev->__devname.c_str(), O_RDONLY | O_LARGEFILE)) == -1)
#endif
    throw vfsError("devices::open error can't open file");
  if (stat(dev->__devname.c_str(), &stbuff) == -1)
    throw vfsError("devices::open error can't stat");
  return (n);
}

int devices::vread(int fd, void *buff, unsigned int size)
{
  int n;
  
  n = read(fd, buff, size);
  if (n < 0)
  {
    if (errno == EIO)
      {
	throw vfsError("devicess::EIO error");
      }
    else
      throw vfsError("devices::vread error read = -1");
  }
  return n;
}

int devices::vclose(int fd)
{
  if (close(fd) == -1)
  {
    throw vfsError("devices::close error can't close");
  }
  return (0);
}

uint64_t devices::vseek(int fd, uint64_t offset, int whence)
{
 uint64_t  n = 0;

 if (whence == 0)
   whence = SEEK_SET;
 else if (whence == 1)
   whence = SEEK_CUR;
 else if (whence == 2)
   whence = SEEK_END;
#if defined(__FreeBSD__) || defined(__APPLE__)
 n = lseek(fd, offset, whence);
#elif defined(__linux__)
 n = lseek64(fd, offset, whence);
#endif
 if (n == ((uint64_t)-1))
   {
     throw vfsError("devices::vseek can't seek error " + std::string(strerror(errno)));
   }
 return (n);
}

uint64_t	devices::vtell(int32_t fd)
{
  uint64_t	pos;

  pos = this->vseek(fd, 0, 1);
  return pos;
}

unsigned int devices::status(void)
{
  return (1);
}
