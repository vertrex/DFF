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

#include "local.hpp"

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

#include "path.hpp"
#include "vfs.hpp"
#include "exceptions.hpp"

local::local(): fso("local"), nfd(0), parent(NULL)
{
}

local::~local()
{
}

void local::iterdir(std::string dir, Node *parent)
{
  struct stat		stbuff; 
  struct dirent*	dp;
  DIR*			dfd;
  std::string		upath;
  
  if ((dfd = opendir(dir.c_str())))
  {
    while ((dp = readdir(dfd)))
    {
      if (!strcmp(dp->d_name, ".")  || !strcmp(dp->d_name, ".."))
	continue; 
      upath = dir + "/" + dp->d_name;
      if (lstat(upath.c_str(), &stbuff) != -1)
      {
	if (((stbuff.st_mode & S_IFMT) == S_IFDIR ))
	{
	  ULocalNode* tmp = new ULocalNode(dp->d_name, 0, parent, this, ULocalNode::DIR,  upath);
	  this->iterdir(upath, tmp);
	}
	else
          new ULocalNode(dp->d_name, stbuff.st_size, parent, this, ULocalNode::FILE, upath);
      }
    }
    closedir(dfd);
  }
}

void	local::createTree(std::list<Variant_p > vl)
{
  std::list<Variant_p >::iterator	it;
  Path*					tpath;
  std::string				name;
  struct stat				stbuff;

  for (it = vl.begin(); it != vl.end(); it++)
  {
    tpath = (*it)->value<Path*>();
    if ((tpath->path.rfind('/') + 1) == tpath->path.length())
      tpath->path.resize(tpath->path.rfind('/'));
    name = tpath->path.substr(tpath->path.rfind("/") + 1);
    this->basePath = tpath->path.substr(0, tpath->path.rfind('/'));
    if (stat(tpath->path.c_str(), &stbuff) == -1)
    {
      return ;
    }
    if (((stbuff.st_mode & S_IFMT) == S_IFDIR ))
    {
      Node *dir = new ULocalNode(name, 0, NULL, this, ULocalNode::DIR, tpath->path);
      this->iterdir(tpath->path, dir);
      this->registerTree(this->parent, dir);
    }
    else
    {
      Node *f;
      f = new ULocalNode(name, stbuff.st_size, NULL, this, ULocalNode::FILE, tpath->path);
      this->registerTree(this->parent, f);
    }
  }
}

void local::start(std::map<std::string, Variant_p > args)
{
  std::map<std::string, Variant_p >::iterator	argit;

  if ((argit = args.find("parent")) != args.end())
    this->parent = argit->second->value<Node*>();
  else
    this->parent = VFS::Get().GetNode("/");
  if ((argit = args.find("path")) != args.end())
    if (argit->second != NULL)
      this->createTree(argit->second->value<std::list<Variant_p > >());
    else
      throw(envError("local module requires at least one path parameter"));
  else
    throw(envError("local module requires path argument"));
  return ;
}

int local::vopen(Node *node)
{
  int n;
  struct stat 	stbuff;
  std::string	file;
  ULocalNode*	unode = dynamic_cast<ULocalNode* >(node);

  if (unode == NULL)
   return (0);
  file = unode->originalPath; 
#if defined(__FreeBSD__) || defined(__APPLE__)
  if ((n = open(file.c_str(), O_RDONLY)) == -1)
#elif defined(__linux__)
  if ((n = open(file.c_str(), O_RDONLY | O_LARGEFILE)) == -1)
#endif
      throw vfsError("local::open error can't open file");
  if (stat(file.c_str(), &stbuff) == -1)
    throw vfsError("local::open error can't stat");
  if (((stbuff.st_mode & S_IFMT) == S_IFDIR ))
    throw vfsError("local::open error can't open directory");
  nfd++;
  return (n);
}

int	local::vread_error(int fd, void *buff, unsigned int size)
{
  unsigned int	pos;
  int		n;
  int		toread;

  pos = 0;
  while (pos < size)
  {
    if (size - pos < 512)
      toread = size - pos;
    else
      toread = 512;
    if ((n = read(fd, ((char*)buff)+pos, toread)) == -1)
    {
      memset(((char*)buff)+pos, 0, toread);
      this->vseek(fd, toread, 1);
    }
    pos += toread;
  }
  return size;
}

int local::vread(int fd, void *buff, unsigned int size)
{
  int n;
  
  n = read(fd, buff, size);
  if (n < 0)
  {
    if (errno == EIO)
    {
      std::cout << "io error " << std::endl;
      return this->vread_error(fd, buff, size);
    }
    else
      throw vfsError("local::vread error read = -1");
  }
  return n;
}

int local::vclose(int fd)
{
  if (close(fd) == -1)
  {
    throw vfsError("local::close error can't close");
  }
  nfd--;
  return (0);
}

uint64_t local::vseek(int fd, uint64_t offset, int whence)
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
   throw vfsError("local::vseek can't seek error " + std::string(strerror(errno)));
 }
 return (n);
}

uint64_t	local::vtell(int32_t fd)
{
  uint64_t	pos;

  pos = this->vseek(fd, 0, 1);
  return pos;
}

unsigned int local::status(void)
{
  return (nfd);
}
