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

#include "fuse.hpp"
#include "vfile.hpp"
#include "node.hpp"
#include "vfs.hpp"
#include "path.hpp"

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

extern "C" 
{
  VFS&	vfs = VFS::Get();
  static int f_getattr(const char *path, struct stat *stbuf)
  {
    Node* node;
    memset(stbuf, 0, sizeof(struct stat));

    node = vfs.GetNode(path);
    if (!node)
      return (-ENOENT);
  
    if (node->hasChildren())
    {
      stbuf->st_mode = S_IFDIR | 0755;
      stbuf->st_nlink = 2 + node->childCount();
    }
    else
    {
      stbuf->st_mode = S_IFREG | 0444;
      stbuf->st_nlink = 1;
      stbuf->st_size = node->size();
    }

    return (0);
  }

  static int f_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
  {
    Node *node;

    node = vfs.GetNode(path);
    if (!node)
      return (-ENOENT);
    if (node->hasChildren())
    {
      filler(buf, ".", NULL, 0);
      filler(buf, "..", NULL, 0);
      std::vector<Node*>childs = node->children();
      std::vector<Node*>::iterator i = childs.begin();
      for (; i != childs.end(); i++)
      {
        filler(buf, (*i)->name().c_str(), NULL, 0);
      }
    }
    else
      return (-ENOENT);

   return (0);
  }

  static int f_open(const char *path, struct fuse_file_info *fi)
  {
    Node *node;

    node = vfs.GetNode(path);
    if (!node)
      return (-ENOENT);
    if (!node->size())
      return (-ENOENT);
    if ((fi->flags & 3) != O_RDONLY)
      return (-EACCES);

    return (0);
  }

  static int f_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
  {
    Node 	*node;
    VFile 	*file;
    int		n;

    node = vfs.GetNode(path);
    if (!node)
      return (0);
    try
    {
      file = node->open();
      file->seek(offset);
      n = file->read(buf, size);
      file->close();
    }
    catch (vfsError e)
    {
      return (0);
    }
    return n;
  }

  struct f_oper : fuse_operations  
  {
    f_oper() 
    {
      getattr = f_getattr;
      open = f_open;
      readdir = f_readdir;
      read = f_read;
    }
  };
  static struct f_oper f_opers;
}


void	fuse::__addArgument(std::string arg) throw (std::string)
{
  if(fuse_opt_add_arg(&this->__arguments, arg.c_str()) != 0)
    throw(std::string("Errror while adding argument"));
}


void	fuse::__cleanContext()
{
  if (this->__handle != NULL)
    fuse_destroy(this->__handle);
  fuse_opt_free_args(&this->__arguments);
}


void	fuse::start(std::map<std::string, Variant_p > args)
{
  std::map<std::string, Variant_p >::iterator	it;
  Path			*tpath;
  std::string		mntopt;
  
  if ((it = args.find("path")) != args.end())
  {
    tpath = it->second->value<Path*>();
    this->__mnt = tpath->path;
  }
  else
  {
    this->res["error"] = new Variant(std::string("Path not provided"));
    return;
  }
  if ((it = args.find("mount_options")) != args.end())
    mntopt = it->second->value<std::string>();
  try
  {
    this->__addArgument("-s");
    this->__addArgument("-o");
    if (! mntopt.empty())
      this->__addArgument(mntopt);
    else
      this->__addArgument("allow_other");
  }
  catch (std::string err)
  {
    this->res["error"] = new Variant(err);
    return;
  }
  if ((this->__channel = fuse_mount(this->__mnt.c_str(), &this->__arguments)) == NULL)
  {
    this->res["error"] = new Variant(std::string("Error while creating fuse channel"));
    this->__cleanContext();
    return;
  }
  if ((this->__handle = fuse_new(this->__channel, &this->__arguments, &f_opers, sizeof(struct fuse_operations), this->__handle)) == NULL)
  {
    this->res["error"] = new Variant(std::string("Error while creating handle"));
    this->__cleanContext();
    return;
  }
  if (fuse_loop(this->__handle) != 0)
  {
    this->res["error"] = new Variant(std::string("Error while running fuse loop"));
    this->__cleanContext();
    return;
  }
  this->__cleanContext();
  return;
}

fuse::fuse() : mfso("fuse"), __channel(NULL), __handle(NULL)
{
  this->__arguments.argc = 0;
  this->__arguments.argv = NULL;
  this->__arguments.allocated = 0;
}

fuse::~fuse()
{
  fuse_unmount(this->__mnt.c_str(), this->__channel);
}
