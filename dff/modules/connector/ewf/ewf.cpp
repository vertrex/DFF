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
#include <string>
#include <iostream>
#include <stdlib.h>

#include "ewf.hpp"
#include "ewfnode.hpp"

#include "vfs.hpp"
#include "path.hpp"
#include "fdmanager.hpp"
#include "node.hpp"

ewf::ewf() : fso("ewf"), parent(NULL), __fdm(new FdManager), volumeSize(0), files(NULL), nfiles(0), __ewf_error(NULL), ewf_ghandle(NULL)
{
  mutex_init(&this->__io_mutex);
}

ewf::~ewf()
{
  delete this->__fdm;
  this->__cleanup();
  mutex_destroy(&this->__io_mutex);
}

void	ewf::__cleanup()
{
  if (this->__ewf_error != NULL)
  {
    libewf_error_free(&this->__ewf_error);
    this->__ewf_error = NULL;
  }
  if (this->ewf_ghandle != NULL)
  {
    libewf_handle_close(this->ewf_ghandle, NULL);
    libewf_handle_free(&this->ewf_ghandle, NULL);
    this->ewf_ghandle = NULL;
  }
  if (this->files != NULL)
  {
    this->files = NULL;
    free(this->files);
  }
}

void	ewf::__checkSignature(std::list< Variant_p > vl) throw (std::string)
{
  std::list<Variant_p >::iterator	vpath;
  std::string				err;
  char*					cerr;

#ifdef WIN32
  this->files = (wchar_t**)malloc(sizeof(wchar_t*) * (vl.size() + 1));
#else
  this->files = (char**)malloc(sizeof(char*) * (vl.size() + 1));
#endif
  this->nfiles = 0;
  for (vpath = vl.begin(); vpath != vl.end(); vpath++)
    {
      std::string path = (*vpath)->value<Path* >()->path;
#ifdef WIN32
      int length = MultiByteToWideChar(CP_UTF8, 0, path.data(), path.length(), NULL, 0);
      std::wstring utf16path;
      utf16path.resize(length);
      MultiByteToWideChar(CP_UTF8, 0, path.data(), path.length(), &utf16path[0], utf16path.length());
      if (libewf_check_file_signature_wide(utf16path.c_str(), &this->__ewf_error) == 1)
	{
	  this->files[nfiles] = wcsdup((wchar_t*)utf16path.c_str());
#else
      if (libewf_check_file_signature(path.c_str(), &this->__ewf_error) == 1)
	{
	  this->files[nfiles] = strdup((char*)path.c_str());
#endif
	  this->nfiles++;
	}
      else
	{
	  if (this->__ewf_error != NULL)
	    {
	      cerr = new char[512];
	      libewf_error_backtrace_sprint(this->__ewf_error, cerr, 511);
	      err = std::string(cerr);
	    }
	  else
	    {
	      std::ostringstream error;
	      error << "file " << path << " is not a ewf file." << std::endl;
	      err = error.str();
	    }
	  throw (err);
	}
    }
  this->files[nfiles] = NULL;
  return ;
}

void	ewf::__initHandle(libewf_handle_t** handle, libewf_error_t** error) throw (std::string)
{
  std::string	err;
  char*		cerr;

  if (libewf_handle_initialize(handle, error) != 1)
  {
    if (error != NULL)
    {
      cerr = new char[512];
      libewf_error_backtrace_sprint(*error, cerr, 511);
      err = std::string(cerr);
      delete[] cerr;
    }
    else
      err = std::string("Ewf: Unable to initialize handle");
    throw (err);
  }
  return;
}

void	ewf::__openHandle(libewf_handle_t* handle, libewf_error_t** error) throw (std::string)
{
  std::string				err;
  char*					cerr;

#ifdef WIN32
  if (libewf_handle_open_wide(handle, this->files, this->nfiles, LIBEWF_OPEN_READ, error) != 1)
#else
  if (libewf_handle_open(handle, this->files, this->nfiles, LIBEWF_OPEN_READ, error) != 1)
#endif
  {
    if (error != NULL)
    {
      cerr = new char[512];
      libewf_error_backtrace_sprint(*error, cerr, 511);
      err = std::string(cerr);
    }
    else
      err = std::string("Can't open EWF files");
    throw (err);
  }
  return;
}


void	ewf::__getVolumeName()
{
  uint8_t*	value;
  size_t	val_size;
  std::string	volume;
 
  if (libewf_handle_get_utf8_header_value_size(this->ewf_ghandle, (uint8_t*)"description", 11, &val_size, &this->__ewf_error) != 1)
    this->volumeName = std::string("ewf_volume");
  else
  {
    value = new uint8_t[val_size];
    if (libewf_handle_get_utf8_header_value(this->ewf_ghandle, (uint8_t*)"description", 11, value, val_size, &this->__ewf_error) == 1)
      this->volumeName = std::string((char*)value, val_size-1);
    else
      this->volumeName = std::string("ewf_volume");
    delete[] value;
  }
  return;
}

void	ewf::__getVolumeSize() throw (std::string)
{
  std::string	err;
  
  if (libewf_handle_get_media_size(this->ewf_ghandle, &this->volumeSize, &this->__ewf_error) != 1)
  {
    if (this->__ewf_error != NULL)
    {
      char*	cerr = new char[512];
      libewf_error_backtrace_sprint(this->__ewf_error, cerr, 511);
      err = std::string(cerr);
    }
    else
      err = std::string("Can't get EWF dump size.");
    throw (err);
  }
  return;
}

void ewf::start(std::map<std::string, Variant_p > args)
{
  std::list<Variant_p >	vl;
  EWFNode*		ewfNode;

  if (args.find("parent") != args.end())
    this->parent = args["parent"]->value<Node* >();
  else
    this->parent = VFS::Get().GetNode("/");
  if (args.find("files") != args.end())
    vl = args["files"]->value<std::list<Variant_p > >();
  else
    throw(envError("ewf module requires path argument"));  
  
  try
  {
    this->__initHandle(&this->ewf_ghandle, &this->__ewf_error);
    this->__checkSignature(vl);
    this->__openHandle(this->ewf_ghandle, &this->__ewf_error);
    this->__getVolumeSize();
    this->__getVolumeName();
    ewfNode = new EWFNode(this->volumeName, this->volumeSize, NULL, this, vl);
    this->registerTree(this->parent, ewfNode);
  }
  catch (std::string err)
  {
    this->__cleanup();
    this->res["error"] = Variant_p(new Variant(err));
  }
  return ;
}

int ewf::vopen(Node *node)
{
  fdinfo* fi = new fdinfo();
  fi->node = node;
  fi->offset = 0;
  return (this->__fdm->push(fi));
}

int ewf::vread(int fd, void *buff, unsigned int size)
{
  fdinfo*		fi;

  try
  {
    fi = this->__fdm->get(fd);
  }
  catch (...)
  {
    return (0);
  }
  int res = 0;
  mutex_lock(&this->__io_mutex);
  libewf_error_t* error = NULL;
  res = libewf_handle_read_random(this->ewf_ghandle, buff, size, fi->offset, &error);
  if (res > 0)
    fi->offset += res;
  mutex_unlock(&this->__io_mutex);

  if (res < 0)
    return (0);
  return (res);
}

int ewf::vclose(int fd)
{
  this->__fdm->remove(fd);
  return 0;
}

uint64_t ewf::vseek(int fd, uint64_t offset, int whence)
{
  Node*	node;
  fdinfo* fi;

  try
  {
    fi = this->__fdm->get(fd);
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
    return ((uint64_t) -1);
  }

  return ((uint64_t) -1);
}

uint64_t	ewf::vtell(int32_t fd)
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

unsigned int ewf::status(void)
{
  return (0);
}
