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

#include "libbde.h"

#include "libbfio_wrapper.hpp"

#include "bitlocker.hpp"
#include "bitlockernode.hpp"
#include "path.hpp"

BitLocker::BitLocker() : fso("BitLocker"), __parent(NULL), __fdm(new FdManager()), __volume(NULL), __volumeNode(NULL)
{
  mutex_init(&__io_mutex);
}

BitLocker::~BitLocker()
{
  libbde_error_t*      bdeError = NULL;

  libbde_volume_close(this->__volume, &bdeError);
  libbde_volume_free(&this->__volume, &bdeError);
  delete __fdm;

  mutex_destroy(&__io_mutex);
}

void BitLocker::start(std::map<std::string, Variant_p > args)
{
  if (args.find("parent") != args.end())
    this->__parent = args["parent"]->value<Node* >();


  this->setEncryptionKey(args);
  this->openVolume();
  this->__volumeNode = new BitLockerVolumeNode(this->__volume, this->__parent, this);
}


void BitLocker::setEncryptionKey(std::map<std::string, Variant_p>& args)
{
  libbde_error_t*       bdeError   = NULL;

  if (libbde_volume_initialize(&this->__volume, &bdeError) != 1)
    throw vfsError(std::string("Can't initialize bde volume"));

  std::string   error = "";

  if (args.find("startup-key-node") != args.end())
  {
    libbfio_handle_t* ioHandle = NULL;
    libbfio_error_t*  ioError= NULL;

    Node* node = args["startup-key-node"]->value<Node*>();
    if (dff_libbfio_file_initialize(&ioHandle, &ioError, node) != 1)
      error += std::string("DFF bfio can't open startup key as node\n");
    if (libbde_volume_read_startup_key_file_io_handle(this->__volume, ioHandle, &bdeError) != 1)
      error += std::string("Startup key node is invalid.\n");
  }  
  if (args.find("startup-key-file") != args.end())
  {
    std::string filePath = args["startup-key-file"]->value<Path*>()->path;
    if (libbde_volume_read_startup_key(this->__volume, filePath.c_str(), &bdeError) != 1)
      error += std::string("Startup key file is invalid.\n");
  }  
  if (args.find("recovery-password") != args.end())
  {
    std::string password = args["recovery-password"]->value<std::string>();
    if (libbde_volume_set_utf8_recovery_password(this->__volume, (const uint8_t*)password.c_str(), password.size(), &bdeError) != 1)
      error += std::string("Recovery password is invalid.\n");
  }
  if (args.find("passphrase") != args.end())
  {
    std::string password = args["passphrase"]->value<std::string>();
    if (libbde_volume_set_utf8_password(this->__volume, (const uint8_t*)password.c_str(), password.size(), &bdeError) != 1)
      error += std::string("Passphrase is invalid.\n");
  }
  if (args.find("volume-keys") != args.end())
  {
    std::string keys = args["volume-keys"]->value<std::string>();
    size_t pos = keys.find(":");
    if (pos == std::string::npos) 
      error += std::string("Keys format is invalid.\n");

    std::string ekey = keys.substr(0, pos);
    std::string tkey = keys.substr(pos + 1);
    if (libbde_volume_set_keys(this->__volume, (const uint8_t*)ekey.c_str(), ekey.size(), (const uint8_t*)tkey.c_str(), tkey.size(), &bdeError) != 1)
      error += std::string("Keys is invalid.\n");
  }

  if (libbde_volume_is_locked(this->__volume, &bdeError) != 1)
    throw vfsError(error);
}

void BitLocker::openVolume(void)
{
  libbfio_handle_t*    ioHandle   = NULL;
  libbfio_error_t*     ioError    = NULL; 
  libbde_error_t*      bdeError   = NULL;
  int                  result     = -1;

  if (dff_libbfio_file_initialize(&ioHandle, &ioError, this->__parent) != 1)
    throw vfsError(std::string("Can't initialize libbfio wrapper for dff"));
  if ((result = libbde_volume_open_file_io_handle(this->__volume, ioHandle, LIBBDE_OPEN_READ, &bdeError)) == 0)
    throw vfsError(std::string("Can't read keys"));
  else if (result == -1)
    throw vfsError(std::string("Can't open volume"));
  if (libbde_check_volume_signature_file_io_handle(ioHandle, &bdeError) != 1)
    throw vfsError(std::string("Can't find bitlocker signature"));
}


int BitLocker::vopen(Node *node)
{
  fdinfo* fi = new fdinfo();
  fi->node = node;
  fi->offset = 0;
  return (this->__fdm->push(fi));
}

int BitLocker::vread(int fd, void *buff, unsigned int size)
{
  fdinfo*       fi;
  int           res = 0;

  try
  {
    fi = this->__fdm->get(fd);
  }
  catch (...)
  {
    return (0);
  }

  mutex_lock(&this->__io_mutex);
  libbde_error_t* error = NULL;
  res = libbde_volume_read_buffer_at_offset(this->__volume, buff, size, fi->offset, &error);
  if (res > 0)
    fi->offset += res;
  mutex_unlock(&this->__io_mutex);

  if (res < 0)
    return (0);
  return (res);
}

int BitLocker::vclose(int fd)
{
  this->__fdm->remove(fd);
  return (0);
}

uint64_t BitLocker::vseek(int fd, uint64_t offset, int whence)
{
  Node*	  node;
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

uint64_t	BitLocker::vtell(int32_t fd)
{
  fdinfo*		fi;

  try 
  {
    fi = this->__fdm->get(fd);
    return (fi->offset);
  }
  catch (...)
  {
    return (-1);
  }
}

unsigned int BitLocker::status(void)
{
  return (0);
}
