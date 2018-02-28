/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2014 ArxSys
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

#include <sstream>
#include "qcow.hpp"

#include "fdmanager.hpp"

QCow::QCow() : mfso("qcow"), __parent(NULL), __root(NULL), __size(0), __qcowFile(NULL), __bfio_handle(NULL)
{
  mutex_init(&this->__mutex);
}

QCow::~QCow()
{
  mutex_destroy(&this->__mutex);
}

void      QCow::start(std::map<std::string, Variant_p > args)
{
  std::string	path;
  
  if (args.find("file") != args.end())
    this->__parent = args["file"]->value<Node* >();
  else
    throw envError("vshadow needs a file argument.");
  try
  {
    this->__createNode();
    this->stateinfo = std::string("QCow volume mounted successfully");
    this->res["Result"] = Variant_p(new Variant(std::string("QCow volume mounted successfully")));
  }
  catch (vfsError err)
  {
    res["Result"] = Variant_p(new Variant(std::string("QCow mount failed")));
  }
}


int32_t     QCow::vread(int fd, void *buff, unsigned int size)
{
  fdinfo*		fi;
  libqcow_error_t*	error = NULL;

  try
  {
    fi = this->__fdmanager->get(fd);
  }
  catch (vfsError e)
  {
    return (0); 
  }

  mutex_lock(&this->__mutex);
  uint64_t ret = libqcow_file_read_buffer_at_offset(this->__qcowFile, buff, size, fi->offset, &error);
  mutex_unlock(&this->__mutex);

  return (ret);
}


uint64_t    QCow::vseek(int32_t fd, uint64_t offset, int32_t whence)
{
  fdinfo*	fi = NULL;

  try
  {
    fi = this->__fdmanager->get(fd);
  }
  catch (...)
  {
    return ((uint64_t)-1);
  }
  if (whence == 0)
  {
    if (offset > this->__size)
      return ((uint64_t)-1);
    else
      fi->offset = offset;
  }
  else if (whence == 1)
  {
    if ((fi->offset + offset) > this->__size)
      return ((uint64_t)-1);
    else
      fi->offset += offset;
  }
  else if (whence == 2)
    fi->offset = this->__size;

  return (fi->offset);
}


void        QCow::__createNode(void) 
{
  libqcow_error_t*	error = NULL;

  if (dff_libbfio_file_initialize(&this->__bfio_handle, (libbfio_error_t**)&error, this->__parent) != 1)
    throw vfsError(std::string("Unable to initialize input file IO handle."));
  if (libqcow_file_initialize(&this->__qcowFile, &error) != 1)
    throw vfsError(std::string("Unable to initialize qcow file."));
  if (libqcow_check_file_signature_file_io_handle(this->__bfio_handle, &error) == 0)
    throw vfsError(std::string("QCow file Bad signature."));
  if (libqcow_file_open_file_io_handle(this->__qcowFile, this->__bfio_handle, libqcow_get_access_flags_read(), &error) != 1)
    throw vfsError(std::string("Unable to open input volume."));
  if (libqcow_file_get_media_size(this->__qcowFile, &this->__size, &error) != 1)
    throw vfsError(std::string("unable to retrieve size from input volume."));

  this->__root = new QCowNode("qcow", this->__size, NULL, this);
  this->registerTree(this->__parent, this->__root);
}


QCowNode::QCowNode(std::string name, uint64_t size, Node* parent, fso* fsobj) : Node(name, size, parent, fsobj)
{
}

QCowNode::~QCowNode()
{
}

Attributes	QCowNode::_attributes(void)
{
  Attributes	ret;

  return ret;
}
