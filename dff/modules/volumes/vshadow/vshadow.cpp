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
 *  Frederic Baguelin <fba@digital-forensic.org>
 */

#include <stdlib.h>
#include <sstream>
#include "vshadow.hpp"
#include "fdmanager.hpp"

Vshadow::Vshadow() : mfso("vshadow")
{
  this->__parent = NULL;
  this->__root = NULL;
  this->__volume_offset = 0;
  this->__volume_size = 0;
  this->__volume = NULL;
  this->__bfio_handle = NULL;
  this->__stores_count = 0;
  this->__input_stores = NULL;
  mutex_init(&this->__mutex);
}

Vshadow::~Vshadow()
{
  mutex_destroy(&this->__mutex);
}

void		Vshadow::start(std::map<std::string, Variant_p > args)
{
  std::string	path;
  
  if (args.find("file") != args.end())
    this->__parent = args["file"]->value<Node* >();
  else
    throw envError("vshadow needs a file argument.");
  if (args.find("offset") != args.end())
    this->__volume_offset = args["offset"]->value<uint64_t>();
  try
    {
      this->__setContext();
      this->__createNodes();
      this->stateinfo = std::string("Volume shadow snapshots mount successfully");
      this->res["Result"] = Variant_p(new Variant(std::string("Volume shadow snapshots mount successfully")));
    }
  catch (vfsError err)
    {
      res["Result"] = Variant_p(new Variant(std::string("Volume shadow snapshots not mount")));
      std::cout << err.error << std::endl;
    }
}


int32_t		Vshadow::vread(int fd, void *buff, unsigned int size)
{
  fdinfo*		fi;
  VshadowNode*		node;
  libvshadow_error_t*	error;
  int32_t		bread;


  error = NULL;
  try
    {
      fi = this->__fdmanager->get(fd);
    }
  catch (vfsError e)
    {
      return (0); 
    }
  node = dynamic_cast<VshadowNode*>(fi->node);
  if (node != NULL)
    {
      mutex_lock(&this->__mutex);
      if (libvshadow_store_seek_offset(this->__input_stores[node->index()], fi->offset, 0, &error) == -1)
       	{
	  mutex_unlock(&this->__mutex);
       	  return 0;
       	}
      if ((bread = libvshadow_store_read_buffer(this->__input_stores[node->index()], (uint8_t*)buff, size, &error)) == -1)
	{
	  mutex_unlock(&this->__mutex);
	  return 0;
	}
      else
	{
	  mutex_unlock(&this->__mutex);
	  fi->offset += bread;
	  return bread;
	}
    }
  return -1;
}


uint64_t	Vshadow::vseek(int32_t fd, uint64_t offset, int32_t whence)
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
      if (offset > this->__volume_size)
	return ((uint64_t)-1);
      else
	fi->offset = offset;
    }
  else if (whence == 1)
    {
      if ((fi->offset + offset) > this->__volume_size)
	return ((uint64_t)-1);
      else
	fi->offset += offset;
    }
  else if (whence == 2)
    fi->offset = this->__volume_size;
  return (fi->offset);
}


void		Vshadow::__setContext() throw (vfsError)
{
  libvshadow_error_t*	error;
  int			result;
  int			i;

 
  error = NULL;
  if (dff_libbfio_file_initialize(&this->__bfio_handle, &error, this->__parent) != 1)
    throw vfsError(std::string("Unable to initialize input file IO handle."));
  if (libvshadow_volume_initialize(&this->__volume, &error) != 1)
    throw vfsError(std::string("Unable to initialize input volume."));
  result = libvshadow_check_volume_signature_file_io_handle(this->__bfio_handle, &error);
  if (result != 0)
    {
      if (libvshadow_volume_open_file_io_handle(this->__volume, this->__bfio_handle, LIBVSHADOW_OPEN_READ, &error) != 1)
	throw vfsError(std::string("Unable to open input volume."));
      if (libvshadow_volume_get_number_of_stores(this->__volume, &this->__stores_count, &error)  != 1)
	throw vfsError(std::string("Unable to retrieve number of stores."));
      if (this->__stores_count < 0 || this->__stores_count > 255)
	throw vfsError(std::string("Unsupported number of stores."));
      if ((this->__input_stores = (libvshadow_store_t**) malloc(sizeof(libvshadow_store_t *) * this->__stores_count)) == NULL)
	throw vfsError(std::string("Unable to create input stores."));
      for (i = 0; i < this->__stores_count; i++)
	this->__input_stores[i] = NULL;
      if (libvshadow_volume_get_size(this->__volume, &this->__volume_size, &error) != 1)
	throw vfsError(std::string("unable to retrieve size from input volume."));
    }
  else
    throw vfsError(std::string("Unable to determine if volume has a VSS signature."));
}


void	Vshadow::__createNodes()
{
  std::stringstream     ostr;
  int			idx;
  VshadowNode*		node;
  libvshadow_error_t*	error;

  this->__root = new Node("Volume Shadow Copy", 0, NULL, this);
  for (idx = 0; idx <= this->__stores_count-1; idx++)
    {
      if (libvshadow_volume_get_store(this->__volume, idx, &(this->__input_stores[idx]), &error) != 1)
	{
	  std::cout << "unable to retrieve input store: " << idx << " from input volume." << std::endl;
	}
      ostr << "vss" << idx+1;
      node = new VshadowNode(ostr.str(), this->__volume_size, this->__root, this);
      node->setIndex(idx);
      ostr.str("");
    }
  this->registerTree(this->__parent, this->__root);
}


VshadowNode::VshadowNode(std::string name, uint64_t size, Node* parent, fso* fsobj) : Node(name, size, parent, fsobj)
{
  this->__idx = 0;
}

VshadowNode::~VshadowNode()
{
}

void		VshadowNode::setIndex(int idx)
{
  this->__idx = idx;
}

int		VshadowNode::index()
{
  return this->__idx;
}

Attributes	VshadowNode::_attributes(void)
{
  Attributes	ret;

  return ret;
}
