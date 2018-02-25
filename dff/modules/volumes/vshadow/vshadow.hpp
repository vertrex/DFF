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

#ifndef __VSHADOW_HPP__
#define __VSHADOW_HPP__

#include "vshadow_common.hpp"
#include "libbfio_wrapper.hpp"

using namespace DFF;

class VshadowNode : public Node
{
private:
  int	__idx;
public:
  VshadowNode(std::string name, uint64_t size, Node* parent, fso* fsobj);
  ~VshadowNode();
  void		setIndex(int idx);
  int		index();
  Attributes	_attributes();
};


class Vshadow : public DFF::mfso
{
private:
  Node*			__parent;
  Node*			__root;
  uint64_t		__volume_offset;
  uint64_t		__volume_size;
  libvshadow_volume_t*	__volume;
  libbfio_handle_t*	__bfio_handle;
  libvshadow_store_t**	__input_stores;
  int			__stores_count;
  void			__setContext() throw (vfsError);
  void			__freeContext() {}
  void			__createNodes();
  mutex_def(__mutex);

public:
  Vshadow();
  ~Vshadow();
  int32_t	vread(int fd, void *buff, unsigned int size);
  uint64_t	vseek(int fd, uint64_t offset, int whence);
  virtual void	start(std::map<std::string, Variant_p >);
};

#endif
