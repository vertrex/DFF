/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2014 ArxSys
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
 *  Frederic Baguelin <fba@digital-forensic.org>
 */

#ifndef __HFSP_EXTENTS_FILE_HPP__
#define __HFSP_EXTENTS_FILE_HPP__

#include <stdint.h>

#include "export.hpp"
#include "node.hpp"
#include "filemapping.hpp"

#include "endian.hpp"
#include "extents/fork.hpp"
#include "extents/extent.hpp"

using namespace DFF;

class VirtualNode : public Node
{
private:
  Node*			__origin;
  uint64_t		__voffset;
public:
  VirtualNode(fso* fsobj);
  ~VirtualNode();
  void			setContext(Node* origin, uint64_t voffset) throw (std::string);
  void			setContext(Node* origin, uint64_t voffset, uint64_t size) throw (std::string);
  virtual void		fileMapping(FileMapping* fm);
  virtual Attributes	_attributes(void);
};


class SpecialFile : public Node
{
private:
  class ForkData*	__fork;
  Node*			__origin;
public:
  SpecialFile(std::string name, Node* parent, fso* fsobj);
  ~SpecialFile();
  void			setContext(ForkData* fork, Node* origin);
  virtual void		fileMapping(FileMapping* fm);
  virtual Attributes	_attributes(void);
};

#endif
