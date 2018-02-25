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
 *  Jeremy MOUNIER <fba@digital-forensic.org>
 */

#ifndef __VMNODE_HPP__
#define __VMNODE_HPP__

#include "node.hpp"
#include "vmware.hpp"
#include "vmdk.hpp"
#include "link.hpp"

using namespace DFF;

class VMNode: public Node
{

public:
  VMNode(std::string name, uint64_t size, Node* parent, class VMware *vm, Link *lnk);
  ~VMNode();
  virtual void	fileMapping(FileMapping *fmap);

private:

  class VMware* _vm;

  unsigned int* mapGT(uint64_t GTOffset, Extent* ext);
  uint64_t	getGTOffset(uint64_t GDEOffset, Extent* ext);
  int		mapGTGrains(uint64_t currentGDE, uint32_t curextent, FileMapping *fm, uint64_t *voffset, uint64_t *vextoffset, uint64_t GTEntries);

  Link		*getDeltaLink(uint64_t currentGDE, uint32_t currentGTE, uint32_t curextent);
  uint32_t	readGTEntry(uint64_t GTEOffset, uint32_t currentGTE, Extent *ext);
  Link		*getBaseLink();

  Link		*_baseLink;
  Link		*_lnk;
  std::string	_cid;
  std::list<Link*>	_links;

};

#endif
