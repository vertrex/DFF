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

#ifndef __HFSP_HPP__
#define __HFSP_HPP__

#include <map>

#include "variant.hpp"
#include "mfso.hpp"
#include "node.hpp"

#include "specialfile.hpp"
#include "volume/volume.hpp"

using namespace DFF;

class HfsRootNode: public DFF::Node
{
private:
  VolumeInformation*	__vinfo;
public:
  HfsRootNode(std::string name, uint64_t size, Node* parent, fso* fsobj);
  HfsRootNode();
  ~HfsRootNode();
  void		setVolumeInformation(VolumeInformation* vinfo);
  Attributes	_attributes();
};


class Hfsp : public DFF::mfso
{
private:
  Node*			__parent;
  VirtualNode*		__virtualParent;
  HfsRootNode*		__root;
  uint64_t		__vheaderOffset;
  VolumeFactory*	__volumeFactory;
  bool			__mountWrapper;
  void			__setContext(std::map<std::string, Variant_p > args) throw (std::string);
  void			__process() throw (std::string);
  void			__createHfsHandler(Node* origin, VolumeInformation* vinfo) throw (std::string);
  void			__createHfspHandler(Node* origin, VolumeInformation* vinfo) throw (std::string);
  void		        __createWrappedHfspHandler(Node* origin, VolumeInformation* vinfo) throw (std::string);
public:
  Hfsp();
  ~Hfsp();
  virtual void	start(std::map<std::string, Variant_p > args);
};


#endif
