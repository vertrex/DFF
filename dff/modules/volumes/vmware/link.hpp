/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2013 ArxSys
 *
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
 *  MOUNIER Jeremy <jmo@digital-forensic.org>
 *
 */

#ifndef __LINK_HPP__
#define __LINK_HPP__

#include "vmdk.hpp"
#include "extent.hpp"

#include "diskDescriptor.hpp"

class	Link
{
public:
  Link(diskDescriptor	*desc, int type, Node *vmdkroot);
  ~Link();

  int			listExtents();
  //  int			readSparseHeader(extentInfo *extent);
  int			addExtent(Node *vmdk);
  bool			isBase();
  uint64_t		volumeSize();

  std::vector<Extent*>	getExtents();
  std::string		getCID();
  std::string		getPCID();


  void			setLinkStorageVolumeSize();

  //  int			createBackupHeader(int type, extentInfo *extent);

private:

  int			_type;

  uint64_t		_storageVolumeSize;

  Node			*_vmdkroot;

  diskDescriptor	*_descriptor;

  std::string		_cid;
  std::string		_pcid;

  bool			_baseLink;

  std::vector<Extent*>	_extents;

};

#endif
