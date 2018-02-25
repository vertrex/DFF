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

#ifndef __VMWARE_HPP__
#define __VMWARE_HPP__

#include <list>

#include "vmdk.hpp"
#include "vmnode.hpp"
#include "mfso.hpp"

class Link;

class	VMware : public DFF::mfso
{
public:
  VMware();
  ~VMware();

  virtual void	        start(std::map<std::string, Variant_p  > args);
  //  void                  setResults();
  
  int			detectDiskDescriptor(Node *vmdk);
  int			createLinks(Node *vmdkroot, std::string pcid);

  std::list<Link*>	getLinksFromCID(std::string cid);

  Node  		*getParentVMDK(std::string parentFileName);

  int			createNodes();

  // ==============================
  //  string		getExtentName(string str);

  // Disk Descriptor operations (class?)
  //  void			readDiskDescriptor(VFile *vmdk, unsigned int offset, unsigned int size);
  //  void			parseLineDiskDescriptor();

  //  char*			getLinesDiskDescriptor(char* ptr);
  // ==========================================



  //string			cleanExtentString(string str);

  // XXXX TODO
  //Sparse Extents ****
  //Use template and default VMDK header if not present *** (opt)
  //getFreeGrains / sectors **
  //Use redondant  **
  //ESX **
  //Check if data in free grains / sectors * (opt)
  //Bypass Grain Directory if not present *

  // Create a tree for snapshots

  // Test on different versions 4 5 6 7
  // test with broken vmdk (DC3)
  // test with classical FS (Ext, NTFS, FAT?)


private:
  //Node*			_node;
  Node			*_vmdkroot;
  Node			*_rootdir;
  Node*			_root;
  Node*			_baseroot;
  Node*			_snaproot;

  std::list<Node*>	_baseNodes;

  //map<string, diskDescriptor*>	_links;
  std::map<std::string, Link*>	_links;
  

  // ==========================================
  //  Node*			_storageVolume;
  //  dff_ui64		_storageVolumeSize;
  // ==========================================

  //  vector<Node*>		_nodeExtents;
  VFile*	        _vfile;

  // In argument, try to use default values to reconstruct header and access GD
  //  bool			_forceVmdkReconstruction;
  // Header
  //  SparseExtentHeader	_backupMonoHeader;
  //  SparseExtentHeader	_backupTwoHeader;


  //===============================================
  // Text Disk Description 
  //  char*			_descData;
  //  list<char*>		_descLines;
  //  list<string>		_descExtents;
  //  map<string, string>	_descMap;
  // ==========================================

};

#endif
