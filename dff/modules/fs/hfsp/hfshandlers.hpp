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

#ifndef __HFSHANDLERS_HPP__
#define __HFSHANDLERS_HPP__

#include <map>

#include "variant.hpp"
#include "mfso.hpp"
#include "node.hpp"

#include "specialfile.hpp"
#include "volume/volume.hpp"
#include "extents/extentstree.hpp"
#include "extents/fork.hpp"
#include "allocation.hpp"
#include "catalog/catalogtree.hpp"

class SpecialFile;
class CatalogTree;
class AllocationFile;
class ExtentsTree;
class VolumeInformation;

class FileSystemHandler
{
protected:
  uint64_t	_offset;
  Node*		_mountPoint;
  Node*		_origin;
  fso*		_fsobj;
public:
  FileSystemHandler();
  virtual ~FileSystemHandler() {}
  void					setOrigin(Node* origin) throw (std::string);
  void					setOrigin(Node* origin, uint64_t offset) throw (std::string);
  void					setMountPoint(Node* parent) throw (std::string);
  void					setFsObject(fso* fsobj) throw (std::string);
  uint64_t				offset();
  Node*					origin();
  Node*					mountPoint();
  fso*					fsObject();
  void					setStateInformation(std::string information);
  virtual uint64_t			blockSize() = 0;
  virtual std::list<uint64_t>		detetedEntries() = 0;
  virtual std::list<uint64_t>		orphanEntries() = 0;
  virtual std::list<Node*>		listFiles(uint64_t uid) = 0;
  virtual std::list<std::string>	listNames(uint64_t uid) = 0;
  virtual Node*				unallocatedSpace() = 0;
  virtual Node*				freeSpace() = 0;
  virtual Node*				slackSpace() = 0;
  virtual void				report() = 0;
};


class HfsFileSystemHandler : public FileSystemHandler
{
protected:
  SpecialFile*		_extentsTreeNode;
  SpecialFile*		_catalogNode;
  VolumeInformation*	_volumeInformation;
  ExtentsTree*		_extentsTree;
  CatalogTree*		_catalogTree;
  
  void			_createEtree() throw (std::string);
  void			_createCatalog() throw (std::string);
public:
  HfsFileSystemHandler();
  virtual ~HfsFileSystemHandler();
  virtual void		process(Node* origin, uint64_t offset, fso* fsobj)  throw (std::string) = 0;
  virtual uint64_t	blockSize();
  void			setVolumeInformation(VolumeInformation* volume) throw (std::string);
  VolumeInformation*	volumeInformation();
  ExtentsTree*		extentsTree();
  Node*			catalogNode();
  CatalogTree*		catalogTree();
};


class HfsHandler : public HfsFileSystemHandler
{
public:
  HfsHandler();
  ~HfsHandler();
  virtual void				process(Node* origin, uint64_t offset, fso* fsobj) throw (std::string);
  virtual std::list<uint64_t>		detetedEntries();
  virtual std::list<uint64_t>		orphanEntries();
  virtual std::list<Node*>		listFiles(uint64_t uid);
  virtual std::list<std::string>	listNames(uint64_t uid);
  virtual Node*				unallocatedSpace();
  virtual Node*				freeSpace();
  virtual Node*				slackSpace();
  virtual void				report();
};


class HfspHandler : public HfsFileSystemHandler
{
private:
  SpecialFile*		__allocationNode;
  AllocationFile*	__allocationFile;
  void			__createAllocation() throw (std::string);
public:
  HfspHandler();
  ~HfspHandler();
  virtual void				process(Node* origin, uint64_t offset, fso* fsobj) throw (std::string);
  virtual std::list<uint64_t>		detetedEntries();
  virtual std::list<uint64_t>		orphanEntries();
  virtual std::list<Node*>		listFiles(uint64_t uid);
  virtual std::list<std::string>	listNames(uint64_t uid);
  virtual Node*				unallocatedSpace();
  virtual Node*				freeSpace();
  virtual Node*				slackSpace();
  virtual void				report();
};


#endif
