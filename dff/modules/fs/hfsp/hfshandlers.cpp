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


#include "hfshandlers.hpp"


FileSystemHandler::FileSystemHandler() : _offset(0), _mountPoint(NULL), _origin(NULL), _fsobj(NULL)
{
}


void				FileSystemHandler::setOrigin(Node* origin) throw (std::string)
{
  this->setOrigin(origin, 0);
}


void				FileSystemHandler::setOrigin(Node* origin, uint64_t offset) throw (std::string)
{
  if (origin != NULL)
    this->_origin = origin;
  else
    throw std::string("Provided origin does not exist");
  if (offset < this->_origin->size())
    this->_offset = offset;
  else
    throw std::string("Provided offset is greater than the size of the provided origin node");
}


void				FileSystemHandler::setMountPoint(Node* mountPoint) throw (std::string)
{
  if (mountPoint != NULL)
    this->_mountPoint = mountPoint;
  else
    throw std::string("Provided mount point does not exist");  
}


void				FileSystemHandler::setFsObject(fso* fsobj) throw (std::string)
{
  if (fsobj != NULL)
    this->_fsobj = fsobj;
  else
    throw std::string("Provided mount point does not exist");  
}


uint64_t			FileSystemHandler::offset()
{
  return this->_offset;
}


Node*				FileSystemHandler::origin()
{
  return this->_origin;
}


Node*				FileSystemHandler::mountPoint()
{
  return this->_mountPoint;
}


fso*				FileSystemHandler::fsObject()
{
  return this->_fsobj;
}


void				FileSystemHandler::setStateInformation(std::string information)
{
  this->_fsobj->stateinfo = information;
}


HfsFileSystemHandler::HfsFileSystemHandler() : _extentsTreeNode(NULL), _catalogNode(NULL), _volumeInformation(NULL), _extentsTree(NULL), _catalogTree(NULL)
{
}


HfsFileSystemHandler::~HfsFileSystemHandler()
{
  delete this->_extentsTreeNode;
  delete this->_catalogNode;
  delete this->_extentsTree;
  delete this->_catalogTree;
}


uint64_t	HfsFileSystemHandler::blockSize()
{
  if (this->_volumeInformation != NULL)
    return (uint64_t)this->_volumeInformation->blockSize();
  else
    return 0;
}


void		HfsFileSystemHandler::setVolumeInformation(VolumeInformation* vinfo)  throw (std::string)
{
  if (vinfo != NULL)
    this->_volumeInformation = vinfo;
  else
    throw std::string("Provided volume information does not exist");
}


VolumeInformation*	HfsFileSystemHandler::volumeInformation()
{
  return this->_volumeInformation;
}


ExtentsTree*		HfsFileSystemHandler::extentsTree()
{
  return this->_extentsTree;
}


Node*			HfsFileSystemHandler::catalogNode()
{
  return this->_catalogNode;
}


CatalogTree*		HfsFileSystemHandler::catalogTree()
{
  return this->_catalogTree;
}


void		HfsFileSystemHandler::_createEtree() throw (std::string)
{
  ForkData*	fork;
  
  this->_extentsTreeNode = new SpecialFile("$ExtentsFile", this->_mountPoint, this->_fsobj);
  fork = new ForkData(3, this->_volumeInformation->blockSize());
  fork->process(this->_volumeInformation->overflowExtents(), this->_volumeInformation->overflowSize(), ForkData::Data);
  this->_extentsTreeNode->setContext(fork, this->_origin);
  if (this->_volumeInformation->type() == HfsVolume)
    this->_extentsTree = new ExtentsTree(0);
  else
    this->_extentsTree = new ExtentsTree(1);
  this->_extentsTree->setHandler(this);
  this->_extentsTree->process(this->_extentsTreeNode, 0);
}


void		HfsFileSystemHandler::_createCatalog() throw (std::string)
{
  ForkData*	fork;
  
  this->_catalogNode = new SpecialFile("$CatalogFile", this->_mountPoint, this->_fsobj);
  fork = new ForkData(4, this->_extentsTree);
  fork->process(this->_volumeInformation->catalogExtents(), this->_volumeInformation->catalogSize(), ForkData::Data);
  this->_catalogNode->setContext(fork, this->_origin);
  if (this->_volumeInformation->type() == HfsVolume)
    this->_catalogTree = new CatalogTree(0);
  else
    this->_catalogTree = new CatalogTree(1);
  this->_catalogTree->setHandler(this);
  this->_catalogTree->process(this->_catalogNode, 0);
}
