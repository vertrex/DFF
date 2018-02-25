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
 *  Frederic Baguelin <fba@digital-forensic.org>
 */

#include "exceptions.hpp"

#include "hfsp.hpp"
#include "hfshandlers.hpp"


HfsRootNode::HfsRootNode(std::string name, uint64_t size, Node* parent, fso* fsobj) : Node(name, size, parent, fsobj), __vinfo(NULL)
{
}


HfsRootNode::HfsRootNode() : __vinfo(NULL)
{
}


HfsRootNode::~HfsRootNode()
{
}


void		HfsRootNode::setVolumeInformation(VolumeInformation* vinfo)
{
  this->__vinfo = vinfo;
}


Attributes	HfsRootNode::_attributes()
{
  return this->__vinfo->_attributes();
}


Hfsp::Hfsp() : mfso("hfsp"), __parent(NULL), __virtualParent(NULL), __root(NULL), __vheaderOffset(0), __volumeFactory(NULL), __mountWrapper(false)
{
}


Hfsp::~Hfsp()
{
}


void		Hfsp::start(std::map<std::string, Variant_p > args)
{
  try
    {
      this->__setContext(args);
      this->__process();
    }
  catch(std::string e)
    {
      throw (e);
    }
  catch(vfsError e)
    {
      throw (e);
    }
  catch(envError e)
    {
      throw (e);
    }
  return ;
}


void		Hfsp::__setContext(std::map<std::string, Variant_p > args) throw (std::string)
{
  std::map<std::string, Variant_p >::iterator	it;

  if ((it = args.find("file")) != args.end())
    this->__parent = it->second->value<Node*>();
  else
    throw(std::string("Hfsp module: no file provided"));
  if ((it = args.find("mount-wrapper")) != args.end())
    this->__mountWrapper = it->second->value<bool>();
  else
    this->__mountWrapper = false;
  this->__virtualParent = new VirtualNode(this);
  if ((it = args.find("vheader-offset")) != args.end())
    {
      this->__vheaderOffset = it->second->value<uint64_t>();
      // XXX better solution is to provide a dedicated mapper which
      // automatically creates missing bytes with sparse chunk.
      if (this->__vheaderOffset >= 1024)
	this->__vheaderOffset -= 1024;
      else
	throw(std::string("Hfsp module: Volume header should be at least 1024"));
    }
  else
    this->__vheaderOffset = 0;
  this->__volumeFactory = new VolumeFactory();
  this->__virtualParent->setContext(this->__parent, this->__vheaderOffset);
  return;
}


void			Hfsp::__createHfspHandler(Node* origin, VolumeInformation* vinfo)  throw (std::string)
{
  VolumeInformation*	volume;
  VolumeHeader*		vheader;
  HfsFileSystemHandler*	hfshandler;

  if (vinfo == NULL)
    volume = this->__volumeFactory->createVolumeInformation(origin, this);
  else
    volume = vinfo;
  if ((vheader = dynamic_cast<VolumeHeader* >(volume)) == NULL)
    throw std::string("Cannot get Volume Header on this volume");
  this->res["Volume Header"] = new Variant(vheader->_attributes());
  hfshandler = new HfspHandler();
  hfshandler->setOrigin(origin);
  hfshandler->setVolumeInformation(volume);
  if (vheader->isHfsxVolume())
    this->__root = new HfsRootNode("HFSX", 0, NULL, this);
  else
    this->__root = new HfsRootNode("HFSP", 0, NULL, this);
  this->__root->setVolumeInformation(volume);
  hfshandler->setMountPoint(this->__root);
  hfshandler->process(origin, 0, this);
  this->registerTree(this->__parent, this->__root);
}


void			Hfsp::__createWrappedHfspHandler(Node* origin, VolumeInformation* vinfo)  throw (std::string)
{
  uint64_t		volumesize;
  uint64_t		startoffset;
  VolumeInformation*	volume;
  MasterDirectoryBlock*	mdb;
  VirtualNode*		virtualParent;

  if (vinfo == NULL)
    volume = this->__volumeFactory->createVolumeInformation(origin, this);
  else
    volume = vinfo;
  if ((mdb = dynamic_cast<MasterDirectoryBlock* >(volume)) == NULL)
    throw std::string("Cannot get Master Directory Block on this volume");
  virtualParent = new VirtualNode(this);
  this->res["Master Directory Block"] = new Variant(mdb->_attributes());
  volumesize = (uint64_t)mdb->embedBlockCount() * (uint64_t)volume->blockSize();
  startoffset = (uint64_t)mdb->embedStartBlock() * (uint64_t)volume->blockSize() + (uint64_t)mdb->firstAllocationBlock() * 512;
  virtualParent->setContext(this->__virtualParent, startoffset, volumesize);
  this->__createHfspHandler(virtualParent, NULL);
}


void			Hfsp::__createHfsHandler(Node* origin, VolumeInformation* vinfo)  throw (std::string)
{
  uint64_t		volumesize;
  uint64_t		startoffset;
  VolumeInformation*	volume;
  MasterDirectoryBlock*	mdb;
  HfsFileSystemHandler*	hfshandler;
  VirtualNode*		virtualParent;

  if (vinfo == NULL)
    volume = this->__volumeFactory->createVolumeInformation(origin, this);
  else
    volume = vinfo;
  if ((mdb = dynamic_cast<MasterDirectoryBlock* >(volume)) == NULL)
    throw std::string("Cannot get Master Directory Block on this volume");
  this->res["Master Directory Block"] = new Variant(mdb->_attributes());
  hfshandler = new HfsHandler();
  hfshandler->setOrigin(origin);
  hfshandler->setVolumeInformation(volume);
  if (volume->isWrapper())
    this->__root = new HfsRootNode("HFS Wrapper", 0, NULL, this);
  else
    this->__root = new HfsRootNode("HFS", 0, NULL, this);
  this->__root->setVolumeInformation(volume);
  hfshandler->setMountPoint(this->__root);
  virtualParent = new VirtualNode(this);
  volumesize = (uint64_t)mdb->totalBlocks() * (uint64_t)volume->blockSize();
  startoffset = (uint64_t)mdb->firstAllocationBlock() * 512;
  virtualParent->setContext(this->__virtualParent, startoffset, volumesize);
  hfshandler->process(virtualParent, 0, this);
  this->registerTree(this->__parent, this->__root);
}


void			Hfsp::__process() throw (std::string)
{
  VolumeInformation*	volume;

  volume = NULL;
  try
    {
      volume = this->__volumeFactory->createVolumeInformation(this->__virtualParent, this);
      if (volume->type() == HfsVolume)
	{
	  if (volume->isWrapper())
	    {	      
	      if (this->__mountWrapper)
		this->__createHfsHandler(this->__virtualParent, volume);
	      this->__createWrappedHfspHandler(this->__virtualParent, volume);
	    }
	  else
	    this->__createHfsHandler(this->__virtualParent, volume);
	}
      else
	this->__createHfspHandler(this->__virtualParent, volume);
      this->stateinfo = std::string("Successfully mounted");
    }
  catch (std::string err)
    {
      if (this->__root != NULL)
  	delete this->__root;
      if (volume != NULL)
  	delete volume;
      this->stateinfo = std::string("Error while mounting\n") + err;
      throw(std::string("HFS module: error while processing\n") + err);
    }
  return;
}
