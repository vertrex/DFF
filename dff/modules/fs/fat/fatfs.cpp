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

#include "fatfs.hpp"

void		Fatfs::__process() throw (std::string)
{
  BootSector*		bs;
  FileAllocationTable*	fat;
  FatTree*		tree;

  bs = NULL;
  fat = NULL;
  tree = NULL;
  try
    {
      if (this->__parent->size() > 0)
	{
	  bs = new BootSector();
	  bs->process(this->__parent, this);
	  fat = new FileAllocationTable();
	  fat->setBootSector(bs);
	  fat->process(this->__parent, this);
	  tree = new FatTree();
	  tree->setBootSector(bs);
	  tree->setFat(fat);
	  tree->process(this->__parent, this, this->__metacarve);
	}
    }
  catch(...)
    {
      throw(std::string("Fatfs module: error while processing"));
    }
  return;
}

void		Fatfs::__setContext(std::map<std::string, Variant_p > args) throw (std::string)
{
  std::map<std::string, Variant_p >::iterator	it;

  this->__fat_to_use = 0;
  this->__metacarve = false;
  if ((it = args.find("file")) != args.end())
    this->__parent = it->second->value<Node*>();
  else
    throw(std::string("Fatfs module: no file provided"));
  if (this->__parent == NULL)
    throw(std::string("Fatfs module: Error NULL node provided"));
  if ((it = args.find("fat_to_use")) != args.end())
    {
      if ((this->__fat_to_use = it->second->value<uint16_t>()) > 255)
	throw std::string("provided fat to use is too large");
    }
  if ((it = args.find("meta_carve")) != args.end())
    this->__metacarve = true;
  return;
}

void		Fatfs::start(std::map<std::string, Variant_p > args)
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

Fatfs::~Fatfs()
{
}

Fatfs::Fatfs(): mfso("fatfs"), __fat_to_use(0), __metacarve(false), __checkslack(false), __parent(NULL)
{
}
