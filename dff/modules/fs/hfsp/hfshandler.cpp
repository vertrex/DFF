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


HfsHandler::HfsHandler()
{
}


HfsHandler::~HfsHandler()
{
}


void				HfsHandler::process(Node* origin, uint64_t offset, fso* fsobj) throw (std::string)
{
  this->setOrigin(origin, offset);
  this->setFsObject(fsobj);
  this->_createEtree();
  this->_createCatalog();
}


std::list<uint64_t>		HfsHandler::detetedEntries()
{
  std::list<uint64_t>		deleted;
  
  return deleted;
}


std::list<uint64_t>		HfsHandler::orphanEntries()
{
  std::list<uint64_t>		orphaned;

  return orphaned;
}


std::list<Node*>		HfsHandler::listFiles(uint64_t uid)
{
  std::list<Node*>		files;
  
  return files;
}


std::list<std::string>		HfsHandler::listNames(uint64_t uid)
{
  std::list<std::string>	names;
  
  return names;
}


Node*				HfsHandler::unallocatedSpace()
{
  return NULL;
}


Node*				HfsHandler::freeSpace()
{
  return NULL;
}


Node*				HfsHandler::slackSpace()
{
  return NULL;
}


void				HfsHandler::report()
{
}
