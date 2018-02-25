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
 *  Frederic B. <fba@digital-forensic.org>
 */

#include "factory.hpp"

AttributeFactory::AttributeFactory()
{
}

AttributeFactory::AttributeFactory(AttributeFactory &)
{
}

AttributeFactory::~AttributeFactory()
{
  std::map<std::string, finfo*>::iterator object = this->__objects.begin();
  for (; object != this->__objects.end(); ++object)
     delete (*object).second;
  this->__kw_map.clear();
  this->__creator.clear();
}

AttributeFactory*       AttributeFactory::instance(void)
{
  static AttributeFactory fact;
  return &fact;
}

int			AttributeFactory::registerCreator(CName type, CreateInstance creator) throw (std::string)
{
  this->__creator[type] = creator;
  return 1;
}

int			AttributeFactory::addKeyword(std::string keyword, std::string fqn, CName type, QueryFlags::Level flags) throw (std::string)
{
  finfo*	info;
  
  if (__objects.find(fqn) != __objects.end())
    {
      std::string	_err;
      _err = "Attribute " + fqn + " already assigned to a keyword";
      throw _err;
    }
  if ((info = new finfo) != NULL)
    {      
      info->func = this->__creator[type];
      info->qflags = flags;
      __objects[fqn] = info;
      __kw_map[keyword] = fqn;
    }
  return 0;
}

Expression*		AttributeFactory::create(std::string keyword) throw (std::string)
{
  std::map<std::string, std::string>::iterator idx;
  finfo*	info;
  
  idx = __kw_map.find(keyword);
  if (idx != __kw_map.end())
    {      
      if ((info = __objects[idx->second]) != NULL)
	return info->func(idx->second);
      else
	return NULL;
    }
  else
    return NULL;
}


QueryFlags::Level	AttributeFactory::getQueryFlags(std::string fqn) throw (std::string)
{
  finfo*	info;
  std::map<std::string, finfo* >::iterator	idx;
  
  idx = __objects.find(fqn);
  if (idx != __objects.end())
    {
      if ((info = idx->second) != NULL)
	return info->qflags;
      else
	throw std::string("id " + fqn + " is not setted properly");
    }
  else
    throw std::string("id " + fqn + " does not exist");
}

