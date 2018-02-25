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

#ifndef __FACTORY_HPP__
#define __FACTORY_HPP__

#include <iostream>
#include <map>
#include "export.hpp"

struct QueryFlags
{
  enum Level
    {
      Empty = 0x0000,
      Primitive = 0x0001,
      Tags = 0x0002,
      DataType = 0x0004,
      Advanced = 0x0008
    };
};

class Expression;

class AttributeFactory
{
public:
  enum CName
    {
      Named = 0,
      Timestamp = 1
    };
  typedef Expression* (*factoryMethod)();
  typedef Expression* (*CreateInstance)(std::string);
  EXPORT static AttributeFactory*	instance();
  EXPORT int			addKeyword(std::string keyword, std::string fqn, CName type, QueryFlags::Level qflag) throw (std::string);
  EXPORT int			registerCreator(CName type, CreateInstance creator) throw (std::string);
  EXPORT Expression*		create(std::string keyword) throw (std::string);
  EXPORT QueryFlags::Level	getQueryFlags(std::string fqn) throw (std::string);
private:
  EXPORT			AttributeFactory();
  EXPORT			AttributeFactory(AttributeFactory &);
  EXPORT			~AttributeFactory();
  AttributeFactory&		operator=(AttributeFactory &);
  typedef struct
  {
    CreateInstance		func;
    QueryFlags::Level		qflags;
  }				finfo;
  std::map<std::string, finfo* >	__objects;
  std::map<std::string, std::string >	__kw_map;
  std::map<CName, CreateInstance>	__creator;
};

#endif
