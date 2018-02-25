/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2013 ArxSys
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *  
 * See http: www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 * 
 * Author(s):
 *  Solal J. <sja@digital-forensic.org>
 *  Frederic Baguelin <fba@digital-forensic.org>
 */


#ifndef __CONFIG_HPP__
#define __CONFIG_HPP__

#include <string>
#include <list>
#include <map>
#include <iostream>
#include "export.hpp"
#include "argument.hpp"
#include "constant.hpp"

namespace DFF
{

class Config
{
private:
  std::string				__origin;
  std::string				__description;
  std::map<std::string, Argument*>	__arguments;
  std::map<std::string, Constant*>	__constants;

public:
  EXPORT Config(std::string origin, std::string description = "");
  EXPORT ~Config();
  EXPORT std::string		origin();
  EXPORT std::string		description();

  EXPORT void			addArgument(Argument* arg) throw (std::string);
  EXPORT std::list<Argument*>	arguments();
  EXPORT std::list<std::string>	argumentsName();

  EXPORT Argument*		argumentByName(std::string argname);
  EXPORT std::list<Argument*>	argumentsByName(std::list<std::string> argsname);
  EXPORT std::list<Argument*>	argumentsByFlags(uint16_t flags);
  EXPORT std::list<Argument*>	argumentsByInputType(uint16_t itype);
  EXPORT std::list<Argument*>	argumentsByRequirementType(uint16_t rtype);
  EXPORT std::list<Argument*>	argumentsByType(uint16_t type);

  EXPORT void			addConstant(Constant* constant) throw (std::string);
  EXPORT std::list<Constant*>	constants();
  EXPORT Constant*		constantByName(std::string cname);
  EXPORT std::list<Constant*>	constantByType(uint8_t type);
};

}
#endif
