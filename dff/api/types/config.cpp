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
 *  Frederic B. <fba@digital-forensic.org>
 */

#include "config.hpp"

namespace DFF
{

Config::Config(std::string origin, std::string description)
{
  this->__origin = origin;
  this->__description = description;
}

Config::~Config()
{
  std::map<std::string, Argument*>::iterator	ait;
  std::map<std::string, Constant*>::iterator	cit;
  
  for (ait = this->__arguments.begin(); ait != this->__arguments.end(); ait++)
      delete ait->second;
  this->__arguments.clear();
  for (cit = this->__constants.begin(); cit != this->__constants.end(); cit++)
      delete cit->second;
  this->__constants.clear();
}

std::string		Config::origin()
{
  return this->__origin;
}

std::string		Config::description()
{
  return this->__description;
}

void		Config::addArgument(Argument* arg) throw (std::string)
{
  std::string	argname;

  if (arg != NULL)
    {
      argname = arg->name();
      if (!(argname.empty()))
	{
	  if (this->__arguments.find(argname) != this->__arguments.end())
	    throw (std::string("argument" + argname + " has already been added"));
	  this->__arguments.insert(std::pair<std::string, Argument* >(argname, arg));
	}
      else
	throw (std::string("argument name is empty"));
    }
  else
    throw (std::string("provided argument is NULL"));
}

std::list<Argument*>	Config::arguments()
{
  std::map<std::string, Argument*>::iterator	it;
  std::list<Argument*>				larg;

  for (it = this->__arguments.begin(); it != this->__arguments.end(); it++)
    larg.push_back(it->second);
  return larg;
}

std::list<std::string>	Config::argumentsName()
{
  std::map<std::string, Argument*>::iterator	it;
  std::list<std::string>			lname;

  for (it = this->__arguments.begin(); it != this->__arguments.end(); it++)
    lname.push_back(it->first);
  return lname;
}

Argument*		Config::argumentByName(std::string argname)
{
  std::map<std::string, Argument*>::iterator	it;

  it = this->__arguments.find(argname);
  if (it != this->__arguments.end())
    return it->second;
  else
    return NULL;
}

std::list<Argument*>	Config::argumentsByName(std::list<std::string> argsname)
{
  std::list<std::string>::iterator		it;
  Argument*					carg;
  std::list<Argument*>				nargs;

  
  for (it = argsname.begin(); it != argsname.end(); it++)
    if ((carg = this->argumentByName(*it)) != NULL)
      nargs.push_back(carg);
  return nargs;
}

std::list<Argument*>	Config::argumentsByFlags(uint16_t flags)
{
  std::map<std::string, Argument*>::iterator	mit;
  std::list<Argument*>				fargs;

  uint16_t					itype;
  uint16_t					rtype;
  uint16_t					type;
  bool						match;
  
  itype = flags & 0x0300;
  rtype = flags & 0x0c00;
  type = flags & 0x00FF;
  for (mit = this->__arguments.begin(); mit != this->__arguments.end(); mit++)
    {
      match = true;
      if ((type != 0) && (mit->second->type() != type))
	match = false;
      if ((itype != 0) && mit->second->inputType() != itype)
	match = false;
      if ((rtype != 0) && (mit->second->requirementType() != rtype))
	match = false;
      if (match)
	fargs.push_back(mit->second);
    }
  return fargs;
}

std::list<Argument*>	Config::argumentsByInputType(uint16_t itype)
{
  std::map<std::string, Argument*>::iterator	mit;
  std::list<Argument*>				iargs;

  for (mit = this->__arguments.begin(); mit != this->__arguments.end(); mit++)
    if (mit->second->inputType() == itype)
      iargs.push_back(mit->second);
  return iargs;
}

std::list<Argument*>	Config::argumentsByRequirementType(uint16_t rtype)
{
  std::map<std::string, Argument*>::iterator	mit;
  std::list<Argument*>				rargs;

  for (mit = this->__arguments.begin(); mit != this->__arguments.end(); mit++)
    if (mit->second->requirementType() == rtype)
      rargs.push_back(mit->second);
  return rargs;
}

std::list<Argument*>	Config::argumentsByType(uint16_t type)
{
  std::map<std::string, Argument*>::iterator	mit;
  std::list<Argument*>				targs;

  for (mit = this->__arguments.begin(); mit != this->__arguments.end(); mit++)
    {
      if (mit->second->type() == type)
	targs.push_back(mit->second);
    }
  return targs;
}

void		Config::addConstant(Constant* constant) throw(std::string)
{
  std::string	cname;
  
  if (constant != NULL)
    {
      cname = constant->name();
      if (!(cname.empty()))
	{
	  if (this->__constants.find(cname) != this->__constants.end())
	    throw(std::string("constant " + cname + " has already been added"));
	  this->__constants.insert(std::pair<std::string, Constant*>(cname, constant));
	}
    }
  else
    throw(std::string("provided constant is NULL"));
}

std::list<Constant*>		Config::constants()
{
  std::list<Constant*>				lconst;
  std::map<std::string, Constant*>::iterator	it;
  
  for (it = this->__constants.begin(); it != this->__constants.end(); it++)
    lconst.push_back(it->second);
  return lconst;
}

Constant*			Config::constantByName(std::string cname)
{
  std::map<std::string, Constant*>::iterator	it;
  
  it = this->__constants.find(cname);
  if (it != this->__constants.end())
    return it->second;
  else
    return NULL;
}

std::list<Constant*>		Config::constantByType(uint8_t type)
{
  std::map<std::string, Constant*>::iterator	it;
  std::list<Constant*>				lconsts;

  for (it = this->__constants.begin(); it != this->__constants.end(); it++)
    if (it->second->type() == type)
      lconsts.push_back(it->second);
  return lconsts;
}

}
