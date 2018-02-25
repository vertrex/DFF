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
 *  Frederic Baguelin <fba@digital-forensic.org>
 */

#include "confmanager.hpp"

namespace DFF
{

ConfigManager::ConfigManager()
{
}

ConfigManager::~ConfigManager()
{
  std::map<std::string, Config*>::iterator config = this->__configs.begin();
  for (; config != this->__configs.end(); ++config)
     delete (*config).second;
}

ConfigManager*	ConfigManager::Get()
{
    static ConfigManager single;
    return &single;
}

void					ConfigManager::unregisterConf(std::string confname)
{
  std::map<std::string, Config*>::iterator	it;

  it = this->__configs.find(confname);
  if (it != this->__configs.end())
    {
      if (it->second != NULL)
	delete it->second;
      this->__configs.erase(it);
    }
}

void					ConfigManager::registerConf(class Config* conf) throw(std::string)
{
  std::string	cname;

  if (conf != NULL)
    {
      cname = conf->origin();
      if (!cname.empty())
	{
	  if (this->__configs.find(cname) != this->__configs.end())
	    throw (std::string("argument" + cname + " has already been added"));
	  this->__configs.insert(std::pair<std::string, Config* >(cname, conf));
	}
      else
	throw (std::string("argument name is empty"));
    }
  else
    throw (std::string("provided argument is NULL"));
}


std::list<class Config*>		ConfigManager::configs()
{
  std::map<std::string, Config*>::iterator	it;
  std::list<Config*>				lconf;

  for (it = this->__configs.begin(); it != this->__configs.end(); it++)
    lconf.push_back(it->second);
  return lconf;
}

std::list<std::string>			ConfigManager::configsName()
{
  std::map<std::string, Config*>::iterator	it;
  std::list<std::string>			lname;

  for (it = this->__configs.begin(); it != this->__configs.end(); it++)
    lname.push_back(it->first);
  return lname;
}

class Config*				ConfigManager::configByName(std::string confname)
{
  std::map<std::string, Config*>::iterator	it;

  it = this->__configs.find(confname);
  if (it != this->__configs.end())
    return it->second;
  else
    return NULL;
}

std::map<std::string, Constant*>	ConfigManager::constantsByName(std::string constname)
{
  std::map<std::string, Config*>::iterator	it;
  std::map<std::string, Constant*>		mconsts;
  Constant*					constant;

  for (it = this->__configs.begin(); it != this->__configs.end(); it++)
    if ((constant = it->second->constantByName(constname)) != NULL)
      mconsts.insert(std::pair<std::string, Constant*>(it->first, constant));
  return mconsts;
}

std::map<std::string, Argument*>	ConfigManager::argumentsByName(std::string argname)
{
  std::map<std::string, Config*>::iterator	it;
  std::map<std::string, Argument*>		margs;
  Argument*					arg;

  for (it = this->__configs.begin(); it != this->__configs.end(); it++)
    if ((arg = it->second->argumentByName(argname)) != NULL)
      margs.insert(std::pair<std::string, Argument*>(it->first, arg));
  return margs;
}

}
