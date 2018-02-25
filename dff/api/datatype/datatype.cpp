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
 *  Solal J. <sja@digital-forensic.org>
 */
#include "exceptions.hpp"
#include "variant.hpp"
#include "node.hpp"
#include "datatype.hpp"
#include "config.hpp"
#include "confmanager.hpp"

namespace DFF
{

/**
 *  Type
 */ 
void		Type::__compatibleModulesByType(const std::map<std::string, Constant*>& cmime, const std::string dtypes, std::list<std::string>& result)
{
  std::map<std::string, Constant*>::const_iterator	cit;
  std::list<Variant_p >					lvalues;
  std::list<Variant_p >::iterator			lit;
  bool							match;

  for (cit = cmime.begin(); cit != cmime.end(); cit++)
    {
      match = false;
      if ((cit->second != NULL) && (cit->second->type() == typeId::String))
	{
	  lvalues = cit->second->values();
	  lit = lvalues.begin();
	  while (lit != lvalues.end() && !match)
	    {
	      std::string	cval = (*lit)->value<std::string>();
	      if (dtypes.find(cval) != std::string::npos)
		{
		  match = true;
		  result.push_back(cit->first);
		}
	      lit++;
	    }
	}
    }
}


/**
 *  Type
 */
Type::Type(const std::string name) : __name(name)
{
  std::list<std::string>        	result;
  ConfigManager*			cm;
  std::map<std::string, Constant*>	constants;
  std::string				ext;

  if ((cm = ConfigManager::Get()) != NULL)
    {
      constants = cm->constantsByName("mime-type");
      if (!constants.empty())       
	{
	  this->__compatibleModulesByType(constants, name, result);
	  this->__compatibleModules = result;
	}
    }
}


Type::~Type()
{
}


const std::string       Type::name() const
{
  return (this->__name);
}

const std::list<std::string>    Type::compatibleModules(void) const
{
  return (this->__compatibleModules);
}


/**
 *  DataTypeManager
 */
DataTypeManager::DataTypeManager()
{
  mutex_init(&this->__mutex);
}


DataTypeManager* 	DataTypeManager::Get()
{
  static DataTypeManager single;
  return &single;
}


DataTypeManager::~DataTypeManager()
{
  std::map<const std::string, const Type*>::iterator type = this->__types.begin();

  for (; type != this->__types.end(); ++type)
    delete (*type).second;
  this->__types.clear();
  this->__nodesType.clear();
  mutex_destroy(&this->__mutex);
}


void		DataTypeManager::Event(event* e)
{
}


bool		DataTypeManager::registerHandler(DataTypeHandler* handler)
{
  if (this->__handler != NULL)
    delete this->__handler;
  this->__handler = handler;
  return true;
}

const std::string	DataTypeManager::type(Node* node)
{
  const	std::string	dtype;
  const Type*		type;
  
  if (node != NULL && this->__handler != NULL)
    {  
      // At first, check if node's type has already been processed
      mutex_lock(&this->__mutex);
      std::map<Node*, const Type* >::const_iterator nodeType = this->__nodesType.find(node);
      mutex_unlock(&this->__mutex);
      if (nodeType != this->__nodesType.end())
	{
	  if ((type = nodeType->second) != NULL)
	    return type->name();
	}
      // else, process node's type and return it;
      else
	{
	  std::string result;
	  try
	    {
	      result = this->__handler->type(node);
	    }
	  catch (...)
	    {
	      result = std::string("error");
	    }
	  mutex_lock(&this->__mutex);
	  std::map<const std::string, const Type* >::const_iterator types = this->__types.find(result);
	  if (types == this->__types.end())
	    {
	      type = new Type(result);
	      this->__types[result] = type;
	      event* e = new event;
	      e->type = 0x0de1; 
	      e->value = Variant_p(new Variant(result));
	      this->notify(e);
	    }
	  else
	    type = types->second;
	  this->__nodesType[node] = type;
	  this->__typeNodes[result].push_back(node);
	  mutex_unlock(&this->__mutex);
	  return result;
	}
    }
  return std::string("");
}

  
const std::list<std::string>	DataTypeManager::existingTypes()
{
  std::map<const std::string, const Type* >::const_iterator	typesIterator;
  std::list<std::string>					typesList;

  for (typesIterator = this->__types.begin(); typesIterator != this->__types.end(); ++typesIterator)
    typesList.push_back(typesIterator->first);
  return typesList;
}


const std::vector<Node* >	DataTypeManager::nodes(std::string type)
{
  std::map<const std::string, std::vector<Node* > >::const_iterator types = this->__typeNodes.find(type);
  if (types == this->__typeNodes.end())
    return std::vector<Node* >();
  return types->second;
}


uint64_t	DataTypeManager::nodesCount(std::string type)
{
  std::map<const std::string, std::vector<Node* > >::const_iterator types = this->__typeNodes.find(type);
  if (types == this->__typeNodes.end())
    return 0;
  return types->second.size();
}


std::list<std::string>		DataTypeManager::compatibleModules(Node* node)
{
  std::list<std::string>	modules;
  const std::string dtype = node->dataType(); //node dataType could be overloaded so must call it
  const Type* type = NULL;

  mutex_lock(&this->__mutex);
  std::map<const std::string, const Type* >::const_iterator types = this->__types.find(dtype);
  mutex_unlock(&this->__mutex);
  if (types != this->__types.end())
    type = types->second;
  if (type != NULL)
    {
      //modules.copy()
      std::list<std::string> currentModules = type->compatibleModules();
      std::list<std::string>::iterator currentModule = currentModules.begin();
      for (; currentModule != currentModules.end(); ++currentModule)
  	modules.push_back(*currentModule);
      modules.unique();
    }
  return (modules);
}


/**
 *  DataTypeHandler
 */
DataTypeHandler::DataTypeHandler()
{
  DataTypeManager* 	dataTypeManager =  DataTypeManager::Get();

  dataTypeManager->registerHandler(this);
}

DataTypeHandler::~DataTypeHandler()
{

}

}
