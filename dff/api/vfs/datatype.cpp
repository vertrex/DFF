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
#include "vfile.hpp"
#include "../magic/magic.h"
#include <ctime>
#include "threading.hpp"
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

const std::string       DataTypeManager::typeFromBuffer(std::string buff)
{
  magic_t mime = magic_open(MAGIC_NONE);
  magic_load(mime, DFF_MAGIC_MGC_PATH);
  std::string result = "error";

  const char* magic_result = magic_buffer(mime, buff.c_str(), buff.size());
  if (magic_result)
    result = std::string(magic_result);
  magic_close(mime);

  return (result);
}

const std::string	DataTypeManager::type(Node* node)
{
  const	std::string	dtype;
  const Type*		type;
  
  if (node != NULL)
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
          if (node->size() > 0)
          {
            magic_t mime = magic_open(MAGIC_NONE);
            magic_load(mime, DFF_MAGIC_MGC_PATH);
            try
            {
               VFile* vfile = node->open();
               uint8_t buff[0x2000];
               uint32_t size = vfile->read(&buff, 0x2000);
               vfile->close();

               const char* magic_result = magic_buffer(mime, &buff, size);
               if (magic_result)
                 result = std::string(magic_result);
               else
                 result = "data";
               magic_close(mime);
            }
            catch (...)
            {
               result = "error";
            }
          }
          else if (node->hasChildren())
           result = "directory";
          else
           result = "empty";  

	  mutex_lock(&this->__mutex);
	  std::map<const std::string, const Type* >::const_iterator types = this->__types.find(result);
	  if (types == this->__types.end()) //XXX ca va faire bcp d event ! pdt le scan car il va tous ce les prendre 
	  {
	      type = new Type(result);
	      this->__types[result] = type;
	      //event* e = new event;
	      //e->type = 0x0de1; 
	      //e->value = Variant_p(new Variant(result));
	      //this->notify(e);
	  }
	  else
	    type = types->second;
	  this->__nodesType[node] = type;

          std::size_t pos = result.find(" ");
          while (pos != std::string::npos)
          {
            std::string left = result.substr(0, pos);
  	    this->__typeNodes[left].push_back(node);
            result = result.substr(pos + 1); 
            pos  = result.find(" ");
          }
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
 *  DataTypeScanner
 */ 
ThreadResult   DataTypeScannerWorker(ThreadData vnodes)
{
  std::vector<Node*>* nodes = static_cast<std::vector<Node*>* >(vnodes);
  std::vector<Node*>::iterator node = nodes->begin();
  DataTypeScanner& dataTypeScanner = DataTypeScanner::instance();

  uint64_t total = nodes->size();
  uint64_t current = 0;
  uint64_t oldTotal = 0;
  uint64_t i = 0;
  for (; node != nodes->end(); ++node)
  {
    //each x percent ... call directyle a func -> add percent ? or send a signal // or global var ?
    (*node)->dataType();
    i++;
    if (current != i*((float)100/total))
    {
      current = i*((float)100/total);
      dataTypeScanner.updateProgress(i - oldTotal);
      oldTotal = i;
    }
  }
  delete nodes; //le pointeur et la liste a clear ?
  return (NULL);
}

DataTypeScanner::DataTypeScanner()
{
}

DataTypeScanner& DataTypeScanner::instance()
{
  static DataTypeScanner dataTypeScanner;
  return (dataTypeScanner);
}

DataTypeScanner::~DataTypeScanner()
{
}

void    DataTypeScanner::Event(event* e)
{
}

std::vector<Node*>    DataTypeScanner::walk(Node* node)
{
  std::vector<Node*> nodes;
  nodes.push_back(node);

  std::vector<Node*> children = node->children();
  std::vector<Node*>::iterator child = children.begin();
  for (; child != children.end(); ++child)
  {
     std::vector<Node*> childs = this->walk(*child);
     nodes.insert(nodes.end(), childs.begin(), childs.end()); 
  }

  return (nodes);
}

void    DataTypeScanner::updateProgress(uint64_t count)
{
    this->currentProgress += count;
    event* e = new event;
    e->type = 0xdff;
    e->value = Variant_p(new Variant(currentProgress));
    this->notify(e);
}

void    DataTypeScanner::scan(Node* root) //std::vector<Node*> nodes) //class with event ?
{
  std::time_t begin = std::time(NULL);
  std::vector<Node*> nodes = this->walk(root);// this->walk(VFS::Get().GetNode("/"));

  uint64_t   cpuCount = 0;
  cpu_count(cpuCount);

  ThreadStruct*  thread = new ThreadStruct[cpuCount];

  uint64_t size = nodes.size();
  uint64_t part = size / cpuCount;
  uint64_t leak = size % cpuCount;
  //handle leak et part > cpuCount !
  if (size < cpuCount)
    cpuCount = 1;
  
  uint8_t i = 0;

  event* e = new event;
  e->type = 0xdfe;
  e->value = Variant_p(new Variant(nodes.size()));
  this->notify(e);

  for (; i < cpuCount -1; ++i)
  {
    std::vector<Node*>* snodes = new std::vector<Node*>(nodes.begin() + (part * i), nodes.begin() + (part * (i + 1)));
    createThread(DataTypeScannerWorker, snodes, thread[i]); 
  }
  std::vector<Node*>* snodes = new std::vector<Node*>(nodes.begin() + (part * i), nodes.begin() + (part * (i + 1)) + leak);
  createThread(DataTypeScannerWorker, snodes, thread[i]); 
  for (i = 0; i < cpuCount; ++i)
  {
    ThreadResult result;
    thread_join(thread[i], result);
  }
//for i in 
//  #destroy thread ?
  std::cout << "finish" << std::endl;
  std::time_t end = std::time(NULL);
  int64_t elapsed_secs = end - begin;
  std::cout << "scaned  " << nodes.size() << " in " << elapsed_secs << std::endl;
  if (elapsed_secs)
  std::cout << std::fixed << nodes.size() / elapsed_secs << " datatype by seconds" << std::endl;
}

}
