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

#ifndef __DATATYPE_HPP__
#define __DATATYPE_HPP__

#ifndef WIN32
  #include <stdint.h>
#elif _MSC_VER >= 1600
  #include <stdint.h>
#else
  #include "wstdint.h"
#endif
#include <vector>
#include <map>
#include <list>
#include <stdexcept>
#include <string>
#include "rc.hpp"
#include "variant.hpp"
#include "threading.hpp"
#include "eventhandler.hpp"

namespace DFF
{

class Node;
class Constant;
typedef std::map<std::string, DFF::RCPtr< class DFF::Variant > > Attributes;

class DataTypeHandler
{
public:
  EXPORT			DataTypeHandler();
  EXPORT  virtual 		~DataTypeHandler();
  EXPORT  virtual std::string	type(Node* ) = 0;
}; 

class Type
{
public:
  EXPORT				Type(const std::string name);
  EXPORT				~Type();
  EXPORT const std::string		name(void) const;
  EXPORT const std::list<std::string>	compatibleModules(void) const;
private:
  const std::string			__name;
  std::list<std::string>		__compatibleModules;
  void					__compatibleModulesByType(const std::map<std::string, Constant*>& cmime, const std::string dtypes, std::list<std::string>& result);
};

// class Types
// {
// public:
//   EXPORT        Types();
//   EXPORT        ~Types();
//   EXPORT const Type*   find(std::string typeName) const;
//   EXPORT const Type*   insert(std::string typeName);
// private:
//   std::map<const std::string, const Type* >    __types;
// };

// class NodesTypes
// {
// public:
//   EXPORT NodesTypes();
//   EXPORT const std::vector<const Type* >               find(Node* node) const; 
//   EXPORT void                                          insert(Node* node, const Type* type);
// private:
//   std::map<Node*, std::vector<const Type* > >   __nodesTypes; //XXX dff:map //pour locker !
// };

class DataTypeManager  : public EventHandler
{
private:
  EXPORT					DataTypeManager();
  						DataTypeManager(const DataTypeManager&);
  EXPORT					~DataTypeManager();
  DataTypeManager&				operator=(DataTypeManager& copy);
                                                mutex_def(__mutex);
  //EXPORT const Type*				__type(Node* node);
  DataTypeHandler*				__handler;
  std::map<const std::string, const Type* >	__types;
  std::map<Node*, const Type* >			__nodesType;
  std::map<const std::string, std::vector<Node* > > __typeNodes;
  void		                                __compatibleModulesByExtension(const std::map<std::string, Constant*>& cextensions, std::string& ext, std::list<std::string>& result);
public:
  EXPORT static DataTypeManager*		Get();
  EXPORT virtual void				Event(event* e);
  EXPORT bool					registerHandler(DataTypeHandler* dataTypeHandler);
  EXPORT const std::string			type(Node* node);
  EXPORT const std::list<std::string>		existingTypes();
  EXPORT const std::vector<Node* >		nodes(std::string type);
  EXPORT uint64_t				nodesCount(std::string type);
  EXPORT std::list<std::string>			compatibleModules(Node* node);
};

}
#endif
