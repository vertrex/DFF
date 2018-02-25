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

#ifndef __NODE_HPP__
#define __NODE_HPP__

#ifndef WIN32
  #include <stdint.h>
#elif _MSC_VER >= 1600
  #include <stdint.h>
#else
  #include "wstdint.h"
#endif
#include <string>
#include <map>
#include <vector>
#include <set>
#include <list>
#include <iostream>
#include <sys/types.h>
#include "export.hpp"
#include "rc.hpp"

namespace DFF
{

class Constant;
class FileMapping;
class Variant;
class Tag;
class VFile;
class fso;

#define Variant_p	DFF::RCPtr< DFF::Variant > //typedef

typedef std::map<std::string, RCPtr< class Variant > > Attributes;

class AttributesHandler
{
  std::string   		__handlerName;
public:
  EXPORT			AttributesHandler(std::string handlerName);
  EXPORT virtual		~AttributesHandler();
  EXPORT virtual Attributes 	attributes(class Node*) = 0;
  EXPORT std::string		name(void);
};

class AttributesHandlers
{
private:
  uint64_t                              __state; 
  std::set<AttributesHandler*>          __handlers; 
public:
  EXPORT                                AttributesHandlers();
  EXPORT                                ~AttributesHandlers();
  EXPORT size_t                         count();
  EXPORT std::set<AttributesHandler*>&  handlers();
  EXPORT void                           updateState(void);
  EXPORT const uint64_t                 state(void);
  EXPORT bool                           add(AttributesHandler* attributeHandler);
  EXPORT bool                           remove(AttributesHandler* attributeHandler);
  EXPORT bool                           remove(std::string name);
};

#define ISFILE		0x01
#define ISDIR		0x02
#define ISLINK		0x04
#define ISDELETED	0x08

enum	attributeNameType
{
  ABSOLUTE_ATTR_NAME = 0,
  RELATIVE_ATTR_NAME = 1
};

class Node
{
protected:
  class Node*				__parent;
  AttributesHandlers                    __attributesHandlers;
  std::vector<class Node *>		__children;
  uint32_t				__childcount;
  std::string				__name;
  uint64_t				__size;
  fso*				        __fsobj;
  uint64_t				__common_attributes;
  uint64_t				__uid;
  uint64_t				__tags;
  EXPORT virtual Attributes		_attributes();
  EXPORT virtual uint64_t               _attributesState();
  EXPORT void				attributesByTypeFromVariant(Variant_p rcvar, uint8_t, Attributes*, std::string current);
  
  EXPORT void	 			attributesByNameFromVariant(Variant_p rcvar, std::string name, std::list< Variant_p >* result);
  EXPORT void				attributeByAbsoluteNameFromVariant(Variant_p rcvar, std::string name, std::list< Variant_p >* result);
  
  EXPORT void	 			attributesNamesFromVariant(Variant_p rcvar, std::list<std::string>* names);
  EXPORT void	 			attributesNamesFromVariant(Variant_p rcvar, std::list<std::string>* names, std::string current);
  
  EXPORT void				attributesNamesAndTypesFromVariant(Variant_p rcvar, std::map<std::string, uint8_t> *namestypes, std::string current);
  EXPORT bool				constantValuesMatch(Constant* constant, Attributes vars);
  void		                        __compatibleModulesByExtension(const std::map<std::string, Constant*>& cextensions, std::string& ext, std::list<std::string>& result);
public:
  EXPORT 					Node(std::string name, uint64_t size = 0, Node* parent = NULL, fso* fsobj = NULL, bool registerNode = true);
  EXPORT 					Node();
  EXPORT virtual 				~Node();

  uint32_t					__at;

  EXPORT void					setFile(void);
  EXPORT void					setDir(void);
  EXPORT void					setLink(void);
  EXPORT void					setDeleted(void);
  EXPORT void					setSize(uint64_t size);
  EXPORT void					setFsobj(fso* obj);
  EXPORT void					setParent(Node* parent);

  EXPORT virtual void				fileMapping(FileMapping *);
  EXPORT virtual uint64_t                       fileMappingState(void);
  EXPORT virtual uint64_t			size(void);

  EXPORT std::string				path(void);
  EXPORT std::string				name(void);
  EXPORT std::string				absolute(void);
  EXPORT std::string				extension(void);


  EXPORT virtual bool				isFile(void);
  EXPORT virtual bool				isDir(void);
  EXPORT virtual bool				isLink(void);
  EXPORT virtual bool				isVDir(void);
  EXPORT virtual bool				isDeleted(void);

  EXPORT virtual fso*    			fsobj(void);

  EXPORT Node*					parent(void);

  EXPORT std::vector<class Node*>		children(void);
  EXPORT bool					addChild(class Node* child);
  EXPORT bool                                   removeChild(class Node* child);
  EXPORT bool					hasChildren(void);
  EXPORT uint32_t				childCount(void);
  EXPORT uint64_t				totalChildrenCount(uint32_t depth=(uint32_t)-1);

  EXPORT virtual VFile*	                        open(void);
  EXPORT uint32_t				at(void);
  EXPORT uint64_t				uid(void);

  EXPORT virtual AttributesHandlers&            attributesHandlers(void);
  EXPORT virtual bool				registerAttributes(AttributesHandler*);

  EXPORT virtual const std::string		dataType(void);
  EXPORT virtual Attributes			attributes(void);
  EXPORT virtual Attributes			attributesByType(uint8_t type);
  EXPORT virtual std::list< Variant_p >		attributesByName(std::string name, attributeNameType tname=RELATIVE_ATTR_NAME);
  EXPORT virtual std::list<std::string>		attributesNames(attributeNameType tname=RELATIVE_ATTR_NAME);
  
  EXPORT virtual std::map<std::string, uint8_t>	attributesNamesAndTypes(void);
  EXPORT virtual std::string			icon(void);
  EXPORT virtual std::list<std::string>		compatibleModules(void);
  EXPORT virtual Attributes			dynamicAttributes(void);
  EXPORT virtual Attributes			dynamicAttributes(std::string name);
  EXPORT virtual std::list<std::string>		dynamicAttributesNames(void);
  EXPORT virtual Attributes			fsoAttributes(void);
  EXPORT virtual bool				setTag(std::string name);  
  EXPORT virtual bool				setTag(uint32_t id);
  EXPORT virtual bool				removeTag(std::string name);
  EXPORT virtual bool				removeTag(uint32_t id);
  EXPORT virtual bool				isTagged(std::string name);
  EXPORT virtual bool				isTagged(uint32_t id);	
  EXPORT virtual std::vector<Tag* >		tags(void);
  EXPORT virtual std::vector<uint32_t>		tagsId(void);
};

}
#endif
