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

#ifndef __FSO_HPP__
#define __FSO_HPP__

#ifndef WIN32
  #include <stdint.h>
#elif _MSC_VER >= 1600
	#include <stdint.h>
#else
  #include "wstdint.h"
#endif

#include <string.h>
#include <iostream>
#include <stdio.h>
#include <list>
#include <map>
#include <vector>

#include "variant.hpp"

namespace DFF
{

//typedef std::map<std::string, Variant_p > RunTimeArguments; 
class Node;

class fso
{
private:
  std::map<uint64_t, Node* >            __nodes;
  uint16_t				__uid;
  std::vector<class fso*>		__children;
  fso*					__parent;
public:
  std::map<std::string, Variant_p > 	res;
  std::string				stateinfo;
  std::string				name;

  EXPORT fso(std::string name);
  EXPORT virtual ~fso();
  EXPORT virtual void			start(std::map<std::string, RCPtr< Variant > > args) = 0;
  EXPORT virtual int32_t 		vopen(class Node *n) = 0;
  EXPORT virtual int32_t 		vread(int32_t fd, void *rbuff, uint32_t size) = 0;
  EXPORT virtual int32_t 		vwrite(int32_t fd, void *wbuff, uint32_t size) = 0;
  EXPORT virtual int32_t 		vclose(int32_t fd) = 0;
  EXPORT virtual uint64_t		vseek(int32_t fd, uint64_t offset, int32_t whence) = 0;
  EXPORT virtual uint32_t		status(void) = 0;
  EXPORT virtual uint64_t		vtell(int32_t fd) = 0;
  EXPORT virtual void			setVerbose(bool verbose){ (void)verbose;}
  EXPORT virtual bool			verbose() { return false; }
  EXPORT void				registerTree(Node* parent, Node* head);
  EXPORT uint64_t			registerNode(uint64_t id, Node* node);
  EXPORT std::vector<Node*>     	nodes();
  EXPORT uint64_t			nodeCount();
  EXPORT uint16_t			uid();
  EXPORT Node*  			getNodeById(uint64_t id);
  EXPORT bool				hasChildren();
  EXPORT std::vector<class fso*>	children();
  EXPORT uint32_t			childCount();
  EXPORT void				setParent(class fso* parent);
  EXPORT class fso*			parent();
  EXPORT void				addChild(class fso* child);
  EXPORT virtual bool                   unmap(Node* node);
};

}
#endif
