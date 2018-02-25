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
 *  Solal Jacob <sja@digital-forensic.org>
 */

#ifndef __ROOTNODE_HPP__
#define __ROOTNODE_HPP__

#include <string>
#include <set>
#include "eventhandler.hpp"
#include "threading.hpp"
#include "node.hpp"

namespace DFF
{

class VFSRootNode : public Node
{
public:
  EXPORT VFSRootNode(std::string name);
  EXPORT ~VFSRootNode();
};

class ModulesRootNode: public Node, public EventHandler 
{
private:
                               mutex_def(__mutex);
  std::map<std::string, Node*> __modulesNameRootNode;
public:
  EXPORT                ModulesRootNode(EventHandler* vfs, Node* root);
  EXPORT                ~ModulesRootNode();
  EXPORT std::string    icon();
  EXPORT void           Event(event* e); 
};

}
#endif
