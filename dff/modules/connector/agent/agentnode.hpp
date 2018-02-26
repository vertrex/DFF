/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *  
 * See http: *www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 * 
 * Author(s):
 *  Solal Jacob <sja@digital-forensic.org>
 */

#include "node.hpp"
#include "variant.hpp"
#include "dobject.hpp"
#include "drealvalue.hpp"

using namespace DFF;
using namespace Destruct;

class Agent;

class AgentNode : public Node
{
public:
  AgentNode(DObject* agent, Agent* fsobj);
  std::string   icon(void);
  Attributes    _attributes(void);
private:
  Agent*        __agent;
};

class AgentDeviceNode : public Node
{
public:
  AgentDeviceNode(DObject* device, Node* parent, Agent* fsobj);
  DValue        device(void);
  Attributes    _attributes(void);
private:
  RealValue<DObject*>      __device;
  std::string              __serialNumber;
  std::string              __model;
};
