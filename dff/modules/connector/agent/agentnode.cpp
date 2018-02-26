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

#include "agentnode.hpp"
#include "agent.hpp"

/**
 *  AgentNode 
 */
AgentNode::AgentNode(DObject* agent, Agent* fsobj) : Node("", 0, NULL, fsobj), __agent(fsobj)
{
  this->__name = fsobj->host();
  //this->setSize(agent->call("size").get<DUInt64>());
}

std::string  AgentNode::icon(void)
{
  return (":network");
}

Attributes      AgentNode::_attributes(void)
{
  Attributes attr;

  attr["host"] = Variant_p(new Variant(this->__agent->host()));
  attr["port"] = Variant_p(new Variant(this->__agent->port()));

  return (attr);
}

/**
 *  AgentDevice
 */
AgentDeviceNode::AgentDeviceNode(DObject* device, Node* parent, Agent* fsobj) : Node("", 0, parent, fsobj), __device(device)
{
  this->__name = device->getValue("blockDevice").get<DUnicodeString>();
  this->setSize(device->getValue("size").get<DUInt64>());
  this->__model = device->getValue("model").get<DUnicodeString>();
  this->__serialNumber = device->getValue("serialNumber").get<DUnicodeString>(); 
}

Attributes      AgentDeviceNode::_attributes(void)
{
  Attributes attr;

  attr["Serial number"] = Variant_p(new Variant(this->__serialNumber));
  attr["Model"] = Variant_p(new Variant(this->__model));

  return (attr);
}

DValue  AgentDeviceNode::device(void)
{
  return (this->__device);
}
