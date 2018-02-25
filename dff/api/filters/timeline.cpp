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

#include <algorithm>

#include "datetime.hpp"
#include "timeline.hpp"
#include "variant.hpp"
#include "node.hpp"

namespace DFF
{

TimeLineNode::TimeLineNode(Node* node, const std::string& attributeName, const DateTime& attribute) : __node(node), __attributeName(attributeName), __timeAttribute(attribute)
{
}
      
TimeLineNode::TimeLineNode(const TimeLineNode& copy) : __node(copy.__node), __attributeName(copy.__attributeName), __timeAttribute(copy.__timeAttribute)
{
}

TimeLineNode::~TimeLineNode()
{
}
 
bool    TimeLineNode::compare(TimeLineNode* a, TimeLineNode* b)
{
  if (a && b)
    return (a->__timeAttribute < b->__timeAttribute);
  else
    return (false);
}
 
Node*   TimeLineNode::node(void) const
{
  return (this->__node);
}

DateTime  TimeLineNode::attribute(void) const
{
  return (this->__timeAttribute);
}

const std::string TimeLineNode::attributeName(void) const
{
  return (this->__attributeName);
}

/**
 *  TimeLiner
 */
TimeLine::TimeLine() : __stop(0), __processed(0), __toProcess(0)
{
}

TimeLine::~TimeLine()
{
  this->__clear();
}

void                          TimeLine::stop(void)
{
  this->__stop = 1;
}

uint64_t                      TimeLine::toProcess(void) const
{
  return (this->__toProcess);
}

uint64_t                      TimeLine::processed(void) const
{
  return (this->__processed);
}

const std::vector<TimeLineNode*>&   TimeLine::sort(std::vector<Node*> nodes)
{
  this->__toProcess = nodes.size();

  std::vector<Node*>::iterator node = nodes.begin();
  for (; node != nodes.end(); ++node)
  {
    if (this->__stop)
    {
      this->__clear();
      this->__stop = 0;
      throw std::string("TimeLine::sort() stopped");
    }
    try 
    {
      Attributes attributes = (*node)->attributesByType(typeId::DateTime); 
      Attributes::iterator attribute = attributes.begin();
      for (; attribute != attributes.end(); ++attribute)
      {
        DateTime* time = attribute->second->value<DateTime*>();
        if (time)
          this->__sorted.push_back(new TimeLineNode((*node), attribute->first, *time));
      }
    }
    catch (...)
    {
    }
    this->__processed += 1;
  }
  std::sort(this->__sorted.begin(), this->__sorted.end(), TimeLineNode::compare);

  return (this->__sorted);
}

const std::vector<TimeLineNode*>&     TimeLine::sorted(void) const
{
  return (this->__sorted);
}

void                                  TimeLine::__clear(void)
{
  std::vector<TimeLineNode*>::iterator timeLineNode = this->__sorted.begin();
  for (; timeLineNode != this->__sorted.end(); ++timeLineNode)
    delete (*timeLineNode);
  this->__sorted.clear();
}

}
