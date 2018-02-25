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

#include "vfs.hpp"
#include "node.hpp"
#include "tags.hpp"

namespace DFF
{

Color::Color() : r(0), g(0), b(0)
{
}

Color::Color(uint8_t cr, uint8_t cg, uint8_t cb) : r(cr), g(cg), b(cb)
{
}

Tag::Tag() : __id(0)
{
}

Tag::Tag(uint32_t id, std::string name, Color color) : __id(id), __name(name), __color(color)
{
}

Tag::Tag(uint32_t id, std::string name, uint8_t r, uint8_t g, uint8_t b) : __id(id), __name(name), __color(r, g, b)
{
}

Tag::~Tag()
{
}

const std::string Tag::name(void) const
{
  return (this->__name);
}

const Color    Tag::color(void) const
{
  return (this->__color);
}

uint32_t Tag::id(void) const
{
  return (this->__id);
}

void	Tag::setColor(Color color)
{
   this->__color = color;
}

void    Tag::setColor(uint8_t r, uint8_t g, uint8_t b)
{
  this->__color.r = r;
  this->__color.g = g;
  this->__color.b = b;
}

void	Tag::setName(const std::string name)
{
  this->__name = name;
}

#define DEFAULT_TAG(n, r, g, b) this->add(std::string(n), r, g, b);

TagsManager::TagsManager()
{
  DEFAULT_TAG("known good",   0, 255,   0)
  DEFAULT_TAG("known bad",    0,   0, 255)
  DEFAULT_TAG("malware",    255,   0,   0)
  DEFAULT_TAG("viewed",     255, 255,   0)
  DEFAULT_TAG("suspicious", 255, 85,    0)
  this->__defaults = this->__tagsList.size();
}

TagsManager::~TagsManager()
{
  std::vector<Tag*>::iterator tag = this->__tagsList.begin();
  for (; tag != this->__tagsList.end(); ++tag)
     delete (*tag);
}

  
TagsManager&	TagsManager::get()
{
  static TagsManager single;
  return (single);
}


void		TagsManager::Event(event* event)
{
}


uint32_t        TagsManager::add(const std::string name, Color color)
{
  return (this->add(name, color.r, color.g, color.b));
}

uint32_t 	TagsManager::add(const std::string name, uint8_t r, uint8_t g, uint8_t b)
{
  try 
  {
    Tag* t  =  this->tag(name);
    return (t->id());
  }
  catch (envError) 
  {
  }

  if (this->__tagsList.size() < 63)
  {
    uint32_t id = this->__tagsList.size() + 1;
 
    Tag* tag = new Tag(id, name, r, g, b); 
    this->__tagsList.push_back(tag);
    event* e = new event;
    e->type = 0x0003;
    e->value = Variant_p(new Variant(name));
    this->notify(e);
    return (id);
  }
  else
  {
    uint32_t  id = 0;

    for (; id < 63; id++)
    {
      if (this->__tagsList[id] == NULL)
      {
        this->__tagsList[id] = new Tag(id + 1, name, r, g, b);
	event* e = new event;
	e->type = 0x0003;
	e->value = Variant_p(new Variant(name));
	this->notify(e);
	return (id + 1);
      }
    }
  }

  return (0);
}

uint32_t 	TagsManager::add(const std::string name)
{
  //getcolorauto XXX //random ??
  return (this->add(name, 100, 170, 80));
}


bool		TagsManager::addNode(uint32_t tagId, uint64_t nodeUid)
{
  this->__nodes[tagId].push_back(nodeUid);
  event* e = new event;
  e->type = 0x0000;
  e->value = Variant_p(new Variant(nodeUid));
  this->notify(e);
  return true;
}


bool		TagsManager::removeNode(uint32_t tagId, uint64_t nodeUid)
{
  this->__nodes[tagId].remove(nodeUid);
  event* e = new event;
  e->type = 0x0001;
  e->value = Variant_p(new Variant(nodeUid));
  this->notify(e);
  return true;
}


uint64_t	TagsManager::nodesCount(const std::string name)
{
  Tag*		tag;
  
  try
    {
      tag = this->tag(name);
      return this->nodesCount(tag->id());
    }
  catch (envError e)
    {
      return 0;
    }  
}


uint64_t	TagsManager::nodesCount(uint32_t tagId)
{
  std::map<uint32_t, std::list<uint64_t> >::const_iterator	it;

  if ((it = this->__nodes.find(tagId)) != this->__nodes.end())
    return it->second.size();
  return 0;
}


std::list<uint64_t>	TagsManager::nodes(const std::string name)
{
  Tag*			tag;
  
  try
    {
      tag = this->tag(name);
      return this->nodes(tag->id());
    }
  catch (envError e)
    {
      return std::list<uint64_t>();
    }
}


std::list<uint64_t>	TagsManager::nodes(uint32_t tagId)
{
  std::map<uint32_t, std::list<uint64_t> >::const_iterator	it;

  if ((it = this->__nodes.find(tagId)) != this->__nodes.end())
    return it->second;
  return std::list<uint64_t>();
}

  
void            TagsManager::__removeNodesTag(uint32_t id, Node* node)
{
  node->removeTag(id);
  if (!(node->hasChildren()))
    return ;

  std::vector<Node*>           childs = node->children();
  std::vector<Node*>::iterator it = childs.begin();
  for (; it != childs.end(); it++)
    if ((*it) != NULL)
      this->__removeNodesTag(id, (*it));
}

void            TagsManager::__removeNodesTag(uint32_t id)
{
  Node* root = VFS::Get().GetNode("/");

  this->__removeNodesTag(id, root);
}

bool		TagsManager::remove(uint32_t id)
{
  try
  {
    Tag* t = this->__tagsList.at(id - 1);
    if (t != NULL)
    {
      this->__removeNodesTag(id);
      if (id > this->__defaults)
      {
        delete this->__tagsList[id - 1];
        this->__tagsList[id - 1] = NULL;
	event* e = new event;
	e->type = 0x0004;
	e->value = Variant_p(new Variant(t->name()));
	this->notify(e);
        return (true);
      }
      else
        return (false);
    }
  }
  catch (std::exception)
  {
    return (false);
  }
  return (false);
}


bool		TagsManager::remove(const std::string name)
{
  std::vector<Tag* >::iterator it = this->__tagsList.begin();
  
  for (; it != this->__tagsList.end(); it++)
  {
    if (((*it) != NULL) && ((*it)->name() == name))
      return (this->remove((*it)->id())); 
  } 
  return (false);
}

const std::vector<Tag* >	TagsManager::tags(void) const
{
  return (this->__tagsList);
}

Tag*			TagsManager::tag(uint32_t id) const
{
  try 
  {
    Tag* t = this->__tagsList.at(id - 1);
    if (t != NULL)
      return (t);
  }
  catch (std::exception)
  {
  }
  throw envError("Tag not found"); 
}

Tag*			TagsManager::tag(const std::string name) const
{
  std::vector<Tag* >::const_iterator	it = this->__tagsList.begin();

  for (; it != this->__tagsList.end(); it++)
    if (((*it) != NULL) && (*it)->name() == name)
      return (*it); 

  throw envError("Tag not found");
}

}
