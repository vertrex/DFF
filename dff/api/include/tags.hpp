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

#ifndef __TAGS_HPP__
#define __TAGS_HPP__

#ifndef WIN32
  #include <stdint.h>
#elif _MSC_VER >= 1600
  #include <stdint.h>
#else
  #include "wstdint.h"
#endif

#include <string>
#include <vector>
#include "export.hpp"
#include "rc.hpp"
#include "eventhandler.hpp"

namespace DFF
{

class Node;

class Color
{
public:
  EXPORT        Color();
  EXPORT        Color(uint8_t r, uint8_t g, uint8_t b);
  uint8_t       r;
  uint8_t       g;
  uint8_t       b;
};

class Tag
{
private:
  uint32_t				__id;
  std::string	                        __name;
  Color 				__color;
public:
  EXPORT				~Tag();
  EXPORT                                Tag();
  EXPORT				Tag(uint32_t id, const std::string, Color color);
  EXPORT				Tag(uint32_t id, const std::string, uint8_t r, uint8_t g, uint8_t b);
  EXPORT uint32_t			id(void) const;
  EXPORT const std::string	        name(void) const;
  EXPORT const Color  			color(void) const;
  EXPORT void				setColor(Color color);
  EXPORT void				setColor(uint8_t r, uint8_t g, uint8_t b);
  EXPORT void				setName(const std::string name);
};

class TagsManager : public EventHandler
{
private:
					TagsManager(const TagsManager&);
  EXPORT				TagsManager();
  EXPORT                                ~TagsManager();
  TagsManager*				operator=(TagsManager&);
  void                                  __removeNodesTag(uint32_t id);
  void                                  __removeNodesTag(uint32_t id, class Node* node);
  std::vector<Tag*>			__tagsList;
  std::map<uint32_t, std::list<uint64_t> >	__nodes;
  uint32_t                              __defaults;
public:
  EXPORT static	TagsManager&		get(void);
  EXPORT virtual void			Event(event* e);
  EXPORT bool				addNode(uint32_t tagId, uint64_t nodeUid);
  EXPORT bool				removeNode(uint32_t tagId, uint64_t nodeUid);
  EXPORT uint64_t			nodesCount(const std::string name);
  EXPORT uint64_t			nodesCount(uint32_t tagId);
  EXPORT std::list<uint64_t>		nodes(const std::string name);
  EXPORT std::list<uint64_t>		nodes(uint32_t tagId);
  EXPORT Tag*				tag(uint32_t id) const;
  EXPORT Tag*				tag(const std::string name) const;
  EXPORT const std::vector<Tag* >	tags(void) const;	
  EXPORT uint32_t			add(const std::string name);
  EXPORT uint32_t			add(const std::string name, Color color);
  EXPORT uint32_t			add(const std::string name, uint8_t r, uint8_t g, uint8_t b);
  EXPORT bool				remove(uint32_t id);
  EXPORT bool				remove(const std::string name);
};

}
#endif
