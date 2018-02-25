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

#ifndef __FILTER_HPP__
#define __FILTER_HPP__

#include <stdio.h>
#include "eventhandler.hpp"
#include "../filters/astnodes.hpp"
#include "../filters/scanner.hpp"

namespace DFF
{
class fso;
class Node;

class Filter : public EventHandler
{
public:
  EXPORT Filter(std::string fname); 
  EXPORT ~Filter();
  EXPORT std::string		query();
  EXPORT std::string		filterName();
  EXPORT virtual void		Event(event* e);
  EXPORT void			setFilterName(std::string fname); 
  EXPORT void			compile(std::string query);
  EXPORT void			processFolder(Node* nodeptr); 
  EXPORT void			process(Node* nodeptr, bool recursive=true);
  EXPORT void			process(std::list<Node*> nodes); 
  EXPORT void			process(std::vector<Node*> nodes); 
  EXPORT void			process(uint64_t nodeid, bool recursive=true);
  EXPORT void			process(fso* fsobj);
  EXPORT bool			match(Node* node);
  EXPORT bool			match(uint64_t nodeId);
  EXPORT std::vector<Node*>	matchedNodes();
  enum EventTypes
    {
      TotalNodesToProcess = 0x200,
      ProcessedNodes = 0x201,
      NodeMatched = 0x202,
      StopProcessing = 0x204,
      EndOfProcessing = 0x205,
      AstReset = 0x4242
    };
private:
  void			__process(Node* nodeptr, uint64_t* processed);
  void			__reset();
  void			__notifyNodesToProcess(uint64_t nodescount);
  void			__notifyMatch(Node* nodeptr);
  void			__notifyProgress(uint64_t processed);
  void			__notifyEndOfProcessing(uint64_t processed);
  std::string		__formatErrorMsg();
  void			__initCtx(); 
  bool			__eval(Node* node);
  event*		__ev;
  std::vector<Node*>	__matchednodes;
  std::string		__fname;
  uint32_t		__uid;
  std::string		__query;
  filter_ctx*		__ctx;
  bool			__stop;
};

}
#endif
