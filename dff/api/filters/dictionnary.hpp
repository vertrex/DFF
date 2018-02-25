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
 *  Frederic B. <fba@digital-forensic.org>
 */

#ifndef __DICTIONNARY_HPP__
#define __DICTIONNARY_HPP__

#ifndef WIN32
  #include <stdint.h>
#elif _MSC_VER >= 1600
  #include <stdint.h>
#else
  #include "wstdint.h"
#endif
// forward declaration
#include <ios>
#include <iostream>
#include <fstream>
#include <map>
#include <vector>
#include <stdlib.h>

#include "export.hpp"
#include "threading.hpp"

namespace DFF
{
  class Node;
  class Search;
};

using namespace DFF;

class Dictionnary;
//class Node;

class IndexedPatterns
{
private:
  EXPORT	IndexedPatterns() :  __nodePatterns(DFF::map<Node*, DFF::vector< uint32_t > >()),
				     __patternNodes(DFF::map<uint32_t, DFF::vector< Node* > >()),
				     __uniq(DFF::map<std::string, uint32_t>()),
				     __idString(DFF::map<uint32_t, std::string>()),
				     __counter(0) {}
  EXPORT	IndexedPatterns(IndexedPatterns&) {}
  EXPORT	~IndexedPatterns() {}
  EXPORT	IndexedPatterns&	operator=(IndexedPatterns&);
  DFF::map<Node*, DFF::vector< uint32_t > >	__nodePatterns;
  DFF::map<uint32_t, DFF::vector< Node* > >	__patternNodes;
  DFF::map<std::string, uint32_t>		__uniq;
  DFF::map<uint32_t, std::string>		__idString;
  uint32_t					__counter;
  
public:
  EXPORT	static IndexedPatterns*	instance()
  {
    static IndexedPatterns __instance;
    return &__instance;
  }
  EXPORT void	addPattern(std::string, Node* node);
  EXPORT std::vector<std::string>	patternsByNode(Node* node);
  EXPORT std::vector<Node*>		nodesByPattern(std::string pattern);
};

class BadPattern
{
public:
  unsigned int	line;
  std::string	pattern;
  std::string	message;
};

class DictRegistry
{
private:
  EXPORT	DictRegistry() {};
  EXPORT	DictRegistry(DictRegistry &) {};
  EXPORT	~DictRegistry() {};
  DictRegistry&	operator=(DictRegistry &);
  std::map<std::string, Dictionnary* >	__dictionnaries;
  typedef std::map<std::string, Dictionnary* >::iterator	dictit;
public:
  EXPORT static DictRegistry*	instance()
  {
    static DictRegistry __instance;
    return &__instance;
  }

  EXPORT void		add(std::string name, Dictionnary* dict) throw (std::string);
  EXPORT void		remove(std::string id) throw (std::string);
  EXPORT Dictionnary*	get(std::string id) throw (std::string);
  EXPORT std::map<std::string, Dictionnary* > dictionnaries();
};


class Dictionnary //: public DEventHandler ??? to notify watchers for compile error and instance reporting and be able to stop compile
{
private:
  std::vector<DFF::Search* >			__cpatterns;
  std::vector<BadPattern* >		__bad_patterns;
  size_t				__cp_pos;
protected:
  void					_addBadPattern(std::string pattern, std::string message, unsigned int line);
  void					_compilePattern(std::string pattern, unsigned int line);
  bool					_compileErrors;
public:
  EXPORT Dictionnary();
  EXPORT virtual				~Dictionnary();
  EXPORT std::vector<BadPattern* >		badPatterns();
  EXPORT DFF::Search*				nextSearchPattern();
  EXPORT void					reset();
  EXPORT virtual void				save(std::string path) throw (std::string) = 0;
  EXPORT virtual std::string			fileName() = 0;
  EXPORT virtual bool				compile() = 0;
};


class FileDictionnary : public Dictionnary
{
private:
  std::fstream	__fdict;
  std::string	__ifile;
  unsigned int	__line_count;
  void		__commitPattern(std::string pattern);
public:
  EXPORT FileDictionnary(std::string ifile);
  EXPORT ~FileDictionnary();
  EXPORT virtual bool		compile();
  EXPORT virtual void		save(std::string path) throw (std::string);
  EXPORT virtual std::string	fileName();  
};

// class BufferDictionnary : public Dictionnary
// {
// private:
//   std::fstream	__fdict;
//   std::string	__ifile;
//   unsigned int	__line_count;
//   void		__commitPattern(std::string pattern);
// public:
//   BufferDictionnary(std::string dname, char* buffer, unsigned int len, bool recordOnCreate=false);
//   ~BufferDictionnary();
//   virtual bool		compile();
//   virtual void		save(std::string path) throw (std::string);
//   virtual std::string	fileName();  
// };

#endif
