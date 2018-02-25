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

#include <ios>
#include <iostream>
#include <fstream>
#include <map>
#include <vector>
#include <stdlib.h>
#include "dictionnary.hpp"
#include "search.hpp"
#include "node.hpp"

using namespace DFF;

// LiveIndexer::LiveIndexer() : AttributesHandler("matched patterns")
// {
// }

// LiveIndexer::~LiveIndexer()
// {
// }

// LiveIndexer::addPattern(std::string pattern, Node* node)
// {
// }

// Attributes	LiveIndexer::attributes(Node* node)
// {
// }

void	IndexedPatterns::addPattern(std::string pattern, Node* node)
{
  if (node != NULL)
    {
      uint32_t	id;
      
      id = this->__uniq[pattern];
      if (!id)
	{
	  this->__uniq[pattern] = ++__counter;
	  id = __counter;
	  this->__idString[id] = pattern;
	}
      this->__nodePatterns[node].push_back(id);
      this->__patternNodes[id].push_back(node);
    }
}

std::vector<std::string>	IndexedPatterns::patternsByNode(Node* node)
{
  DFF::vector<uint32_t>		patterns;
  std::vector<std::string>	ret;
  unsigned int			iter;

  if (this->__nodePatterns.exist(node))
    {
      patterns = this->__nodePatterns[node];
      for (iter = 0; iter != patterns.size(); ++iter)
	{
	  ret.push_back(this->__idString[patterns.at(iter)]);
	}
    }
  return ret;
}

std::vector<Node*>	IndexedPatterns::nodesByPattern(std::string pattern)
{
  DFF::vector<Node*>	nodes;
  std::vector<Node*>	ret;
  uint32_t		pid;
  unsigned int		iter;

  if (this->__uniq.exist(pattern))
    {
      pid = this->__uniq[pattern];
      nodes = this->__patternNodes[pid];
      for (iter = 0; iter != nodes.size(); ++iter)
	ret.push_back(nodes[iter]);
    }
  return ret;
}


void		DictRegistry::add(std::string name, Dictionnary* dict) throw (std::string)
{
  if (dict == NULL)
    throw (std::string("provided dictionnary is NULL"));
  else
    {
      if (__dictionnaries.find(name) != __dictionnaries.end())
	throw (std::string(name) + std::string(" already exists in registry"));
      __dictionnaries[name] = dict;
    }
}

void	DictRegistry::remove(std::string id) throw (std::string)
{
  Dictionnary*	dict;
  dictit	it;

  dict = NULL;
  it = __dictionnaries.find(id);
  if (it == __dictionnaries.end())
    throw (std::string(id) + std::string(" does not exist in registry"));
  else
    {
      dict = it->second;
      __dictionnaries.erase(it);
      delete dict;
    }
}

Dictionnary*	DictRegistry::get(std::string id) throw (std::string)
{
  Dictionnary*	dict; 
  dictit it = __dictionnaries.find(id);
  
  dict = NULL;
  if (it == __dictionnaries.end())
    throw (std::string(id) + std::string(" does not exist in registry"));
  else
    dict = it->second;
  return dict;
}


std::map<std::string, Dictionnary* > DictRegistry::dictionnaries()
{
  return this->__dictionnaries;
}

Dictionnary::Dictionnary()
{
  this->__cp_pos = 0;
  this->_compileErrors = false;
}


Dictionnary::~Dictionnary()
{
  std::vector<DFF::Search*>::iterator	sit;
  std::vector<BadPattern*>::iterator	bit;

  try
    {
      for (sit = this->__cpatterns.begin(); sit != this->__cpatterns.end(); sit++)
	delete *sit;
      for (bit = this->__bad_patterns.begin(); bit != this->__bad_patterns.end(); bit++)
	delete *bit;
    }
  catch (std::string)
    {
    }
}


std::vector<BadPattern* > Dictionnary::badPatterns()
{
  return this->__bad_patterns;
}


DFF::Search*			Dictionnary::nextSearchPattern()
{
  DFF::Search*		s;

  s = NULL;
  if (this->__cp_pos < this->__cpatterns.size())
    {
      s = this->__cpatterns[this->__cp_pos];
      this->__cp_pos++;
    }
  return s;
}

void			Dictionnary::reset()
{
  this->__cp_pos = 0;
}

void				Dictionnary::_addBadPattern(std::string pattern, std::string message, unsigned int line)
{
  BadPattern*			bp;

  this->_compileErrors = true;
  bp = new BadPattern();
  bp->line = line;
  bp->pattern = pattern;
  bp->message = message;
  this->__bad_patterns.push_back(bp);  
}


void				Dictionnary::_compilePattern(std::string pattern, unsigned int line)
{
  std::string			err;
  DFF::Search*			s;
  DFF::Search::CaseSensitivity	cs;
  size_t			subend;
  size_t			psize;
  char				cstart;
  char				cend;

  s = NULL;
  psize = pattern.size();
  if (psize <= 1)
    this->_addBadPattern(pattern, std::string("Pattern is too short"), line);
  else
    {
      cstart = pattern.at(0);
      cend = pattern.at(psize-1);
      if (cend == 'i')
  	{
	  if (psize > 3)
	    {
	      cend = pattern.at(pattern.size() - 2);
	      subend = pattern.size() - 3;
	      cs = DFF::Search::CaseInsensitive;
	    }
	  else
	    subend = 0; //volontary set to 0 to fail all case condition
  	}
      else
  	{
  	  subend = pattern.size() - 2;
  	  cs = DFF::Search::CaseInsensitive;
  	}
      switch (cstart)
  	{
  	case '/':
  	  {
  	    if (cend == '/' && subend != 0)
  	      s = new DFF::Search(pattern.substr(1, subend), cs, DFF::Search::Regexp);
  	    else
  	      err = "unterminated regular expression";
  	    break;
  	  }
  	case '~':
  	  {
  	    if (cend == '~' && subend != 0)
  	      s = new DFF::Search(pattern.substr(1, subend), cs, DFF::Search::Fuzzy);
  	    else
  	      err = "unterminated fuzzy expression";
  	    break;
  	  }
  	case '$':
  	  {
  	    if (cend == '$' && subend != 0)
  	      s = new DFF::Search(pattern.substr(1, subend), cs, DFF::Search::Wildcard);
  	    else
  	      err = "unterminated wildcard expression";
  	    break;
  	  }
  	case '"':
  	  {
  	    if (cend == '"' && subend != 0)
  	      s = new DFF::Search(pattern.substr(1, subend), cs, DFF::Search::Fixed);
  	    else
  	      err = "unterminated fixed expression";
  	    break;
  	  }
  	default:
  	  err = "unrecognized pattern type";
  	  break;
  	}
      if (!err.empty())
  	this->_addBadPattern(pattern, err, line);
      else if (s != NULL)
  	{
  	  try
  	    {
  	      s->compile();
  	      this->__cpatterns.push_back(s);
  	    }
  	  catch (std::string e)
  	    {
  	      this->_addBadPattern(pattern, e, line);
  	    }
  	}
      else
  	this->_addBadPattern(pattern, std::string("Error while creating DFF::Search instance"), line);
    }
  if (s != NULL)
    delete s;
}


FileDictionnary::FileDictionnary(std::string ifile)
{
  this->__ifile = ifile;
  this->__line_count = 0;
  this->__fdict.exceptions(std::ifstream::failbit|std::ifstream::badbit);
  try
    {
      this->__fdict.open(ifile.c_str(), std::fstream::in);
    }
  catch (std::ifstream::failure e) 
    {
      throw std::string("FileDictionnary: error while opening file: ") + this->__ifile;
    }
}


FileDictionnary::~FileDictionnary()
{
  this->__fdict.close();
}


void		FileDictionnary::__commitPattern(std::string pattern)
{
  size_t		epos;

  if (!pattern.empty())
    {
      epos = pattern.size() - 1;
      while (epos > 0 && (pattern[epos] == '\t' ||
			  pattern[epos] == '\v' ||
			  pattern[epos] == '\f' ||
			  pattern[epos] == '\r' ||
			  pattern[epos] == ' '))
	--epos;
      this->_compilePattern(pattern.erase(epos+1), this->__line_count);
    }
}

bool		FileDictionnary::compile()
{
  std::string		pattern;
  char			c;

  try
    {
      pattern = "";
      while (this->__fdict.good())
	{
	  this->__fdict.get(c);
	  if (c == '\n')
	    {
	      ++this->__line_count;
	      this->__commitPattern(pattern);
	      pattern.clear();
	    }
	  else if (!pattern.empty() || (c != '\t' && c != '\v' && c != '\f' && c != '\r' &&  c != ' '))
	    {
	      if (pattern.size() < 256)
		pattern += c;
	      else
		{
		  this->_addBadPattern(pattern.substr(0, 10) + "[...]" + pattern.substr(246, 256), std::string("Pattern is too long"), this->__line_count);
		  pattern.clear();
		  while (this->__fdict.good() && this->__fdict.get() != '\n')
		    ;
		  ++this->__line_count;
		}
	    }
	}
    }
  catch (std::ios_base::failure e)
    {
      if (this->__fdict.eof())
	{
	  ++this->__line_count;
	  this->__commitPattern(pattern);
	}
      else
	throw std::string("Error with provided file: ") + e.what();
    }
  return !this->_compileErrors;
}


void		FileDictionnary::save(std::string path) throw (std::string)
{
  throw std::string("Not implemented");
}

std::string	FileDictionnary::fileName()
{
  return this->__ifile;
}
