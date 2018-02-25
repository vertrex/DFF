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

#ifndef __SEARCH_HPP__
#define __SEARCH_HPP__

#ifndef WIN32
#include <stdint.h>
#else
  #if _MSC_VER >= 1600
     #include <stdint.h>
  #else
     #include "wstdint.h"
  #endif
#endif
#include <stdio.h>
#include <cstdio>
#include <string>
#include <list>
#include <vector>
#include "export.hpp"

#include "fastsearch.hpp"
#ifdef HAVE_TRE
  #include "tre.h"
  #ifdef WIN32
     #undef HAVE_ALLOCA
     #undef HAVE_ALLOCA_H
     #define tre_free tre_regfree;
  #else
     #ifdef __cplusplus
     extern "C" {
     #endif
        extern void tre_free(regex_t *preg);
     #ifdef __cplusplus
		}
     #endif
  #endif
#endif

namespace DFF
{

class FastSearch
{
public:
  EXPORT FastSearch();
  EXPORT virtual ~FastSearch();
  EXPORT virtual int32_t	find(unsigned char* haystack, uint32_t hslen, unsigned char* needle, uint32_t ndlen, unsigned char wildcard='\0');
  EXPORT virtual int32_t	rfind(unsigned char* haystack, uint32_t hslen, unsigned char* needle, uint32_t ndlen, unsigned char wildcard='\0');
  EXPORT virtual int32_t       count(unsigned char* haystack, uint32_t hslen, unsigned char* needle, uint32_t ndlen, unsigned char wildcard='\0', int32_t maxcount=-1);
};


typedef int32_t	(*sfunc)(const unsigned char*, int32_t, const unsigned char*, int32_t, int32_t, int);

class Search
{
public:
  enum PatternSyntax
    {
      Fixed = 0,
      Wildcard = 1,
      Regexp = 2,
      Fuzzy = 3
    };
  enum CaseSensitivity
    {
      CaseInsensitive = 0,
      CaseSensitive = 1
    };
  EXPORT Search();
  EXPORT Search(std::string pattern, CaseSensitivity cs = CaseSensitive, PatternSyntax syntax = Fixed);
  EXPORT ~Search();
  EXPORT uint32_t		needleLength();
  EXPORT void			setPattern(std::string pattern);
  EXPORT std::string		pattern();
  EXPORT void			setPatternSyntax(PatternSyntax syntax);
  EXPORT PatternSyntax		patternSyntax();
  EXPORT void			setCaseSensitivity(CaseSensitivity cs);
  EXPORT CaseSensitivity	caseSensitivity();
  //void			setFuzzyWeight();
  EXPORT int32_t		find(char* haystack, uint32_t hslen) throw (std::string);
  EXPORT int32_t		find(std::string haystack) throw (std::string);
  EXPORT int32_t		rfind(char* haystack, uint32_t hslen) throw (std::string);
  EXPORT int32_t		rfind(std::string haystack) throw (std::string);
  EXPORT int32_t		count(char* haystack, uint32_t hslen, int32_t maxcount=-1) throw (std::string);
  EXPORT int32_t		count(std::string haystack, int32_t maxcount=-1) throw (std::string);
  EXPORT void			compile() throw (std::string);
  // std::vector<uint32_t>	indexes(char* haystack, uint32_t hslen) throw (std::string);
  // std::vector<uint32_t>	indexes(std::string haystack) throw (std::string);
private:
#ifdef HAVE_TRE
  regex_t			__preg;
  regaparams_t			__aparams;
#endif
  std::vector<std::string>	__wctxs;
  std::string			__pattern;
  CaseSensitivity		__cs;
  PatternSyntax			__syntax;
  bool				__compiled;
  bool				__needtrefree;
  uint32_t			__nlen;

  typedef int32_t (Search::*findptr)(char* haystack, uint32_t hslen);
  typedef int32_t (Search::*rfindptr)(char* haystack, uint32_t hslen);
  typedef int32_t (Search::*countptr)(char* haystack, uint32_t hslen, int32_t maxcount);

  findptr			__find;
  rfindptr			__rfind;
  countptr			__count;

  //compile methods
  void					__wcompile() throw (std::string);
  void					__recompile() throw (std::string);
  void					__fzcompile() throw (std::string);

  //find methods implementation
  EXPORT int32_t			__ffind(char* haystack, uint32_t hslen);
  EXPORT int32_t			__wfind(char* haystack, uint32_t hslen);
  EXPORT int32_t			__wfindint(unsigned char* haystack, uint32_t hslen, sfunc s, size_t vpos, uint32_t window);
  EXPORT int32_t			__refind(char* haystack, uint32_t hslen);
  EXPORT int32_t			__afind(char* haystack, uint32_t hslen);

  //rfind methods implementation
  EXPORT int32_t			__frfind(char* haystack, uint32_t hslen);
  EXPORT int32_t			__wrfind(char* haystack, uint32_t hslen);
  
  //count methods implementation
  EXPORT int32_t			__fcount(char* haystack, uint32_t hslen, int32_t maxcount);
  EXPORT int32_t			__wcount(char* haystack, uint32_t hslen, int32_t maxcount);
  EXPORT int32_t			__recount(char* haystack, uint32_t hslen, int32_t maxcount);
  EXPORT int32_t			__acount(char* haystack, uint32_t hslen, int32_t maxcount);
};

}
#endif
