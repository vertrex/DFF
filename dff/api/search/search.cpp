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

#include "search.hpp"

#include <iostream>
#include <string.h>
#include <sstream>

namespace DFF
{
//#define DEBUGSEARCH 1

Search::Search()
{
  this->__pattern = "";
  this->__compiled = false;
  this->__needtrefree = false;
  this->__cs = CaseSensitive;
  this->__nlen = 512;
  this->__syntax = Fixed;
  this->__count = 0;
  this->__find = NULL;
  this->__rfind = NULL;
#if HAVE_TRE
  memset(&this->__preg, 0, sizeof(this->__preg));
  memset(&this->__aparams, 0, sizeof(this->__aparams));
  this->__aparams.max_err = 3;
  this->__aparams.max_ins = this->__aparams.max_del = this->__aparams.max_subst = 1;
#endif
}

Search::Search(std::string pattern, CaseSensitivity cs, PatternSyntax syntax)
{
  this->__pattern = pattern;
  this->__cs = cs;
  this->__syntax = syntax;
  this->__compiled = false;
  this->__needtrefree = false;
  this->__nlen = 0;
  this->__count = 0;
  this->__find = NULL;
  this->__rfind = NULL;
#if HAVE_TRE
  memset(&this->__preg, 0, sizeof(this->__preg));
  memset(&this->__aparams, 0, sizeof(this->__aparams));
  this->__aparams.max_err = 3;
  this->__aparams.max_ins = this->__aparams.max_del = this->__aparams.max_subst = 1;
#endif
}

Search::~Search()
{
#if HAVE_TRE
  if (this->__needtrefree)
    tre_free(&this->__preg);
#endif
}

void			Search::setPattern(std::string pattern)
{
  this->__compiled = false;
  this->__pattern = pattern;
}
 
std::string		Search::pattern()
{
  return this->__pattern;
}

void			Search::setPatternSyntax(Search::PatternSyntax syntax)
{
#ifndef HAVE_TRE
  if ((syntax == Regexp) || (syntax == Fuzzy))
    std::cout << "not compiled with tre library, search won't provide results" << std::endl;
#endif
  if (this->__syntax != syntax)
    this->__compiled = false;
  this->__syntax = syntax;
}

Search::PatternSyntax	Search::patternSyntax()
{
  return this->__syntax;
}

void			Search::setCaseSensitivity(Search::CaseSensitivity cs)
{
  if (this->__cs != cs)
    this->__compiled = false;
  this->__cs = cs;
}

Search::CaseSensitivity	Search::caseSensitivity()
{
  return this->__cs;
}

uint32_t		Search::needleLength()
{
  return this->__nlen;
}


int32_t			Search::find(char* haystack, uint32_t hslen) throw (std::string)
{
  if (!this->__compiled)
    this->compile();
  if (hslen)
    return (this->*(__find))(haystack, hslen);
  else
    return -1;
}

int32_t			Search::find(std::string haystack) throw (std::string)
{
  if (!this->__compiled)
    this->compile();
  if (haystack.size())
    return (this->*(__find))((char*)haystack.c_str(), haystack.size());
  else
    return -1;
}

int32_t			Search::rfind(char* haystack, uint32_t hslen) throw (std::string)
{
  if (this->__syntax == Regexp || this->__syntax == Fuzzy)
    throw std::string("regexp and fuzzy rfind not supported");
  if (!this->__compiled)
    this->compile();
  if (hslen)
    return (this->*(__rfind))(haystack, hslen);
  else
    return -1;
}

int32_t			Search::rfind(std::string haystack) throw (std::string)
{
  if (this->__syntax == Regexp || this->__syntax == Fuzzy)
    throw std::string("regexp and fuzzy rfind not supported");
  if (!this->__compiled)
    this->compile();
  if (haystack.size())
    return (this->*(__rfind))((char*)haystack.c_str(), haystack.size());
  else
    return -1;
}

int32_t			Search::count(char* haystack, uint32_t hslen, int32_t maxcount) throw (std::string)
{
  if (!this->__compiled)
    this->compile();
  if (hslen)
    return (this->*(__count))(haystack, hslen, maxcount);
  else
    return -1;
}

int32_t			Search::count(std::string haystack, int32_t maxcount) throw (std::string)
{
  if (!this->__compiled)
    this->compile();
  if (haystack.size())
    return (this->*(__count))((char*)haystack.c_str(), haystack.size(), maxcount);
  else
    return -1;
}

void			Search::compile() throw (std::string)
{
  if (this->__pattern == "")
    throw(std::string("pattern not setted"));
  if (this->__syntax == Fixed)
    {
      this->__nlen = this->__pattern.size();
      __find = &Search::__ffind;
      __rfind = &Search::__frfind;
      __count = &Search::__fcount;
    }
  else if (this->__syntax == Wildcard)
    this->__wcompile();
  else if (this->__syntax == Regexp)
    this->__recompile();
  else if (this->__syntax == Fuzzy)
    this->__fzcompile();
  else
    throw std::string("syntax is neither setted nor correct");
  this->__compiled = true;
}


void			Search::__wcompile() throw (std::string)
{
  size_t		i;
  std::string	needle;
  bool		rpattern = false;
  
  this->__nlen = 0;
  needle = "";
  this->__wctxs.clear();
  for (i = 0; i != this->__pattern.size(); i++)
    {
      if ((this->__pattern[i] != '?') && (this->__pattern[i] != '*'))
	{
	  rpattern = true;
	  needle += this->__pattern[i];
	  this->__nlen++;
	}
      else
	{
	  if (this->__pattern[i] != '?')
	    this->__nlen += 1;
	  else if (this->__pattern[i] != '*')
	    this->__nlen += 512;
	  if (needle.size())
	    {
	      this->__wctxs.push_back(needle);
	      needle.clear();
	    }
	  this->__wctxs.push_back(std::string(1, this->__pattern[i]));
	}
    }
  if (needle.size())
    this->__wctxs.push_back(needle);
  if (!rpattern)
    throw (std::string("pattern is not useful, only * and ? provided"));
#ifdef DEBUGSEARCH
  std::cout << "original pattern --> " << this->__pattern;
  std::cout << "compile pattern with max length of: " << this->__nlen;
  for (i = 0; i != this->__wctxs.size(); i++)
    std::cout << std::string(3, ' ') << this->__wctxs[i] << std::endl;
#endif
  __find = &Search::__wfind;
  __rfind = &Search::__wrfind;
  __count = &Search::__wcount;
}

void			Search::__recompile() throw (std::string)
{
#ifdef HAVE_TRE
  int	cflags;
  
  if (this->__needtrefree)
    tre_free(&this->__preg);
  cflags = REG_EXTENDED;
  if (this->__cs == Search::CaseInsensitive)
    cflags |= REG_ICASE;
  if (tre_regncomp(&this->__preg, this->__pattern.c_str(), this->__pattern.size(), cflags) == REG_OK)
    this->__needtrefree = true;
  else
    throw std::string("error while compiling regexp: " + this->__pattern);
  __find = &Search::__refind;
  __rfind = NULL;
  __count = &Search::__recount;
#else
  throw std::string("regexp support not activated (libtre not linked)");
#endif
}

void			Search::__fzcompile() throw (std::string)
{
#ifdef HAVE_TRE
  int	cflags;
  
  if (this->__needtrefree)
    tre_free(&this->__preg);
  cflags = REG_LITERAL;
  if (this->__cs == Search::CaseInsensitive)
    cflags |= REG_ICASE;
  if (tre_regncomp(&this->__preg, this->__pattern.c_str(), this->__pattern.size(), cflags) == REG_OK)
    this->__needtrefree = true;
  else
    throw std::string("error while compiling regexp: " + this->__pattern);
  __find = &Search::__afind;
  __rfind = NULL;
  __count = &Search::__acount;
#else
  throw std::string("fuzzy support not activated (libtre not linked)");
#endif
}


int32_t			Search::__ffind(char* haystack, uint32_t hslen)
{
  if (this->__cs == CaseInsensitive)
    return cifastsearch((unsigned char*)haystack, hslen, (unsigned char*)this->__pattern.c_str(), this->__nlen, 1, FAST_SEARCH);
  else
    return fastsearch((unsigned char*)haystack, hslen, (unsigned char*)this->__pattern.c_str(), this->__nlen, 1, FAST_SEARCH);
}


int32_t			Search::__wfind(char* haystack, uint32_t hslen)
{
  if (this->__cs == CaseSensitive)
    return this->__wfindint((unsigned char*)haystack, hslen, &fastsearch, 0, 0);
  else
    return this->__wfindint((unsigned char*)haystack, hslen, &cifastsearch, 0, 0);
}

int32_t			Search::__wfindint(unsigned char* haystack, uint32_t hslen, sfunc s, size_t vpos, uint32_t window)
{
  std::string	needle;
  uint32_t	rwindow;
  int32_t	idx;
  uint32_t	oidx;

#ifdef DEBUGSEARCH
  std::ostringstream ostr;
#endif
  needle = this->__wctxs[vpos];
  if (needle != "?" && needle != "*")
    {	
      if (vpos == (this->__wctxs.size() - 1))
  	{
	  if ((needle.size() + window) < hslen)
	    rwindow = needle.size() + window;
	  else
	    rwindow = hslen;
#ifdef DEBUGSEARCH
	  ostr << std::string(vpos, '\t') << "vpos: %d / %d -- token: %s -- hslen: %d -- nsize: %d -- haystack: %" << hslen << "s\n";
	  printf(ostr.str().c_str(), vpos, this->__wctxs.size(), needle.c_str(), rwindow, needle.size(), haystack);
#endif
  	  return s((unsigned char*)haystack, rwindow,
  		   (unsigned char*)needle.c_str(), needle.size(),
  		   1, FAST_SEARCH);
  	}
      else
  	{
	  if (hslen == 0)
	    return -1;
  	  idx = -1;
#ifdef DEBUGSEARCH
	  ostr << std::string(vpos, '\t') << "vpos: %d / %d -- token: %s -- hslen: %d -- nsize: %d -- haystack: %" << hslen << "s\n";
	  printf(ostr.str().c_str(), vpos, this->__wctxs.size(), needle.c_str(), hslen, needle.size(), haystack);
#endif
	  oidx = 0;
	  while ((idx = s((unsigned char*)haystack+oidx, hslen-oidx,
			  (unsigned char*)needle.c_str(), needle.size(), 
			  1, FAST_SEARCH)) != -1)
	    {
#ifdef DEBUGSEARCH
	      ostr.str("");
	      ostr << std::string(vpos, '\t') << "%d / %d -- token: %s -- hslen: %d -- nsize: %d -- haystack: %" << hslen-oidx << "s\n";
	      printf(ostr.str().c_str(), vpos, this->__wctxs.size(), needle.c_str(), hslen-oidx, needle.size(), haystack+oidx);
#endif
	      oidx += idx + needle.size();	      
	      if (this->__wfindint(haystack+oidx, hslen-oidx, s, vpos+1, 0) != -1)
		return idx;
	    }
	}
    }
  else
    {
      if (vpos == (this->__wctxs.size() - 1))
  	return 0;
      if (needle == "?")
	rwindow = 1;
      else
	rwindow = 512;
#ifdef DEBUGSEARCH
      ostr << std::string(vpos, '\t') << "vpos: %d / %d -- token: %s -- hslen: %d -- nsize: %d -- haystack: %" << hslen << "s -- %d\n";
      printf(ostr.str().c_str(), vpos, this->__wctxs.size(), needle.c_str(), hslen, needle.size(), haystack, this->__cs);
#endif
      return this->__wfindint(haystack, hslen, s, vpos+1, rwindow);
    }
  //never reached
  return -1;
}


int32_t                        Search::__refind(char* haystack, uint32_t hslen)
{
  int32_t      ret;
  
  ret = -1;
#ifdef HAVE_TRE
  regmatch_t   pmatch[1];
  
  if (tre_regnexec(&this->__preg, haystack, hslen, 1, pmatch, 0) == REG_OK)
    {
      ret = pmatch[0].rm_so;
      this->__nlen = pmatch[0].rm_eo - pmatch[0].rm_so;
    }
  else
    this->__nlen = 512;
#endif
  this->__nlen = 1;
  return ret;
}



int32_t			Search::__afind(char* haystack, uint32_t hslen)
{
  int32_t	ret;

  ret = -1;
#ifdef HAVE_TRE
  regamatch_t	match;
  regmatch_t	pmatch[1];
  regaparams_t	params;

  params.max_err = 3;
  params.max_cost = INT32_MAX;
  params.cost_ins = INT32_MAX;
  params.cost_subst = INT32_MAX;
  params.cost_del = INT32_MAX;
  params.max_subst = INT32_MAX;
  params.max_del = INT32_MAX;
  params.max_ins = INT32_MAX;
  memset(&match, 0, sizeof(match));
  match.pmatch = pmatch;
  match.nmatch = 1;
  if (tre_reganexec(&this->__preg, haystack, hslen, &match, params, 0) == REG_OK)
    {
      ret = match.pmatch[0].rm_so;
      this->__nlen = match.pmatch[0].rm_eo - match.pmatch[0].rm_so;
      // std::cout << std::string(42, '=') << std::endl;
      // std::cout << std::string(haystack+ret, this->__nlen) << std::endl;
      // std::cout << "match cost ------> " << match.cost << std::endl;
      // std::cout << "num_ins ---------> " << match.num_ins << std::endl;
      // std::cout << "num_del ---------> " << match.num_del << std::endl;
      // std::cout << "num_subst -------> " << match.num_subst << std::endl;
      // std::cout << std::string(42, '=') << std::endl;
    }
  else
    {
      //Current implementation only provide support for fixed litteral. If the
      //provided string described a regexp, it won't be interpreted.
      //Since max_err is set to 3, maximum needle len (when there's no match) can
      //be 3 insertion so this->__pattern.size() + 3
      //Further implementation would let user to custom its weigth and regexp will
      //be enable though changing needle length at each round.
      //this->__nlen = this->__pattern.size() + 3;
    }
#endif
  this->__nlen = 1;
  return ret;
}


int32_t			Search::__frfind(char* haystack, uint32_t hslen)
{
  if (this->__cs == CaseInsensitive)
    return cifastsearch((unsigned char*)haystack, hslen, (unsigned char*)this->__pattern.c_str(), this->__nlen, 1, FAST_RSEARCH);
  else
    return fastsearch((unsigned char*)haystack, hslen, (unsigned char*)this->__pattern.c_str(), this->__nlen, 1, FAST_RSEARCH);
}
 
 
int32_t			Search::__wrfind(char* haystack, uint32_t hslen)
{
  // std::vector<std::string*>::iterator	it, sit;
  // int32_t				buffpos;
  // int32_t				sidx;
  // int32_t				idx;
  // uint32_t				skip;
  // int32_t				(*sfunc)(const unsigned char*, int32_t,
  // 						 const unsigned char*, int32_t,
  // 						 int32_t, int);

  // if (this->__cs == CaseSensitive)
  //   sfunc = &fastsearch;
  // else
  //   sfunc = &cifastsearch;
  // it = this->__wctxs.end() - 1;
  // skip = 0;
  // while (it != this->__wctxs.begin())
  //   {
  //     if (*(*it) == "?")
  // 	skip = 1;
  //     else if (*(*it) == "*")
  // 	skip = 512;
  //     else
  // 	{
  // 	  sit = it;
  // 	  break;
  // 	}
  //     it--;
  //   }
  // buffpos = hslen;
  // while ((buffpos > 0))
  //   {
  //     DEBUG(INFO, "   buffpos: %d -- sidx: %d\n", buffpos, sidx);
  //     for (it = sit; it != this->__wctxs.begin(); it--)
  // 	{
  // 	  if (*(*it) == "?")
  // 	    {
  // 	      DEBUG(INFO, "    setting skip to 1\n");
  // 	      if (buffpos >= 1)
  // 		buffpos -= 1;
  // 	      else
  // 		buffpos = 0;
  // 	      skip = 1;
  // 	    }
  // 	  else if (*(*it) == "*")
  // 	    {
  // 	      DEBUG(INFO, "   setting skip to 512\n");
  // 	      if (buffpos >= 512)
  // 		buffpos -= 512;
  // 	      else
  // 		buffpos = 0;
  // 	      skip = 512;
  // 	    }
  // 	  else
  // 	    {
  // 	      uint32_t size = (*it)->size();
  // 	      uint32_t curhlen = 0;
  // 	      if (buffpos < size + skip)
  // 		buffpos = 0;
  // 	      else
  // 		buffpos -= (size + skip);
  // 	      if (hslen < buffpos + size + skip)
  // 		curhlen = hslen - buffpos;
  // 	      else
  // 		curhlen = size + skip;
  // 	      DEBUG(INFO, "   searching needle %s -- needle size %d -- buffpos: %d -- skip: %d -- haystack length: %d\n", 
  // 		    (*it)->c_str(), size, buffpos, skip, curhlen);
  // 	      if ((idx = sfunc((unsigned char*)(haystack+buffpos), curhlen,
  // 			       (unsigned char*)((*it)->c_str()), size,
  // 			       1, FAST_RSEARCH)) == -1)
  // 		{
  // 		  DEBUG(INFO, "   no match found\n");
  // 		  return -1;
  // 		}
  // 	      else
  // 		skip = 0;
  // 	    }
  // 	}
  //     DEBUG(INFO, "OUT OF LOOP -- buffpos: %d\n", buffpos);
  //     DEBUG(INFO, "wctx.begin() --> %s\n", (*it)->c_str());
  //     if (it == this->__wctxs.begin())
  // 	{
  // 	  if (*(*it) == "?")
  // 	    {
  // 	      if (buffpos >= 1)
  // 		return buffpos - 1;
  // 	      else
  // 		return buffpos;
  // 	    }
  // 	  else if (*(*it) == "*")
  // 	    {
  // 	      if (buffpos >= 512)
  // 		return buffpos - 512;
  // 	      else
  // 		return 0;
  // 	    }
  // 	  else
  // 	    {
  // 	      int32_t	ret;
  // 	      if (hslen < (skip + (*it)->size()))
  // 		buffpos = 0;
  // 	      else
  // 		buffpos = hslen - (skip + (*it)->size());
  // 	      DEBUG(INFO, "First pattern is last of context %s\n", (*it)->c_str());
  // 	      ret = sfunc((unsigned char*)(haystack+buffpos), skip+(*it)->size(),
  // 			  (unsigned char*)((*it)->c_str()), (*it)->size(),
  // 			  1, FAST_RSEARCH);
  // 	      if (ret != -1)
  // 		return buffpos + ret;
  // 	      else
  // 		return -1;
  // 	    }
  // 	}
  //   }
  return -1;
}

int32_t			Search::__fcount(char* haystack, uint32_t hslen, int32_t maxcount)
{
  if (this->__cs == CaseInsensitive)
    return cifastsearch((unsigned char*)haystack, hslen, (unsigned char*)this->__pattern.c_str(), this->__nlen, maxcount, FAST_COUNT);
  else
    return fastsearch((unsigned char*)haystack, hslen, (unsigned char*)this->__pattern.c_str(), this->__nlen, maxcount, FAST_COUNT);
}

int32_t			Search::__wcount(char* haystack, uint32_t hslen, int32_t maxcount)
{
  int32_t	ret;
  int32_t	count;
  int32_t	pos;
  sfunc		s;

  count = 0;
  ret = 0;
  pos = 0;
  if (this->__cs == CaseSensitive)
    s = &fastsearch;
  else
    s = &cifastsearch;
  while (ret != -1)
    {
      ret = this->__wfind(haystack+pos, hslen-pos);
      pos += ret;
      count++;
    }
  return count;
}

int32_t			Search::__recount(char* haystack, uint32_t hslen, int32_t maxcount)
{
  int32_t	hpos;
  int32_t	count;

  count = 0;
  hpos = 0;
#ifdef HAVE_TRE
  regmatch_t   pmatch[1];
  
  this->__nlen = 512;
  while ((maxcount > 0) && (hpos < hslen) && (tre_regnexec(&this->__preg, haystack+hpos, hslen-hpos, 1, pmatch, 0) == REG_OK))
    {
      hpos += pmatch[0].rm_eo;
      this->__nlen = hslen-hpos;
      count++;
      maxcount--;
    }
#endif
  return count;
}

int32_t			Search::__acount(char* haystack, uint32_t hslen, int32_t maxcount)
{
  int32_t	hpos;
  int32_t	count;

  count = 0;
  hpos = 0;
#ifdef HAVE_TRE
  regmatch_t   pmatch[1];
  
  this->__nlen = 512;
  while ((maxcount > 0) && (hpos < hslen) && (tre_regnexec(&this->__preg, haystack+hpos, hslen-hpos, 1, pmatch, 0) == REG_OK))
    {
      hpos += pmatch[0].rm_eo;
      this->__nlen = hslen-hpos;
      count++;
      maxcount--;
    }
#endif
  return count;
}


FastSearch::FastSearch()//: SearchAlgorithm()
{
}

FastSearch::~FastSearch()
{
}

int32_t		FastSearch::find(unsigned char* haystack, uint32_t hslen, unsigned char* needle, uint32_t ndlen, unsigned char wildcard)
{
  if (wildcard == '\0')
    return fastsearch(haystack, hslen, needle, ndlen, 1, FAST_SEARCH);
  else
    {
      if (fastsearch(needle, ndlen, &wildcard, 1, 1, FAST_SEARCH) == -1)
	return fastsearch(haystack, hslen, needle, ndlen, 1, FAST_SEARCH);
      else
	return wfastsearch(haystack, hslen, needle, ndlen, wildcard, 1, FAST_SEARCH);
    }
}


int32_t		FastSearch::rfind(unsigned char* haystack, uint32_t hslen, unsigned char* needle, uint32_t ndlen, unsigned char wildcard)
{
  if (wildcard == '\0')
    return fastsearch(haystack, hslen, needle, ndlen, 1, FAST_RSEARCH);
  else
    {
      if (fastsearch(needle, ndlen, &wildcard, 1, 1, FAST_SEARCH) == -1)
	return fastsearch(haystack, hslen, needle, ndlen, 1, FAST_RSEARCH);
      else
	return wfastsearch(haystack, hslen, needle, ndlen, wildcard, 1, FAST_RSEARCH);
    }
}


int32_t       FastSearch::count(unsigned char* haystack, uint32_t hslen, unsigned char* needle, uint32_t ndlen, unsigned char wildcard, int32_t maxcount)
{
  if (wildcard == '\0')
    return fastsearch(haystack, hslen, needle, ndlen, maxcount, FAST_COUNT);
  else
    {
      if (fastsearch(needle, ndlen, &wildcard, 1, 1, FAST_SEARCH) == -1)
	return fastsearch(haystack, hslen, needle, ndlen, maxcount, FAST_COUNT);
      else
	return wfastsearch(haystack, hslen, needle, ndlen, wildcard, maxcount, FAST_COUNT);
    }
}

}
