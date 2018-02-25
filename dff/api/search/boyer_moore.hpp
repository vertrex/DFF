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

#ifndef __BOYER_MORE_HPP__
#define __BOYER_MORE_HPP__

#define HAYSTACKLEN 10*1024*1024

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <list>
#include "export.hpp"
#include "pattern.hpp"

#ifndef UCHAR_MAX
  #define UCHAR_MAX 255
#endif

namespace DFF
{

typedef struct	s_bmContext
{
  unsigned char* bcs;
  unsigned int	 len;
  unsigned char* needle;
  unsigned char	 wildcard;
  unsigned int	 window;
  unsigned int	 count;
}		bmContext;

class BoyerMoore
{
 private:
  unsigned char*                needle;
  unsigned char		        wildcard;
  unsigned int		        needleSize;
  unsigned char*                bcs;
  bool			        debug;

  bool			        computeBcs();
  unsigned int		        charMatch(unsigned char c1, unsigned char c2);
  unsigned int		        charMatch(unsigned char c1, unsigned char c2, unsigned char w);
 public:
  EXPORT				        BoyerMoore();
  EXPORT				        BoyerMoore(unsigned char *needle, unsigned int needlesize, unsigned char wildcard);
  EXPORT				        ~BoyerMoore();

  EXPORT virtual std::list<unsigned int>	*search(unsigned char *haystack, unsigned int hslen, unsigned int *count);
  EXPORT virtual std::list<unsigned int>	*search(unsigned char *haystack, unsigned int hslen);
  EXPORT unsigned char*                         generateBcs(pattern *p);
  EXPORT int				        search(unsigned char *haystack, unsigned int len, pattern *p, unsigned char *bcs, bool debug=false);
  EXPORT virtual bool			        preprocess();
  EXPORT virtual bool			        setNeedle(unsigned char *needle);
  EXPORT virtual bool			        setNeedleSize(unsigned int size);
  EXPORT virtual bool			        setWildcard(unsigned char wildcard);
  EXPORT virtual unsigned char*                 getNeedle();
  EXPORT virtual unsigned char		        getWildcard();
};

}
#endif
