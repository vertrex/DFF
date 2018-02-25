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

#ifndef __COMMON_HPP__
#define __COMMON_HPP__

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <map>
#include <vector>

#include "search.hpp"
#include "pattern.hpp"
#include "boyer_moore.hpp"

typedef struct	description
{
  pattern	*header;
  pattern	*footer;
  char		*type;
  uint32_t	window;
  bool		aligned;
}		description;

typedef struct		s_context
{
  description		*descr;
  unsigned char		*headerBcs;
  unsigned char		*footerBcs;
  std::vector<uint64_t>	headers;
  std::vector<uint64_t>	footers;
}			context;

#endif
