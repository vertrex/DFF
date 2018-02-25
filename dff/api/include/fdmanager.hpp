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

#ifndef __FDMANAGER_HPP__
#define __FDMANAGER_HPP__

#ifndef WIN32
	#include <stdint.h>
#elif _MSC_VER >= 1600
	#include <stdint.h>
#else
	#include "wstdint.h"
#endif

#include "export.hpp"
#include "exceptions.hpp"
#include "filemapping.hpp"

#include <vector>
#include <iostream>

namespace DFF
{

class fdinfo
{
public:
  class Node*		node;
  class Variant*	id;
  uint64_t		offset;
  class VFile*	        file;
};

class FdManager
{
private:
  	    mutex_def(__mutex);
  uint32_t		allocated;
  std::vector<fdinfo*>	fds;
public:
  EXPORT FdManager();
  EXPORT ~FdManager();
  EXPORT fdinfo*	get(int32_t fd);
  EXPORT void		remove(int32_t fd);
  EXPORT int32_t	push(fdinfo* fi);
};

}
#endif
