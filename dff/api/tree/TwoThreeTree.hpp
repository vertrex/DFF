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
 *  Romain Bertholon <rbe@digital-forensic.org>
 */

#ifndef __TWOTHREETREE_HPP__
#define __TWOTHREETREE_HPP__
#ifndef WIN32
	#include <stdint.h>
#elif _MSC_VER >= 1600
	#include <stdint.h>
#else
	#include "wstdint.h"
#endif
#include "export.hpp"
//XXX #include <stddef.h>
#include <string>
#include <vector>

namespace DFF
{

class TwoThreeTree
{

public:
  typedef struct
  {
    uint64_t	lhs;
    uint64_t	rhs;
  }		elem;

  EXPORT	TwoThreeTree();
  EXPORT	~TwoThreeTree();

  EXPORT	bool			insert(uint64_t val);
  EXPORT	bool			exists(uint64_t val);
  EXPORT	bool			find(uint64_t val);
  EXPORT	bool			remove(uint64_t val);
  EXPORT	void			dump();
  EXPORT	void			clear();
  EXPORT	bool			empty();

private:
  std::vector<elem* >	__elems;
  uint32_t	__bsearch(uint64_t offset, uint64_t lbound, uint64_t rbound, bool* found);
  elem*		__allocElem(uint64_t lhs, uint64_t rhs);
  void		__firstIdxInsert(uint64_t val);
  void		__betweenIdxInsert(uint64_t val, uint32_t idx);
  void		__lastIdxInsert(uint64_t val);
  void		__insert(uint64_t val, uint32_t lidx, uint32_t ridx);
};

}
#endif
