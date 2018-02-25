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

#include <stdio.h>
#include <iostream>

#include "TwoThreeTree.hpp"

#ifdef TWO_THREE_TREE_DEBUG
   #if (!defined(WIN64) && !defined(WIN32))
       #define DEBUG(str, args...) printf(str, ##args);
   #else
       #define DEBUG(str, ...) printf(str, __VA_ARGS__);
   #endif

   #define DEBUG_START(val) std::cout << "STATE BEFORE INSERTING " << val << std::endl; \
 this->dump()
   #define DEBUG_END(val)  std::cout << "STATE AFTER INSERTING " << val << std::endl; \
 this->dump();								\
 std::cout  << std::endl
#else
    #if (!defined(WIN64) && !defined(WIN32))
       #define DEBUG(str, args...)
    #else
       #define DEBUG(str, ...)
    #endif
    #define DEBUG_START(val)
    #define DEBUG_END(val)
#endif

namespace DFF
{

TwoThreeTree::TwoThreeTree()
{
}

TwoThreeTree::~TwoThreeTree()
{
}

uint32_t	TwoThreeTree::__bsearch(uint64_t val, uint64_t lbound, uint64_t rbound, bool* found)
{
  uint32_t		mbound;

  if (rbound < lbound)
    return rbound;
  mbound = (rbound + lbound) / 2;
  if (val < this->__elems[mbound]->lhs)
    {
      if (mbound > 0)
	return this->__bsearch(val, lbound, mbound - 1, found);
      else
	return 0;
    }
  else if (val > this->__elems[mbound]->rhs)
    return this->__bsearch(val, mbound + 1, rbound, found);
  else
    {
      *found = true;
      return mbound;
    }  
}

void	TwoThreeTree::clear()
{
}


TwoThreeTree::elem*		TwoThreeTree::__allocElem(uint64_t lhs, uint64_t rhs)
{
  elem*		e;

  e = new elem;
  e->lhs = lhs;
  e->rhs = rhs;
  return e;
}

void		TwoThreeTree::__insert(uint64_t val, uint32_t lidx, uint32_t ridx)
{
  elem*		lbound;
  elem*		rbound;
  elem*		e;

  lbound = this->__elems[lidx];
  rbound = this->__elems[ridx];
  DEBUG("   disambiguation to insert %llu between (%lu - %lu) and (%lu - %lu)\n", val, lbound->lhs, lbound->rhs, rbound->lhs, rbound->rhs)
  if (lbound->rhs + 1 < val)
    {
      DEBUG("   lbound->rhs + 1 < val\n");
      if (val == rbound->lhs - 1)
	{
	  DEBUG("   val == rbound->lhs - 1\n");
	  rbound->lhs = val;
	}
      else
	{
	  DEBUG("   alloc + insert after ridx");
	  e = this->__allocElem(val, val);
	  this->__elems.insert(this->__elems.begin()+ridx, e);
	}
    }
  else if (val == rbound->lhs - 1)
    {
      DEBUG("   val == rbound->lhs -1 update lbound->rhs to rbound->rhs and remove rbound\n");
      lbound->rhs = rbound->rhs;
      this->__elems.erase(this->__elems.begin() + ridx);
      delete rbound;
    }
  else
    {
      DEBUG("   update lbound->rhs\n");
      lbound->rhs = val;
    }
}

bool		TwoThreeTree::insert(uint64_t val)
{
  uint32_t			idx;
  elem				*e;
  elem				*tmp;
  bool				found;
  bool				inserted;
  
  found = false;
  inserted = true;
  DEBUG_START(val);  
  if (this->__elems.size() == 0)
    {
      DEBUG(" First insertion with %llu\n", val);
      e = this->__allocElem(val, val);
      this->__elems.push_back(e);
    }
  else if (this->__elems.size() == 1)
    {
      DEBUG(" One element exists, inserting with %llu\n", val);
      tmp = this->__elems[0];
      // First check if val is not allocated
      if (val < tmp->lhs || val > tmp->rhs)
	{
	  // Then test if we can merge
	  if (val == tmp->lhs - 1)
	    {
	      DEBUG("   val == tmp->lhs - 1\n");
	      tmp->lhs = val;
	    }
	  else if (val == tmp->rhs + 1)
	    {
	      tmp->rhs = val;
	      DEBUG("   val == tmp->rhs + 1\n");
	    }
	  // otherwise where to insert val
	  else
	    {
	      DEBUG("   inserting val ");
	      e = this->__allocElem(val, val);
	      if (val < tmp->lhs)
		{
		  this->__elems.insert(this->__elems.begin(), e);
		  DEBUG("before\n");
		}
	      else
		{
		  this->__elems.push_back(e);
		  DEBUG("after\n");
		}
	    }
	}
      else
	{
	  DEBUG("   value already existed");
	  inserted = false;
	}
    }
  else
    {
      // More than one elem, binary search to find where to insert or if already existing
      idx = this->__bsearch(val, 0, this->__elems.size() - 1, &found);
      if (!found)
	{
	  if (idx == 0)
	    {	      
	      DEBUG(" size > 1 and idx == 0\n");
	      if (val == this->__elems[idx]->lhs - 1)
		{
		  DEBUG("   val = lhs - 1\n");
		  this->__elems[idx]->lhs = val;
		}
	      else if (val < this->__elems[idx]->lhs)
		{
		  DEBUG("   val < lhs (inserting front)\n");
		  e = this->__allocElem(val, val);
		  this->__elems.insert(this->__elems.begin(), e);		 
		}
	      else
		{
		  DEBUG("   need insertion choice betwen indexes: %lu and %lu ", idx, idx+1);
		  this->__insert(val, idx, idx+1);
		}
	    }
	  else if (idx == (this->__elems.size() - 1))
	    {
	      DEBUG(" size > 1 and idx = size - 1");
	      if (val == (this->__elems[idx]->rhs + 1))
		{
		  DEBUG("   val == rhs + 1");
		  this->__elems[idx]->rhs = val;
		}
	      else if (val > this->__elems[idx]->rhs)
		{
		  DEBUG("   val > rhs (inserting back)");
		  e = this->__allocElem(val, val);
		  this->__elems.push_back(e);
		}
	      else
		{
		  DEBUG("   need insertion choice between indexes: %lu and %lu", idx-1, idx);
		  this->__insert(val, idx-1, idx);
		}
	    }
	  else
	    {
	      DEBUG(" size > 1 inserting between");
	      if (val < this->__elems[idx]->lhs)
		{
		  DEBUG("   val < this->__elems[idx]->lhs -- %llu < %llu", val, this->__elems[idx]->lhs);
		  this->__insert(val, idx-1, idx);
		}
	      else
		{
		  DEBUG("   val > this->__elems[idx]->lhs -- %llu > %llu", val, this->__elems[idx]->lhs);
		  this->__insert(val, idx, idx+1);
		}
	    }
	}
      else
	inserted = false;
    }
  DEBUG_END(val);
  return inserted;
}

bool	TwoThreeTree::find(uint64_t val)
{
  return this->exists(val);
}

bool	TwoThreeTree::exists(uint64_t val)
{
  //uint32_t	idx;
  bool		found;

  found = false;
  if (this->__elems.size() == 0)
    found = false;
  else if (this->__elems.size() == 1)
    {
      if (val >= this->__elems[0]->lhs && val <= this->__elems[0]->rhs)
	found = true;
    }
  else
     this->__bsearch(val, 0, this->__elems.size() - 1, &found);
  return found;
}

bool	TwoThreeTree::remove(uint64_t val)
{
  return false;
}

bool	TwoThreeTree::empty()
{
  return this->__elems.size() == 0;
}

void	TwoThreeTree::dump()
{
  std::vector<elem*>::iterator	it;

  for (it = this->__elems.begin(); it != this->__elems.end(); ++it)
    std::cout << (*it)->lhs << "-" << (*it)->rhs << ", "; 
  std::cout << std::endl;
}

}
