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

#ifndef __TWOTHREENODE_HPP__
#define __TWOTHREENODE_HPP__

#define TWO_NODE	(true)
#define THREE_NODE	(false)

#include "export.hpp"
#include <stdlib.h>
#if (defined(WIN64) || defined(WIN32))
	#if _MSC_VER >= 1600
		#include <stdint.h>
	#else
		#include "wstdint.h"
	#endif
#else
#include <stdint.h>
#endif
#include <sstream>

namespace DFF
{

class TwoThreeNode
{
public:
  TwoThreeNode(uint32_t val, TwoThreeNode *);
   TwoThreeNode(uint32_t lval, uint32_t rval, TwoThreeNode * node);
  ~TwoThreeNode();

  void			setLeftChild(class TwoThreeNode* lchild);
  void			setMiddleChild(class TwoThreeNode* mchild);
  void			setRightChild(class TwoThreeNode* rchild);
  class TwoThreeNode*	leftChild();
  class TwoThreeNode*	middleChild();
  class TwoThreeNode*	rightChild();

  void			setLeftVal(uint32_t lval);
  void			setRightVal(uint32_t rval);
  uint32_t		val();
  uint32_t		leftVal();
  uint32_t		rightVal();

  bool			isTwoNode();
  void			setNodeType(bool node_type);

  void			toThreeNode();
  void			toThreeNode(uint32_t val);

  void			setParent(class TwoThreeNode* parent);
  class TwoThreeNode*	parent();

  bool			isLeaf();


private:
  class TwoThreeNode*	__parent;

  class TwoThreeNode*	__lchild;
  class TwoThreeNode*	__mchild;
  class TwoThreeNode*	__rchild;

  uint32_t		__lval;
  uint32_t		__rval;

  bool			__twonode;
};

}
#endif
