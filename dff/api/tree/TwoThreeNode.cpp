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

#include "TwoThreeNode.hpp"

namespace DFF
{

TwoThreeNode::TwoThreeNode(uint32_t val, TwoThreeNode * node)
{
  this->__lval = val;
  this->__twonode = true;

  this->__parent = node;
  this->__lchild = NULL;
  this->__mchild = NULL;
  this->__rchild = NULL;
  this->__rval = 0;
}

TwoThreeNode::TwoThreeNode(uint32_t lval, uint32_t rval, TwoThreeNode * node)
{
  if (lval > rval)
    {
      this->__rval = lval;
      this->__lval = rval;
    }
  else
    {
      this->__lval = lval;
      this->__rval = rval;
    }
  this->__twonode = false;
  this->__parent = node;
  this->__lchild = NULL;
  this->__mchild = NULL;
  this->__rchild = NULL;
}

TwoThreeNode::~TwoThreeNode()
{
}

void	TwoThreeNode::toThreeNode()
{
  this->__twonode = false;
}

void		TwoThreeNode::setLeftChild(class TwoThreeNode* lchild)
{
  this->__lchild = lchild;
  if (this->__lchild != NULL)
    this->__lchild->setParent(this);
}

void		TwoThreeNode::setMiddleChild(class TwoThreeNode* mchild)
{
  this->__mchild = mchild;
  if (this->__mchild != NULL)
    this->__mchild->setParent(this);
}

void		TwoThreeNode::setRightChild(class TwoThreeNode* rchild)
{
  this->__rchild = rchild;
  if (this->__rchild != NULL)
    this->__rchild->setParent(this);
}

TwoThreeNode*	TwoThreeNode::leftChild()
{
  return this->__lchild;
}

TwoThreeNode*	TwoThreeNode::middleChild()
{
  return this->__mchild;
}

TwoThreeNode*	TwoThreeNode::rightChild()
{
  return this->__rchild;
}

void		TwoThreeNode::setLeftVal(uint32_t lval)
{
  this->__lval = lval;
}

void		TwoThreeNode::setRightVal(uint32_t rval)
{
  this->__rval = rval;
}

uint32_t	TwoThreeNode::leftVal()
{
  return this->__lval;
}

uint32_t	TwoThreeNode::rightVal()
{
  return this->__rval;
}

void		TwoThreeNode::toThreeNode(uint32_t val)
{
  if (val < this->__lval)
    {
      this->__rval = this->__lval;
      this->__lval = val;
    }
  else
    this->__rval = val;
  this->__twonode = false;
}

bool		TwoThreeNode::isTwoNode()
{
  return this->__twonode;
}

void		TwoThreeNode::setNodeType(bool node_type)
{
  this->__twonode = node_type;
}

void		TwoThreeNode::setParent(class TwoThreeNode* parent)
{
  this->__parent = parent;
}

TwoThreeNode*	TwoThreeNode::parent()
{
  return this->__parent;
}

bool	TwoThreeNode::isLeaf()
{
  return ((this->__lchild == NULL) && (this->__rchild == NULL)
	  && (this->__mchild == NULL));
}

}
