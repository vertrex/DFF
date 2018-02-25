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

#ifndef __PARTITION_HPP__
#define __PARTITION_HPP__

#include <map>


#include "gpt.hpp"
#include "dos.hpp"

#include <iostream>
#include <iomanip>
#include <sstream>

#include "node.hpp"
#include "mfso.hpp"

class Partition : public DFF::mfso
{
private:
  DFF::Node*		        __parent;
  DFF::Node*		        __root;
  DosPartition*			__dos;
  GptPartition*			__gpt;  
public:
  Partition();
  ~Partition();
  virtual void		start(std::map<std::string, Variant_p > args);
};

class PartitionsNode : public DFF::Node
{
private:
  Partition*	__part;
public:
  PartitionsNode(Partition* fsobj);
  ~PartitionsNode();
  virtual std::string 	icon();
  virtual Attributes	_attributes();
};

#endif
