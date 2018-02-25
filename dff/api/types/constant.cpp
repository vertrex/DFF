/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2013 ArxSys
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *  
 * See http: www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 * 
 * Author(s):
 *  Frederic B. <fba@digital-forensic.org>
 */


#include "constant.hpp"

namespace DFF
{

Constant::Constant(std::string name, uint8_t type, std::string description)
{
  this->__name = name;
  this->__type = type;
  this->__description = description;
  this->__valueslocked = false;
}

Constant::~Constant()
{
  this->__values.clear();
}

std::string			Constant::name()
{
  return this->__name;
}

std::string			Constant::description()
{
  return this->__description;
}

uint8_t			Constant::type()
{
  return (this->__type);
}

void			Constant::addValues(std::list< Variant_p > values)
{
  if (!this->__valueslocked)
    {
      this->__valueslocked = true;
      this->__values = values;
    }
  else
    return;
}

std::list< Variant_p >		Constant::values()
{
  return this->__values;
}

}
