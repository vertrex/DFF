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


#include "argument.hpp"

namespace DFF
{

Argument::Argument(std::string name, uint16_t flags, std::string description)
{
  this->__name = name;
  this->__flags = flags;
  this->__description = description;
  this->__paramslocked = false;
  if ((flags & 0x0300) == Argument::List)
    this->__minparams = 1;
  else
    this->__minparams = -1;
  this->__maxparams = -1;
  this->setParametersType(Parameter::Editable);
}

Argument::~Argument()
{
  std::list<Argument*>::iterator	ait;

  this->__parameters.clear();
  for (ait = this->__subarguments.begin(); ait != this->__subarguments.end(); ait++)
      delete (*ait);
  this->__subarguments.clear();
}

std::string			Argument::name()
{
  return this->__name;
}


uint16_t			Argument::flags()
{
  return this->__flags;
}


std::string			Argument::description()
{
  return this->__description;
}

// void				Argument::setType(uint16_t type)
// {
//   this->__flags = (this->__flags&0xFF00)|(type&0x00FF);
// }

uint16_t			Argument::type()
{
  return (this->__flags & TYPEMASK);
}

// void				Argument::setInputType(uint16_t itype)
// {
//   this->__flags = (this->__flags&0xFCFF)|(itype&0x0300);
// }

uint16_t			Argument::inputType()
{
  return (this->__flags & 0x0300);
}


void				Argument::setParametersType(uint16_t ptype)
{
  this->__flags = (this->__flags&0x0FFF)|(ptype&0xF000);
}

uint16_t			Argument::parametersType()
{
  return (this->__flags & 0xF000);
}

// void				Argument::setRequirementType(uint16_t ntype)
// {
//   this->__flags = (this->__flags&0xF3FF)|(ntype&0x0C00);
// }

uint16_t			Argument::requirementType()
{
  return (this->__flags & 0x0c00);
}

void				Argument::addSubArgument(Argument* arg)
{
  this->__subarguments.push_back(arg);
}

void				Argument::addParameters(std::list< Variant_p > params, uint16_t type, int32_t min, int32_t max)
{
  if (!this->__paramslocked)
    {
      this->__minparams = min;
      this->__maxparams = max;
      this->__paramslocked = true;
      this->setParametersType(type);
      this->__parameters = params; 
    }
  else
    return;
}

std::list< Variant_p >		Argument::parameters()
{
  return this->__parameters;
}

uint32_t			Argument::parametersCount()
{
  return this->__parameters.size();
}

int32_t			Argument::minimumParameters()
{
  return this->__minparams;
}

int32_t			Argument::maximumParameters()
{
  return this->__maxparams;
}

}
