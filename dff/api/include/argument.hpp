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
 *  Frederic Baguelin <fba@digital-forensic.org>
 */


#ifndef __ARGUMENT_HPP__
#define __ARGUMENT_HPP__

#ifndef WIN32
#include <stdint.h>
#elif _MSC_VER >= 1600
	#include <stdint.h>
#else
#include "wstdint.h"
#endif

#include <string>
#include <list>
#include <map>

#include "variant.hpp"
#include "export.hpp"

#define TYPEMASK			0x00FF
#define INPUTMASK			0x0300
#define NEEDMASK			0x0C00
#define PARAMMASK			0x3000

namespace DFF
{

struct Parameter
{
  enum types
  {
     NotEditable = 0x1000,
     Editable = 0x2000
  };
};

class Argument
{
private:
  std::string			__name;
  uint16_t			__flags;
  std::string			__description;
  bool				__enabled;
  std::list< Variant_p >	__parameters;
  bool				__paramslocked;
  int32_t			__minparams;
  int32_t			__maxparams;
  std::list<class Argument*>	__subarguments;
  void				setParametersType(uint16_t t);

public:
  enum inputTypes
    {
      Empty =			0x0000,
      Single =			0x0100,
      List =			0x0200,
      Optional =		0x0400,
      Required =		0x0800
    };
  EXPORT Argument(std::string name, uint16_t flags, std::string description = "");
  EXPORT ~Argument();
  EXPORT void				addSubArgument(Argument* arg);
  EXPORT void				addParameters(std::list< Variant_p > params, uint16_t type, int32_t min = -1, int32_t max=-1);
  EXPORT std::list< Variant_p >	parameters();
  EXPORT uint32_t			parametersCount();
  EXPORT std::string			name();
  EXPORT uint16_t			flags();
  EXPORT std::string			description();
  EXPORT uint16_t			type();
  EXPORT uint16_t			inputType();
  EXPORT uint16_t			parametersType();
  EXPORT uint16_t			requirementType();
  EXPORT int32_t			minimumParameters();
  EXPORT int32_t			maximumParameters();
};

}
#endif
