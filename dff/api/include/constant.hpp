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

#ifndef __CONSTANT_HPP__
#define __CONSTANT_HPP__

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

namespace DFF
{

class Constant
{
private:
  std::string		__name;
  uint8_t		__type;
  std::string		__description;
  bool			__valueslocked;
  std::list<Variant_p >	__values;

public:
  EXPORT Constant(std::string name, uint8_t type, std::string description);
  EXPORT ~Constant();
  EXPORT std::string		name();
  EXPORT std::string		description();
  EXPORT uint8_t		type();
  EXPORT void			addValues(std::list< Variant_p > values);
  EXPORT std::list< Variant_p >	values();
};

}
#endif
