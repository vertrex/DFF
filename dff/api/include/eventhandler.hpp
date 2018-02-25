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

#ifndef __EVENTHANDLER_HPP__
#define __EVENTHANDLER_HPP__

#ifndef WIN32
#include <stdint.h>
#elif _MSC_VER >= 1600
	#include <stdint.h>
#else
#include "wstdint.h"
#endif
#include "export.hpp"
#include "variant.hpp"
#include <iostream>
#include <iomanip>
#include <vector>

namespace DFF
{

typedef struct 
{
  enum
    {
      OPEN = 0,
      CLOSE = 1,
      READ = 2,
      WRITE = 3,
      SEEK = 4,
      OTHER = 5    
    };
}	etype;

typedef struct
{
  uint32_t		type;
  DFF::RCPtr< DFF::Variant >	value;
}			event;

class EventHandler
{
private:
  std::vector<class EventHandler *>	watchers;
public:
  EXPORT 				EventHandler();
  EXPORT virtual			~EventHandler() {};
  EXPORT virtual void			Event(event *e) = 0;
  EXPORT bool				connection(class EventHandler *obs);
  EXPORT bool				deconnection(class EventHandler *obs);
  EXPORT bool				notify(event *e);
};

}
#endif
