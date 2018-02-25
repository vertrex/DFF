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
 *  Solal J. <sja@digital-forensic.org>
 */


#ifndef __HANDLER_HH__
#define __HANDLER_HH__

#include <string>
#include "export.hpp"

namespace google_breakpad
{
  class ExceptionHandler;
};

class CrashHandler
{
private:
  bool					__silent;
  std::string				__version;
  google_breakpad::ExceptionHandler	*__eh;
public:
  EXPORT CrashHandler();
  EXPORT ~CrashHandler();
  EXPORT void	setSilentReport(bool);
  EXPORT void	setVersion(std::string);
  EXPORT void	setHandler();
  EXPORT void	unsetHandler();
};

#endif 
