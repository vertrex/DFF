// DFF -- An Open Source Digital Forensics Framework
// Copyright (C) 2009-2015 ArxSys
// This program is free software, distributed under the terms of
// the GNU General Public License Version 2. See the LICENSE file
// at the top of the source tree.
 
// See http://www.digital-forensic.org for more information about this
// project. Please do not directly contact any of the maintainers of
// DFF for assistance; the project provides a web site, mailing lists
// and IRC channels for your use.

// Author(s):
//  Frederic Baguelin <fba@digital-forensic.org>


#ifndef __CRASHDUMPINFO_HPP__
#define __CRASHDUMPINFO_HPP__

#include <stdio.h>
#include <iostream>
#include <string>

#include "google_breakpad/processor/minidump.h"

class CrashDumpInfo
{
private:
  google_breakpad::Minidump*		__minidump;
  google_breakpad::MinidumpSystemInfo*	__sysinfo;
  const MDRawSystemInfo*		__rawSysinfo;
  google_breakpad::MinidumpException*	__exception;
  const MDRawExceptionStream*		__rawException;
  std::string				__processorArchitecture;
  std::string				__cpuInformation;
  std::string				__osName;
  std::string				__osVersion;
  uint64_t				__crashAddress;
  std::string				__crashReason;
  void					__armCpuInfo();
  void					__setCpuInformation();
  void					__setOsInformation();
  void					__setCrashReason();
public:
  CrashDumpInfo();
  ~CrashDumpInfo();
  void		process(std::string minidumpPath) throw (std::string);
  void		process(char* minidumpPath) throw (std::string);
  void		print();
  std::string	minidumpPath();
  std::string	details();
  std::string	processorArchitecture();
  std::string	cpuInformation();
  std::string	numberOfProcessors();
  std::string	operatingSystemName();
  std::string	operatingSystemVersion();
  std::string	crashAddress();
  std::string	crashReason();
};


#endif
