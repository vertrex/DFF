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
 *  Frederic B. <fba@digital-forensic.org>
 */


#ifndef __LOGICALDRIVES_HPP__
#define __LOGICALDRIVES_HPP__

#include <Windows.h>

#include "export.hpp"
#include "device.hpp"

#include <iostream>

class LogicalDrive : public DFF::Device
{
private:
  wchar_t*		__drive;
  wchar_t*		__openingDrive();
public:
  EXPORT		LogicalDrive(wchar_t* drive);
  EXPORT		LogicalDrive();
  EXPORT		~LogicalDrive();
  EXPORT wchar_t* 	blockDevice(void);
  EXPORT wchar_t*	serialNumber(void);
  EXPORT wchar_t*	model(void);
  EXPORT uint64_t	size(void);

};


class LogicalDrives : public DFF::DeviceList
{
private:
  wchar_t*		__driveLetter(wchar_t* single);
public:
  std::vector<DFF::Device *> deviceList;
  EXPORT		LogicalDrives();
  EXPORT		~LogicalDrives();
};

#endif
