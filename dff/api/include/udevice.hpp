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

#ifndef __UDEV_HPP__
#define __UDEV_HPP__

#include "device.hpp"
#include <libudev.h>

namespace DFF
{

class UDevice : public Device
{
private:
 wchar_t*	__blockDevice;
 wchar_t*	__serialNumber;
 wchar_t*	__model;
 uint64_t	__size;
public:
		UDevice();
                UDevice(const char* blockDevice, const char* serialNumber, const char* model, uint64_t size);
                ~UDevice();
  wchar_t*      blockDevice(void);
  wchar_t*      serialNumber(void);
  wchar_t*      model(void);
  uint64_t      size(void);
};

class UDevices : public DeviceList
{
public:
                        UDevices();
                        ~UDevices();
  std::vector<Device* > deviceList;
};

}
#endif
