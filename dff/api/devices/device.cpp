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

#include "device.hpp"

namespace DFF
{

Device::Device()
{
}

Device::~Device()
{
}

wchar_t*	Device::blockDevice(void)
{
  return ((wchar_t*)L"Not available");
}

wchar_t*	 Device::serialNumber(void)
{
  return ((wchar_t*)L"Not available");
}

wchar_t*	Device::model(void)
{
  return ((wchar_t*)L"Not available");
}

uint64_t	Device::size(void)
{
  return (0);
}


DeviceList::DeviceList()
{
}

}
