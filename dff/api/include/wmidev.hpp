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


#ifndef __WMIDEVICES_HPP__
#define __WMIDEVICES_HPP__

#include "export.hpp"
#include "device.hpp"

#define _WIN32_DCOM

#include <iostream>
#include <comdef.h>
#include <Wbemidl.h>
# pragma comment(lib, "wbemuuid.lib")

namespace DFF
{

class WMIDevice : public Device
{
private:
  IWbemClassObject	*pclsObj;
public:
  EXPORT			WMIDevice();
  EXPORT			WMIDevice(IWbemClassObject *pcls);
  EXPORT			~WMIDevice();
  EXPORT wchar_t* 		blockDevice(void);
  EXPORT wchar_t*	 	serialNumber(void);
  EXPORT wchar_t*	 	model(void);
  EXPORT uint64_t		size(void);

};

class WMIDevices : public DeviceList
{
private:
  IWbemLocator				*pLoc; 
  IWbemServices				*pSvc;
public:
  std::vector<Device *> 	deviceList;
  EXPORT			WMIDevices();
  EXPORT		  	~WMIDevices();
};

}
#endif
