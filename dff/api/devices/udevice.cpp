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

#include <string.h>
#include <stdlib.h>
#include "udevice.hpp"

namespace DFF
{

/*
This use udev to get devices informations
*/
UDevice::UDevice()
{
  this->__blockDevice = NULL;
  this->__serialNumber = NULL;
  this->__model = NULL;
  this->__size = 0;
}

UDevice::~UDevice()
{
  if (this->__blockDevice)
    delete this->__blockDevice;
  if (this->__serialNumber)
    delete this->__serialNumber;
  if (this->__model)
    delete this->__model;
}

UDevice::UDevice(const char* blockDevice, const char* serialNumber, const char* model, uint64_t size)
{
  this->__blockDevice = new wchar_t[strlen(blockDevice) + 1];
  mbstowcs(this->__blockDevice, blockDevice, strlen(blockDevice) + 1);

  this->__serialNumber = new wchar_t[strlen(serialNumber) + 1];
  mbstowcs(this->__serialNumber, serialNumber, strlen(serialNumber) + 1);
  
  this->__model = new wchar_t[strlen(model) + 1];
  mbstowcs(this->__model, model, strlen(model) + 1);

  this->__size = size;
}

wchar_t*	UDevice::blockDevice(void)
{
  if (this->__blockDevice)
    return (this->__blockDevice);

  return ((wchar_t*)L"Not Found");
}

wchar_t*	UDevice::serialNumber(void)
{
  if (this->__serialNumber)
    return (this->__serialNumber);

  return ((wchar_t*)L"Not Found");
}

wchar_t*	UDevice::model(void)
{
  if (this->__model)
    return (this->__model);

  return ((wchar_t*)L"Not Found");
}

uint64_t	UDevice::size(void)
{
  return this->__size;
}


UDevices::UDevices(void)
{
  udev*			udev;
  udev_enumerate*	enumerate;
  udev_list_entry*	devices;
  udev_list_entry*	dev_list_entry;
  udev_device*		dev;

  udev = udev_new();
  if (udev == NULL)
  {
    std::cout << "can't access udev" << std::endl;
    return ;
  }	
  enumerate = udev_enumerate_new(udev);
  udev_enumerate_add_match_subsystem(enumerate, "block");
  udev_enumerate_scan_devices(enumerate);
  devices = udev_enumerate_get_list_entry(enumerate);

  udev_list_entry_foreach(dev_list_entry, devices)
  {
    const char* path = udev_list_entry_get_name(dev_list_entry);
    dev = udev_device_new_from_syspath(udev, path);
   
    if (std::string(udev_device_get_devtype(dev)) == std::string("disk"))
    {
      const char* blockDevice = udev_device_get_devnode(dev);
      const char* serialNumber = udev_device_get_property_value(dev, "ID_SERIAL");
      const char* model = udev_device_get_property_value(dev, "ID_MODEL");
      const char* size = udev_device_get_sysattr_value(dev, "size");
      const char* block_size = udev_device_get_sysattr_value(dev, "queue/physical_block_size");

      if (blockDevice != NULL && size != NULL)
      {	
        int bs = 512;
	uint64_t realSize = 0;

	if (block_size != NULL)
	  bs = atoi(block_size);
	realSize = atoll(size) * bs;
        if (model == NULL)
          model = "Unknown";
        if (serialNumber == NULL)
          serialNumber = "Unknown";
        if (realSize)
        {
	  UDevice* ud = new UDevice(blockDevice, serialNumber, model, realSize);
	  this->deviceList.push_back(ud);
        }
      }
    }
  }
  udev_enumerate_unref(enumerate);
  udev_unref(udev);
}

UDevices::~UDevices()
{
 std::vector<Device *>::iterator i = this->deviceList.begin();
 for (; i != this->deviceList.end(); i++)
    delete (*i);
}

}
