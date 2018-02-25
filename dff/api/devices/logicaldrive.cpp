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


#include "logicaldrive.hpp"
#include <iostream>
#include <sstream>

LogicalDrive::LogicalDrive(wchar_t* drive)
{
  this->__drive = new wchar_t[MAX_PATH];
  memset(this->__drive, 0, MAX_PATH);
  memcpy(this->__drive, drive, MAX_PATH);
}


LogicalDrive::LogicalDrive()
{
  
}


LogicalDrive::~LogicalDrive()
{
  
}


// wchar_t* 		LogicalDrive::blockDevice(void)
// {
//   HANDLE			device;
//   DWORD				bytes;
//   STORAGE_DEVICE_NUMBER		sdnumber;
//   wchar_t*			result;
//   wchar_t*			name;
//   std::wstringstream		idx;

//   result = new wchar_t[MAX_PATH+32];
//   memset(result, 0, MAX_PATH+32);
//   name = this->__openingDrive();
//   wcsncpy(result, L"\\\\.\\PhysicalDrive", wcslen(L"\\\\.\\PhysicalDrive"));
//   if ((device = CreateFile(name, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL)) != INVALID_HANDLE_VALUE)
//     {
//       if (DeviceIoControl(device, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0,  &sdnumber, sizeof(sdnumber), &bytes, NULL))
// 	{
// 	  idx << sdnumber.DeviceNumber;
// 	  wcsncpy(result+wcslen(L"\\\\.\\PhysicalDrive"), idx.str().c_str(), wcslen(idx.str().c_str()));
// 	}
//       CloseHandle(device);
//     }
//   delete name;
//   return result;
// }


wchar_t* 		LogicalDrive::blockDevice(void)
{
  return this->__openingDrive();
}


wchar_t* 		LogicalDrive::model(void)
{
  std::wstringstream		bdevice;
  wchar_t*			volname;
  unsigned int			dtype;
  std::wstring			letter;

  volname = new wchar_t[MAX_PATH+32];
  memset(volname, 0, MAX_PATH);
  dtype = GetDriveType(this->__drive);
  GetVolumeInformation(this->__drive, volname, MAX_PATH, NULL, NULL, NULL, NULL, 0);
  if ((wcslen(volname) == 0) && (dtype == DRIVE_FIXED))
    wcsncpy(volname, L"Local Disk", wcslen(L"Local Disk"));
  if ((wcslen(volname) == 0) && (dtype == DRIVE_CDROM))
    wcsncpy(volname, L"CD Drive", wcslen(L"CD Drive"));
  letter = L" (" + std::wstring(this->__drive) + L")";
  wcsncpy(volname+wcslen(volname), letter.c_str(), wcslen(letter.c_str()));
  
  return volname;
}


wchar_t* 		LogicalDrive::serialNumber(void)
{
  std::wstringstream	serial;
  DWORD			volserial;
  wchar_t*		strserial;       


  strserial = new wchar_t[32];
  memset(strserial, 0, 32);
  GetVolumeInformation(this->__drive, NULL, 0, &volserial, NULL, NULL, NULL, 0);
  serial << std::hex << volserial;
  wcsncpy(strserial, serial.str().c_str(), wcslen(serial.str().c_str()));
  return strserial;
}


uint64_t		LogicalDrive::size(void)
{
  HANDLE			device;
  DWORD				bytes;
  GET_LENGTH_INFORMATION	length;
  uint64_t			dsize;
  wchar_t*			name;

  dsize = 0;
  name = this->__openingDrive();  
  if ((device = CreateFile(name, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL)) != INVALID_HANDLE_VALUE)
    {
      if (DeviceIoControl(device, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &length, sizeof(length), &bytes, NULL))
	dsize = (uint64_t)length.Length.QuadPart;
      CloseHandle(device);
    }
  delete name;
  return dsize;
}


wchar_t*	LogicalDrive::__openingDrive()
{
  wchar_t*			name;

  name = new wchar_t[MAX_PATH];
  memset(name, 0, MAX_PATH);
  wcsncpy(name, L"\\\\.\\", wcslen(L"\\\\.\\"));
  wcsncpy(name+wcslen(L"\\\\.\\"), this->__drive, wcslen(this->__drive)-1);
  return name;
}


LogicalDrives::LogicalDrives()
{
  DWORD		size;
  wchar_t	drives[MAX_PATH] = {0};
  DWORD		driveslen;


 
  size = MAX_PATH;
  driveslen = GetLogicalDriveStrings(size, drives);
  if (driveslen > 0 && driveslen <= MAX_PATH)
    {
      wchar_t* drive = drives;
      while(*drive)
	{
	  LogicalDrive* ldrive = new LogicalDrive(drive);
	  this->deviceList.push_back(ldrive);
	  drive += wcslen(drive) + 1;
	  ldrive->blockDevice();
	  ldrive->model();
	  ldrive->serialNumber();
	  ldrive->size();
	}
    }  
}


LogicalDrives::~LogicalDrives()
{
}
