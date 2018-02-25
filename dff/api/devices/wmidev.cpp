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

#include "wmidev.hpp"

namespace DFF
{

/*
This use WMI to get devices informations 
*/
WMIDevice::WMIDevice()
{
}


WMIDevice::WMIDevice(IWbemClassObject *pcls)
{
  this->pclsObj = pcls;
}

WMIDevice::~WMIDevice()
{
  this->pclsObj->Release();
}

wchar_t*		WMIDevice::blockDevice(void)
{
   HRESULT	hr;
	_variant_t vtProp;
 
   hr = this->pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
   if (SUCCEEDED(hr))
   {
	   wchar_t*	var = (wchar_t*)vtProp.pbstrVal;
	   return (var);
   }
   return (L"Not Found");
}

wchar_t* 		WMIDevice::serialNumber(void)
{
   HRESULT	hr;
   VARIANT	vtProp;
   hr = this->pclsObj->Get(L"SerialNumber", 0, &vtProp, 0, 0);
  
   wchar_t*	var = (wchar_t*)vtProp.pbstrVal;
   VariantClear(&vtProp);

   return (var);
}

wchar_t*		WMIDevice::model(void)
{
   HRESULT	hr;
   VARIANT	vtProp;
   hr = this->pclsObj->Get(L"Model", 0, &vtProp, 0, 0);
  
   wchar_t*	var = (wchar_t*)vtProp.pbstrVal;
   VariantClear(&vtProp);

   return (var);
}

uint64_t 		WMIDevice::size(void)
{
   HRESULT	hr;
   VARIANT	vtProp;

   hr = this->pclsObj->Get(L"Name", 0, &vtProp, NULL, NULL);
   if (SUCCEEDED(hr))
   {
     wchar_t*	var = (wchar_t*)vtProp.pbstrVal;
	      
	 HANDLE hnd = CreateFileW(var , GENERIC_READ, FILE_SHARE_READ,
			                  0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	 if (hnd == INVALID_HANDLE_VALUE)
	   return  (0);
	 else
	 {
	   GET_LENGTH_INFORMATION diskSize;
	   DWORD lpBytesReturned = 0;
	   DeviceIoControl(hnd, FSCTL_ALLOW_EXTENDED_DASD_IO, NULL, 0, NULL, 0, &lpBytesReturned, NULL);
	   if (DeviceIoControl(hnd, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &diskSize, sizeof(diskSize), &lpBytesReturned,0))
	   {
	     CloseHandle(hnd);
	     return ((uint64_t)diskSize.Length.QuadPart);
	   }
	   CloseHandle(hnd);
     }
   }
   
   return (0);
}


WMIDevices::WMIDevices(void)
{
  HRESULT hres;

  this->pLoc = NULL; 
  this->pSvc = NULL;

  hres =  CoInitializeEx(NULL, COINIT_APARTMENTTHREADED); 
  if (FAILED(hres))
  {
	return;
  }

  hres =  CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT,
							   RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL );
       
  if (FAILED(hres) &&  !(hres == RPC_E_TOO_LATE))
  {
	 return;
  }
 

  hres = CoCreateInstance(CLSID_WbemAdministrativeLocator,
					  	  NULL, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *) &(this->pLoc));

  if (FAILED(hres))
    return ;
  
  hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL , NULL, 0,
							 NULL, 0, 0, &(this->pSvc));

  if (FAILED(hres))
    return;

  hres = CoSetProxyBlanket(this->pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
	     NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

  if (FAILED(hres))
    return; 

  IEnumWbemClassObject* pEnumerator = NULL;
  hres = this->pSvc->ExecQuery(bstr_t("WQL"), bstr_t("SELECT * FROM Win32_DiskDrive"),
			WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,  NULL,&pEnumerator);
  if (FAILED(hres))
	return;

  IWbemClassObject *pclsObj;
  ULONG uReturn = 0;
   
  while (pEnumerator)
  {
    HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

    if (!uReturn)
      break;

	WMIDevice* dev = new WMIDevice(pclsObj);
	this->deviceList.push_back(dev);
  }
  pEnumerator->Release();
}


WMIDevices::~WMIDevices()
{
  std::vector<Device *>::iterator 	i = deviceList.begin();
  for (; i != deviceList.end(); i++)
 	 delete (*i);
  if (this->pSvc)
    this->pSvc->Release();
  if (this->pLoc)
    this->pLoc->Release();
}

}
