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
 *  Solal Jacob <sja@digital-forensic.org>
 */

#ifndef __WINDEVICES_HH__
#define __WINDEVICES_HH__

#include <string>
#include <iostream>
#include <stdio.h>
#include <list>
#include <vector>

#include "fdmanager.hpp"
#include "variant.hpp"
#include "node.hpp"
#include "fso.hpp"

#ifdef WIN32
#pragma comment(lib, "advapi32.lib")
#include <windows.h>
#include <stdio.h>
#include <aclapi.h>

class DeviceBuffer
{
private:
  HANDLE			__handle;
  uint8_t*			__buffer;
  uint64_t			__offset;
  uint32_t			__BPS;
  DWORD				__currentSize;
  uint64_t			__devSize;
  void				fillBuff(uint64_t offset);
public:
  DeviceBuffer(HANDLE handle, uint32_t size, uint32_t BPS,  uint64_t DevSize);
  ~DeviceBuffer();
  uint32_t			__size;
  uint32_t			getData(void* buff, uint32_t size, uint64_t offset);
};
#endif

using namespace DFF;

class DeviceNode : public DFF::Node
{
public:
  DeviceNode(std::string devname, uint64_t size, DFF::fso* fsobj, std::string name);
  std::string		icon();
  std::string		__devname;	
};

class devices : public DFF::fso
{
private:
  DFF::Node*            __parent;
  DFF::Node*		__root;
  DFF::FdManager*       __fdm;
public:
  devices();
  ~devices();
  std::string           devicePath;
  virtual void	        start(std::map<std::string, Variant_p > args);
  int32_t	        vopen(DFF::Node* handle);
  int32_t 	        vread(int fd, void *buff, unsigned int size);
  int32_t 	        vclose(int fd);
  uint64_t 	        vseek(int fd, uint64_t offset, int whence);
  int32_t	        vwrite(int fd, void *buff, unsigned int size) { return 0; };
  uint32_t	        status(void);
  uint64_t	        vtell(int32_t fd);
};
#endif
