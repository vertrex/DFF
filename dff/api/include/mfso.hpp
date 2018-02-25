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
 *  Frederic Baguelin <fba@digital-forensic.org>
 */

#ifndef __MFSO_HPP__
#define __MFSO_HPP__

#ifndef WIN32
  #include <stdint.h>
#elif _MSC_VER >= 1600
  #include <stdint.h>
#else
  #include "wstdint.h"
#endif

#include <stdio.h>
#include <string.h>
#include <iostream>
#include <list>
#include <map>
#include <vector>

#include "fso.hpp"

namespace DFF
{
class FileMappingCache;
class FdManager;
class fdinfo;
class FileMapping;

class mfso: public fso
{
private:
  bool					__verbose;
  std::list<class mfso*>		__children;
  FileMappingCache*			__fmCache;
  int32_t				readFromMapping(FileMapping* fm, fdinfo* fi, void* buff, uint32_t size);
  FileMapping*				mapFile(Node* node);
public:
  FdManager*				__fdmanager;
  EXPORT mfso(std::string name);
  EXPORT virtual ~mfso();
  EXPORT virtual void			start(std::map<std::string, RCPtr< Variant > > args) = 0;
  EXPORT virtual int32_t 		vopen(class Node *n);
  EXPORT virtual int32_t 		vread(int32_t fd, void *rbuff, uint32_t size);
  EXPORT virtual int32_t 		vwrite(int32_t fd, void *buff, uint32_t size);
  EXPORT virtual int32_t 		vclose(int32_t fd);
  EXPORT virtual uint64_t		vseek(int32_t fd, uint64_t offset, int32_t whence);
  EXPORT virtual uint32_t		status(void);
  EXPORT virtual uint64_t		vtell(int32_t fd);
  EXPORT virtual void			setVerbose(bool verbose);
  EXPORT virtual bool			verbose();
  EXPORT bool                           unmap(Node* node);
};

}
#endif
