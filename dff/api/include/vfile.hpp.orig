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

#ifndef __VFILE_HH__
#define __VFILE_HH__

#include <stdlib.h> 
#include <string>
#include <string.h>
#ifndef WIN32
#include <stdint.h>
#elif _MSC_VER >= 1600
	#include <stdint.h>
#else
#include "wstdint.h"
#endif
#include "export.hpp"
#include "eventhandler.hpp"

#define BUFFSIZE 1024*1024*10

namespace DFF
{

struct pdata 
{
  void		*buff;
  uint64_t	len;
};

class Search;

class VFile: public DFF::EventHandler
{
private:
  class FastSearch*   __fs;
  class fso*	__fsobj;
  int32_t	__fd;
  class Node*  	__node;
  bool		__stop;
public:
  EXPORT VFile(int32_t fd, class fso *fsobj, class Node *node);
  EXPORT ~VFile();
  EXPORT class Node*		node();
  EXPORT pdata*			read();
  EXPORT pdata*			read(uint32_t size);
  EXPORT int32_t		read(void *buff, uint32_t size);
  EXPORT uint64_t		seek(uint64_t offset, char *whence);
  EXPORT uint64_t		seek(uint64_t offset, int32_t whence);
  EXPORT uint64_t		seek(uint64_t offset);
  EXPORT uint64_t		seek(int32_t offset, int32_t whence);
  EXPORT int32_t		write(std::string buff);
  EXPORT int32_t		write(char *buff, uint32_t size);
  EXPORT int32_t		dfileno();
  EXPORT uint64_t		tell();
  EXPORT int32_t		close();
  EXPORT virtual void		Event(event* e) { __stop = true; (void)e;}
  EXPORT std::string		readline(uint32_t size=0);
  EXPORT int64_t		find(unsigned char* needle, uint32_t nlen, unsigned char wildcard='\0', uint64_t start=0, uint64_t end=UINT64_MAX);
  EXPORT int64_t		rfind(unsigned char* needle, uint32_t nlen, unsigned char wildcard='\0', uint64_t start=0, uint64_t end=UINT64_MAX);
  EXPORT int32_t		count(unsigned char* needle, uint32_t nlen, unsigned char wildcard='\0', int32_t maxcount=INT32_MAX, uint64_t start=0, uint64_t end=0);
  EXPORT std::vector<uint64_t>*	indexes(unsigned char* needle, uint32_t nlen, unsigned char wildcard='\0', uint64_t start=0, uint64_t end=UINT64_MAX);
  EXPORT std::vector<uint64_t>*	search(char* needle, uint32_t nlen, unsigned char wildcard='\0', uint64_t start=0, uint64_t end=UINT64_MAX);
  EXPORT int64_t		find(std::string needle, unsigned char wildcard='\0', uint64_t start=0, uint64_t end=UINT64_MAX); 
  EXPORT int64_t		rfind(std::string needle, unsigned char wildcard='\0', uint64_t start=0, uint64_t end=UINT64_MAX);
  EXPORT int32_t		count(std::string needle, unsigned char wildcard='\0', int32_t maxcount=INT32_MAX, uint64_t start=0, uint64_t end=UINT64_MAX);
  EXPORT std::vector<uint64_t>*	indexes(std::string needle, unsigned char wildcard='\0', uint64_t start=0, uint64_t end=UINT64_MAX);

  EXPORT int64_t		find(Search* sctx, uint64_t start=0, uint64_t end=UINT64_MAX);
  EXPORT int64_t		rfind(Search* sctx, uint64_t start=0, uint64_t end=UINT64_MAX);
  EXPORT int32_t		count(Search* sctx, int32_t=INT32_MAX, uint64_t start=0, uint64_t end=UINT64_MAX);
  EXPORT std::vector<uint64_t>*	indexes(Search* sctx, uint64_t start=0, uint64_t end=UINT64_MAX);
};

}
#endif
