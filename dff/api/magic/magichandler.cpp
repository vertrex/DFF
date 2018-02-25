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

#include "magichandler.hpp"
#include "vfile.hpp"
#include "exceptions.hpp"

#include <magic.h>
//#include "file.h"



MagicHandler::MagicHandler() : DataTypeHandler("magic")
{
}


MagicHandler::~MagicHandler()
{
}


std::string	MagicHandler::type(Node* node)
{
  VFile*	vf;
  void*		buffer;
  int32_t	rbytes;
  std::string	result;

  vf = NULL;
  buffer = NULL;
  result = std::string("empty");
  if (node != NULL)
    {
      try
	{
	  if ((vf = node->open()) != NULL)
	    {
	      if ((buffer = malloc(4096 * sizeof(uint8_t))) != NULL)
		{
		  rbytes = vf->read(buffer, 4096);
	  	  vf->close();
	  	  //result = this->__magic(buffer, rbytes);
		}
	    }
	}
      catch (vfsError)
	{
	}
    }
  if (buffer != NULL)
    free(buffer);
  return result;
}


std::string	MagicHandler::__magic(void* buffer, uint32_t size)
{
  magic_t	ms;
  const char*	tmp;
  std::string	result;

  //result = std::string("empty");
  ms = NULL;
  tmp = NULL;
  if ((ms = magic_open(MAGIC_CONTINUE)) != NULL)
    {
      if (magic_load(ms, "/home/udgover/projects/magic-custom/file-orig/magic/magic.mgc") != -1)	
       	{
      	  if ((tmp = magic_buffer(ms, buffer, size)) != NULL)
      	    result = std::string(tmp);
      	}
      magic_close(ms);
    }
  return result;
}


// std::string	MagicHandler::__magic(void* buffer, uint32_t size)
// {
//   struct magic_set*	ms;
//   const char*		tmp;
//   std::string		result;
  
//   ms = NULL;
//   tmp = NULL;
//   result = std::string("empty");
//   if ((ms = file_ms_alloc(MAGIC_CONTINUE)) != NULL)
//     {
//       if (file_apprentice(ms, "/home/udgover/projects/magic-custom/file-orig/magic/magic.mgc", FILE_LOAD) != 1)
// 	{
// 	  if (file_reset(ms) == -1)
// 	    return result;
// 	  if (file_buffer(ms, -1, NULL, buffer, size) == -1)
// 	    return result;
// 	  if ((tmp = file_getbuffer(ms)) != NULL)
// 	    result = std::string(tmp);
// 	}
//       file_ms_free(ms);
//     }
//   return result;
// }


static MagicHandler* m = new MagicHandler();
