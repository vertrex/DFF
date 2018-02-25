#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <string>
#include <iostream>
#include <vector>
#include <algorithm>
#include "file.h"
#include "magic.h"

int     allocAndRead(const char* path, void** buffer, int size)
{
  FILE* f;
  int   rbytes;

  rbytes = -1;

  if ((f = fopen(path, "r")) != NULL)
    {
      if ((*buffer = malloc(size)) != NULL)
	rbytes = fread(*buffer, 1, size, f);
      fclose(f);
    }
  return rbytes;
}


char*	getmagic(void* buffer, int rbytes)
{
  magic_t	ms;
  const char*		tmp;
  char*			result;

  ms = NULL;
  tmp = NULL;
  result = NULL;  
  if ((ms = magic_open(MAGIC_NONE)) != NULL)
    {
#ifdef WIN32
      if (magic_load(ms, "magic.mgc") != -1)
#else
      if (magic_load(ms, "magic.mgc") != -1)
#endif
      	{
	  if ((tmp = magic_buffer(ms, buffer, rbytes)) != NULL)
	    {
	      if ((result = (char*)malloc(strlen(tmp) * sizeof(char))) != NULL)
		memcpy(result, tmp, strlen(tmp));
	    }
      	}
      magic_close(ms);
    }
  return result;
}


void	list(char* fn)
{
  magic_t				ms;
  uint32_t				magindex;
  std::string				_type;
  std::vector<std::string>		types;


  ms = NULL;
  magindex = 0;
  std::cout << "listing available types from " << fn << std::endl;
  if ((ms = magic_open(MAGIC_NONE)) != NULL)
    {
#ifdef WIN32
      if (magic_load(ms, fn) != -1)
#else
      if (magic_load(ms, fn) != -1)
#endif
      	{
	  struct mlist* ml;
	  for (ml = ms->mlist[0]->next; ml != ms->mlist[0]; ml = ml->next)
	    {
	      if (ml != NULL)
		{
		  for (magindex = 0; magindex < ml->nmagic; magindex++)
		    {
		      struct magic* m = &(ml->magic)[magindex];
		      if (strlen(m->desc) > 0)
			{
			  _type = std::string(m->desc);
			  if (std::find(types.begin(), types.end(), _type) == types.end())
			   types.push_back(_type);
			}
		    }
		}
	      else
		std::cout << "ml is null" << std::endl;
	    }
      	}
      magic_close(ms);
    }
  std::cout << "Total types: " << types.size() << std::endl;
  for (int i = 0; i != types.size(); i++)
    std::cout << types[i] << " ";
  std::cout << std::endl;
}


bool	compile(char* fn)
{
  magic_t	ms;
  bool		compiled;

  ms = NULL;
  compiled = false;
  std::cout << "Compiling magic files from " << fn;
  if ((ms = magic_open(MAGIC_NONE)) != NULL)
    {
      if (magic_compile(ms, fn) == 0)
	{
	  std::cout << " [SUCCEED]" << std::endl;
	  compiled = true;
	}
      else
	std::cout << " [FAILED]";
      magic_close(ms);
    }
  else
    std::cout << " [FAILED]";
  return compiled;
}


int main(int argc, char* argv[])
{
  void*			buffer;
  int			rbytes;
  std::string		abspath;
  char*			result;

  if (compile("./magic"))
    {
      std::cout << std::endl;
      list("./magic.mgc");
      std::cout << std::endl;
#ifndef WIN32
      abspath = std::string("libcmagic.so");
#else
      abspath = std::string("cmagic.dll");
#endif
      std::cout << "Testing compiled magic file on " << abspath;
      if ((rbytes = allocAndRead(abspath.c_str(), &buffer, 2048)) > 0)
	{
	  std::cout << "\n\t";
	  if ((result = getmagic(buffer, rbytes)) != NULL)
	    std::cout << "type: " << result << std::endl;
	  else
	    std::cout << "FAILED" << std::endl;
	}
    }
  else
    std::cout << "File types won't be available at runtime!" << std::endl;
}
