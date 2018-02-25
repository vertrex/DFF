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

#include "fdmanager.hpp"
#include "threading.hpp"

namespace DFF
{

FdManager::FdManager()
{
  mutex_init(&this->__mutex);
  this->fds.assign(16384, (fdinfo*)0);
  this->allocated = 0;
}

FdManager::~FdManager()
{
  mutex_destroy(&this->__mutex);
}

fdinfo*		FdManager::get(int32_t fd)
{
  fdinfo*	fi;

  mutex_lock(&this->__mutex);
  if (fd > (int32_t)this->fds.size())
  {
    mutex_unlock(&this->__mutex);
    throw(vfsError("fdmanager::get -> Provided fd is too high"));
  }
  else
  {
     fi = this->fds[fd];
     if (fi != 0)
     {
       mutex_unlock(&this->__mutex);
       return fi;
     }
     else
     {
       mutex_unlock(&this->__mutex);
       throw(vfsError("fdmanager::get -> fd not allocated"));
     }
   }
}

int32_t	FdManager::push(fdinfo* fi)
{
  uint32_t	i;
  bool		empty;

  mutex_lock(&this->__mutex);
  empty = false;
  if (this->allocated == this->fds.size())
  {
    mutex_unlock(&this->__mutex);
    throw(vfsError("fdmanager::push -> there is no room for new fd"));
  }
  else
  {
    i = 0;
    while ((i < this->fds.size()) && !empty)
    {
       if (this->fds[i] == 0)
         empty = true;
       else
         i++;
    }
    if (empty && (i < this->fds.size()))
    {
      this->allocated++;
      this->fds[i] = fi;
      mutex_unlock(&this->__mutex);
      return (i);
    }
    else
    {
      mutex_unlock(&this->__mutex);
      throw(vfsError("fdmanager::push -> new fd allocation failed"));
    }
  }
}

void		FdManager::remove(int32_t fd)
{
  fdinfo*	fi;
  
  mutex_lock(&this->__mutex);
  if (fd > (int32_t)this->fds.size())
  {
     std::cout << "fdmanager::remove -> fd not allocated" << std::endl;
     //throw(vfsError("fdmanager::remove -> fd not allocated"));
  }
  else
  {
    fi = this->fds[fd];
    if (fi != 0)
    {
      delete fi;
      this->fds[fd] = 0;
      this->allocated--;
    }
  }
  mutex_unlock(&this->__mutex);
}

}
