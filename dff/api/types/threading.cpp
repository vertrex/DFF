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

#include "threading.hpp"

#include <iostream>

namespace DFF 
{
  Mutex::Mutex()
  {
    mutex_init(&__mutex);
  }
  
  Mutex::Mutex(const Mutex& other)
  {
    mutex_init(&__mutex);
  }
  
  Mutex::~Mutex()
  {
    mutex_destroy(&__mutex);
  }

  void Mutex::lock()
  {
    mutex_lock(&__mutex);
  }

  void	Mutex::release()
  {
    mutex_unlock(&__mutex);
  }
  
  ScopedMutex::ScopedMutex(Mutex& mutex) : __mutex(mutex)
  {
    __mutex.lock();
  }

  ScopedMutex::~ScopedMutex()
  {
    __mutex.release();
  }

};
