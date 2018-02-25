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


#ifndef __THREADING_HPP__
#define __THREADING_HPP__

#include <stdexcept>
#include <map>
#include <vector>
#include <queue>
#include "export.hpp"


#ifdef WIN32
  typedef HANDLE                ThreadStruct;
  typedef DWORD                 ThreadResult;
  typedef LPVOID                ThreadData;
  #define createThread(function, data, threadStruct)\
  threadStruct = CreateThread(NULL, 0, function, (ThreadData)data, 0, NULL);\
  if (threadStruct == NULL)\
    throw std::string("Error creating thread");
  #define destroyThread(var)   CloseHandle(var)   
  #define thread_join(var, res) WaitForSingleObject(var, INFINITE);\
                               ExitCodeThread(var, &res)

  #define cpu_count(var)       SYSTEM_INFO sysinfo;\
                               GetSystemInfo(&sysinfo);\
                               var = sysinfo.dwNumberOfProcessors;\
                               }
 
  #define mutex_def(var)	CRITICAL_SECTION var
  #define mutex_init(var)  	InitializeCriticalSection(var)
  #define mutex_destroy(var)	DeleteCriticalSection(var)
  #define mutex_lock		EnterCriticalSection
  #define mutex_unlock		LeaveCriticalSection

  #define cond_def(var)		CONDITION_VARIABLE var
  #define cond_init(var)        InitializeConditionVariable(var)
  #define cond_destroy(var)		
  #define cond_signal(var)      WakeConditionVariable(var)
  //#define cond_wait(cond, mut)  pthread_testcancel(); SleepConditionVariableCS(cond, mut, INFINITE)
  #define cond_wait(cond, mut)  SleepConditionVariableCS(cond, mut, INFINITE)
  #define cond_broadcast(var)	WakeAllConditionVariable(var)
#else
  #include <pthread.h>
  #include <unistd.h>
  typedef pthread_t             ThreadStruct;
  typedef void*                 ThreadResult;
  typedef void*                 ThreadData;
  #define createThread(function, data, threadStruct)\
  int result = pthread_create(&threadStruct, NULL, function, (void*)data);\
  if (result)\
    throw std::string("Error creating thread");
  #define destroyThread(var)
  #define thread_join(var, res) pthread_join(var, &res);

  #define cpu_count(var)        var = sysconf(_SC_NPROCESSORS_ONLN);

  #define mutex_def(var)	pthread_mutex_t	var	
  #define mutex_init(var)	pthread_mutex_init(var, NULL)
  #define mutex_destroy(var)	pthread_mutex_destroy(var)
  #define mutex_lock 		pthread_mutex_lock
  #define mutex_unlock 		pthread_mutex_unlock

  #define cond_def(var)		pthread_cond_t var
  #define cond_init(var)        pthread_cond_init(var, NULL)
  #define cond_destroy(var)	pthread_cond_destroy(var)
  #define cond_signal(var)	pthread_cond_signal(var)
  #define cond_wait(cond, mut)  pthread_cond_wait(cond, mut)
  #define cond_broadcast(var)	pthread_cond_broadcast(var)
#endif

namespace DFF 
{
  class Mutex
  {
  public:
    EXPORT Mutex();
    EXPORT ~Mutex();
    EXPORT Mutex(const Mutex& other);
    EXPORT void	lock();
    EXPORT void	release();
  private:
    mutex_def(__mutex); 
  };

  class ScopedMutex
  {
  public:
    EXPORT ScopedMutex(Mutex& mutex);
    EXPORT ~ScopedMutex();
  private:
    Mutex&	__mutex;
  };

  template< typename key, typename value >
  class map
  {
  public:
    EXPORT map() { }
    EXPORT ~map() 
    { 
      ScopedMutex locker(__mutex);
      internals.clear();
    }

    EXPORT value&	operator[](const key _k) 
    { 
      ScopedMutex	locker(__mutex);
      return internals[_k];
    }

    EXPORT bool exist(key _k)
    {
      ScopedMutex locker(__mutex);
      return internals.find(_k) != internals.end();
    }
    
    EXPORT bool	empty() const
    {
      ScopedMutex	locker(__mutex);
      return internals.empty();
    }

    EXPORT value	 get_value(key _k)
    {
       ScopedMutex	locker(__mutex);
       typename std::map<key, value>::iterator iv;
       iv = internals.find(_k);	
       if (iv != internals.end())
       {
	 return(value(iv->second));
       }
       throw std::string("Can't find value");
    }

    EXPORT const std::map< key, value > &	getInternals()
    {
      return internals;
    }

    EXPORT void erase(key _k)
    {
      ScopedMutex locker(__mutex);
      internals.erase(_k);
      return ;
    }

  private:
    std::map< key, value >	internals;
    mutable Mutex		__mutex;
  };

  template< typename value >
  class vector
  {
  public:
    EXPORT vector() { }

    EXPORT ~vector() 
    { 
      ScopedMutex locker(__mutex);
      internals.clear();
    }

    EXPORT value&	operator[](unsigned int n) throw (std::out_of_range)
    {
      ScopedMutex     locker(__mutex);
      return internals[n];
    }

    EXPORT const value at(unsigned int idx) const
    {
      ScopedMutex locker(__mutex);
      return internals.at(idx);
    }
    
    EXPORT bool	empty() const
    {
      ScopedMutex	locker(__mutex);
      return internals.empty();
    }

    EXPORT unsigned int size() const
    {
      return internals.size();
    }

    EXPORT void	push_back(const value& val)
    {
      ScopedMutex	locker(__mutex);
      internals.push_back(val);
    }
  private:
    mutable Mutex		__mutex;
    std::vector< value >	internals;
  };

template <typename T> 
class WorkQueue
{ 
public:
  EXPORT WorkQueue() 
  {
     mutex_init(&this->__mutex);
     cond_init(&this->__condv);
  }

  EXPORT ~WorkQueue() 
  {
    mutex_destroy(&this->__mutex);
    cond_destroy(&this->__condv);
  }

  EXPORT void add(T item) 
  {
    mutex_lock(&this->__mutex);
    this->__queue.push(item);
    cond_signal(&this->__condv);
    mutex_unlock(&this->__mutex);
  }

  EXPORT T remove() 
  {
    mutex_lock(&this->__mutex);
    while (this->__queue.empty()) 
      cond_wait(&this->__condv, &this->__mutex);
    
    T item = this->__queue.front();
    this->__queue.pop();
    mutex_unlock(&this->__mutex);
    return item;
  }
private:
  std::queue<T>         __queue;
  mutex_def(__mutex);
  cond_def(__condv);
};

}

#endif
