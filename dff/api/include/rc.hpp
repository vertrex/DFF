#ifndef __RC_HPP__
#define __RC_HPP__


#ifndef WIN32
 #include <stdint.h>
#elif _MSC_VER >= 1600
 #include <stdint.h>
#else
 #include "wstdint.h"
#endif

#include <iostream>
#include <string>
#include "export.hpp"
#include "threading.hpp"

namespace DFF
{

struct RCObjBase  
{
public:
  EXPORT int32_t ref_count() const
  {
    return (refCount);
  }

  EXPORT int32_t addref() const
  {
    return (++refCount);
  }
    
  EXPORT int32_t delref() const
  {
    if (refCount == 0 || --refCount == 0) 
    {
      delete this;
      return (0);
    } 
    return (refCount);
  }
    
protected:
  EXPORT RCObjBase();
  EXPORT RCObjBase(const RCObjBase& );
  EXPORT virtual ~RCObjBase() = 0;

private:

  RCObjBase& operator=(const RCObjBase& );
  friend struct RCObj;
  mutable int32_t refCount;
};



struct RCObj : virtual RCObjBase 
{
  protected:
    RCObj()
    {
    }
};

template <class T> inline T* addref(T* r)
{ 
  return (r && r->addref()) ? r : 0;
}
  
template <class T> inline T* delref(T* r)
{
  return (r && r->delref()) ? r : 0;
}

template <class T> struct RCPtr  
{
  typedef T* pointer_type;
  typedef T& refernce_type;
  typedef T  value_type;  
  
  RCPtr() : pointee(0) 
  {
  };

  RCPtr(T* realPtr) :pointee(realPtr) 
  {
   DFF::ScopedMutex  locker(__mutex);
   addref(pointee);  
  };

  RCPtr(const RCPtr& rhs) : pointee(rhs.pointee) 
  { 
    DFF::ScopedMutex locker(__mutex);
    addref(pointee);
  };

  ~RCPtr() 
  { 
    DFF::ScopedMutex locker(__mutex);
    delref(pointee); 
  };

  RCPtr& operator=(const RCPtr& rhs) 
  { 
    DFF::ScopedMutex locker(__mutex);

    if (pointee != rhs.pointee) 
    {
      delref(pointee);
      pointee = rhs.pointee;
      addref(pointee);
    }
    return (*this);
  };
  
  T* operator->() 
  { 
    return (pointee); 
  }
  T& operator*() 
  { 
    return (*pointee); 
  }

  const T* operator->() const 
  { 
    return (pointee); 
  }
  const T& operator*() const 
  { 
    return (*pointee); 
  }

  operator T*() 
  { 
    return (pointee); 
  }
  operator T&() 
  { 
    return (*pointee);
  }  

  operator const T*() const 
  { 
    return (pointee); 
  }
  operator const T&() const 
  { 
    return (*pointee);
  }  

  T* get() 
  { 
    return (pointee);
  }
  T* get() const 
  { 
    return (pointee);
  }
    
private:
  T* pointee;
  DFF::Mutex __mutex;
};

}
#endif
