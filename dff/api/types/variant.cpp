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

#include "variant.hpp"
#include "typeinfo"
#include "string.h"
#include <stdio.h>

#include "datetime.hpp"
#include "path.hpp"

#ifdef WIN32
#define snprintf _snprintf
#endif

namespace DFF
{

typeId*	typeId::Get()
{
	static typeId single;
	return &single;
}


typeId::typeId()
{
  this->mapping.insert(std::pair<std::string, uint8_t>( typeid(int16_t*).name(), typeId::Int16));
  this->mapping.insert(std::pair<std::string, uint8_t>(typeid(uint16_t*).name(), typeId::UInt16));
  this->mapping.insert(std::pair<std::string, uint8_t>(typeid(int32_t*).name(), typeId::Int32));
  this->mapping.insert(std::pair<std::string, uint8_t>(typeid(uint32_t*).name(), typeId::UInt32));
  this->mapping.insert(std::pair<std::string, uint8_t>(typeid(int64_t*).name(), typeId::Int64));
  this->mapping.insert(std::pair<std::string, uint8_t>(typeid(uint64_t*).name(), typeId::UInt64));
  this->mapping.insert(std::pair<std::string, uint8_t>(typeid(char*).name(), typeId::Char));
  this->mapping.insert(std::pair<std::string, uint8_t>(typeid(bool*).name(), typeId::Bool));
  this->mapping.insert(std::pair<std::string, uint8_t>(typeid(char**).name(), typeId::CArray));
  this->mapping.insert(std::pair<std::string, uint8_t>(typeid(void**).name(), typeId::VoidPtr));
  this->mapping.insert(std::pair<std::string, uint8_t>(typeid(std::string *).name(), typeId::String));
  this->mapping.insert(std::pair<std::string, uint8_t>(typeid(class DateTime**).name(), typeId::DateTime));
  this->mapping.insert(std::pair<std::string, uint8_t>(typeid(class Node**).name(), typeId::Node));
  this->mapping.insert(std::pair<std::string, uint8_t>(typeid(class VLink**).name(), typeId::VLink));
  this->mapping.insert(std::pair<std::string, uint8_t>(typeid(class Path * *).name(), typeId::Path));
  this->mapping.insert(std::pair<std::string, uint8_t>(typeid(class Argument * *).name(), typeId::Argument));
  this->mapping.insert(std::pair<std::string, uint8_t>(typeid(std::map<std::string, Variant_p > *).name(), typeId::Map));
  this->mapping.insert(std::pair<std::string, uint8_t>(typeid(std::list< Variant_p > *).name(), typeId::List));


  this->rmapping.insert(std::pair<uint8_t, std::string>(typeId::Invalid, "Invalid"));
  this->rmapping.insert(std::pair<uint8_t, std::string>(typeId::String, "std::string"));
  this->rmapping.insert(std::pair<uint8_t, std::string>(typeId::Char, "char"));
  this->rmapping.insert(std::pair<uint8_t, std::string>(typeId::CArray, "char*"));
  this->rmapping.insert(std::pair<uint8_t, std::string>(typeId::Int16, "int16_t"));
  this->rmapping.insert(std::pair<uint8_t, std::string>(typeId::UInt16, "uint16_t"));
  this->rmapping.insert(std::pair<uint8_t, std::string>(typeId::Int32, "int32_t"));
  this->rmapping.insert(std::pair<uint8_t, std::string>(typeId::UInt32, "uint32_t"));
  this->rmapping.insert(std::pair<uint8_t, std::string>(typeId::Int64, "int64_t"));
  this->rmapping.insert(std::pair<uint8_t, std::string>(typeId::UInt64, "uint64_t"));
  this->rmapping.insert(std::pair<uint8_t, std::string>(typeId::Bool, "bool"));
  this->rmapping.insert(std::pair<uint8_t, std::string>(typeId::Map, "std::map<std::string, Variant_p >"));
  this->rmapping.insert(std::pair<uint8_t, std::string>(typeId::List, "std::list< Variant_p >"));
  this->rmapping.insert(std::pair<uint8_t, std::string>(typeId::DateTime, "DateTime*"));
  this->rmapping.insert(std::pair<uint8_t, std::string>(typeId::Node, "Node*"));
  this->rmapping.insert(std::pair<uint8_t, std::string>(typeId::Path, "Path*"));
  this->rmapping.insert(std::pair<uint8_t, std::string>(typeId::Argument, "Argument*"));
  this->rmapping.insert(std::pair<uint8_t, std::string>(typeId::VoidPtr, "void*"));
  this->rmapping.insert(std::pair<uint8_t, std::string>(typeId::VLink, "VLink*"));
  //this->mapping.insert(std::pair<char*, uint8_t>((char*)typeid(std::vector<class Variant*> *).name(), typeId::List));
  //this->mapping.insert(std::pair<char*, uint8_t>((char*)typeid(std::set<class Variant*> *).name(), typeId::List));
}

typeId::~typeId()
{
  //  delete this->mapping;
}


uint8_t	typeId::getType(std::string type)
{
  std::map<std::string, uint8_t>::iterator it;
  
  it = this->mapping.find(type);
  if (it != this->mapping.end())
    {
      return it->second;
    }
  else
    {
      return 0;
    }
}

std::string	typeId::typeToName(uint8_t t)
{
  std::map<uint8_t, std::string>::iterator it;
  
  it = this->rmapping.find(t);
  if (it != this->rmapping.end())
    return it->second;
  else
    return std::string("");
}


Variant::Variant()
{
  this->_type = typeId::Invalid;
}

Variant::Variant(class Variant* orig) throw (std::string)
{
  if (orig != NULL)
    {
      if (orig->type() == typeId::Invalid)
	throw (std::string("provided Variant cannot be of type Invalid"));
      this->_type = orig->type();
      if ((this->_type == typeId::String) || (this->_type == typeId::CArray))
        this->__data.str = new std::string(orig->value<std::string>());
      if (this->_type == typeId::Char)
	this->__data.c = orig->value<char>();
      if (this->_type == typeId::UInt16)
	this->__data.us = orig->value<uint16_t>();
      if (this->_type == typeId::Int16)
	this->__data.s = orig->value<int16_t>();
      if (this->_type == typeId::UInt32)
	this->__data.ui = orig->value<uint32_t>();
      if (this->_type == typeId::Int32)
	this->__data.i = orig->value<int32_t>();
      if (this->_type == typeId::UInt64)
	this->__data.ull = orig->value<uint64_t>();
      if (this->_type == typeId::Int64)
	this->__data.ll = orig->value<int64_t>();
      if (this->_type == typeId::Bool)
	this->__data.b = orig->value<bool>();
      if (this->_type == typeId::DateTime)
	{
	  DateTime* vt = orig->value<DateTime*>(); //XXX delete original ?
	  this->__data.ptr = new DateTime(*vt);
	}
      if (this->_type == typeId::Node)
	this->__data.ptr = (void*)orig->value<class Node*>();
      if (this->_type == typeId::VLink)
	this->__data.ptr = (void*)orig->value<class VLink*>();
      if (this->_type == typeId::Path)
	this->__data.ptr = (void*)orig->value<class Path*>();
      if (this->_type == typeId::Argument)
	this->__data.ptr = (void*)orig->value<class Argument*>();
      if (this->_type == typeId::List)
	{
	  std::list< Variant_p >*		lmine;
	  std::list< Variant_p >		lorig;
	  std::list< Variant_p >::iterator	it;

	  lorig = orig->value< std::list< Variant_p > >();
	  lmine = new std::list< Variant_p >;
	  for (it = lorig.begin(); it != lorig.end(); it++)
	    lmine->push_back(*it);
	  this->__data.ptr = (void*)lmine;
	}
      if (this->_type == typeId::Map)
	{
	  std::map<std::string, Variant_p >*		mmine;
	  std::map<std::string, Variant_p >		morig;
	  std::map<std::string, Variant_p >::iterator	mit;

	  mmine = new std::map<std::string, Variant_p >;
	  morig = orig->value< std::map<std::string, Variant_p > >();
	  for (mit = morig.begin(); mit != morig.end(); mit++)
	    mmine->insert(std::pair<std::string, Variant_p >(mit->first, mit->second));
	  this->__data.ptr = (void*)mmine;
	}
      if (this->_type == typeId::VoidPtr)
	this->__data.ptr = orig->value<void*>();
    }
  else
    throw (std::string("NULL Pointer provided"));
}

Variant::~Variant()
{
  if ((this->_type == typeId::String) || (this->_type == typeId::CArray))
    {      
      if (this->__data.str != NULL)
	delete this->__data.str;
      this->__data.str = NULL;
    }
  if (this->_type == typeId::DateTime)
    {
      if (this->__data.ptr != NULL)
	{
	  DateTime*	vt = (DateTime*)this->__data.ptr;
	  delete vt;
	}
      this->__data.ptr = NULL;
    }
  if (this->_type == typeId::List)
    {
      std::list<Variant_p >*		l;
      
      if (this->__data.ptr != NULL)
	{
	  l = (std::list< Variant_p >*)this->__data.ptr;
	  l->clear();
	  delete l;
	}
      this->__data.ptr = NULL;
    }
  if (this->_type == typeId::Map)
    {
      std::map<std::string, Variant_p >* m;
      if (this->__data.ptr != NULL)
	{
	  m = (std::map<std::string, Variant_p >*)this->__data.ptr;
	  m->clear();
	  delete m;
	}
    }
}


Variant::Variant(std::string str)
{
  this->__data.str = new std::string(str);
  this->_type = typeId::String;
}

Variant::Variant(char *carray) throw (std::string)
{
  if (carray != NULL)
    {
      this->__data.str = new std::string(carray);
      this->_type = typeId::CArray;
    }
  else
    throw (std::string("NULL Pointer provided"));
}

Variant::Variant(char c)
{
  this->__data.c = c;
  this->_type = typeId::Char;
}

Variant::Variant(int16_t s)
{
  this->__data.s = s;
  this->_type = typeId::Int16;
}

Variant::Variant(uint16_t us)
{
  this->__data.us = us;
  this->_type = typeId::UInt16;
}

Variant::Variant(int32_t i)
{
  this->__data.i = i;
  this->_type = typeId::Int32;
}

Variant::Variant(uint32_t ui)
{
  this->__data.ui = ui;
  this->_type = typeId::UInt32;
}

Variant::Variant(int64_t ll)
{
  this->__data.ll = ll;
  this->_type = typeId::Int64;
}

Variant::Variant(uint64_t ull)
{
  this->__data.ull = ull;
  this->_type = typeId::UInt64;
}

Variant::Variant(bool b)
{
  this->__data.b = b;
  this->_type = typeId::Bool;
}

Variant::Variant(DFF::DateTime *vt) throw (std::string)
{
  if (vt != NULL)
    {
      this->__data.ptr = (void*)vt;
      this->_type = typeId::DateTime;
    }
  else
    throw (std::string("NULL Pointer provided"));
}

Variant::Variant(class Node *node) throw (std::string)
{
  if (node != NULL)
    {
      this->__data.ptr = node;
      this->_type = typeId::Node;
    }
  else
    throw (std::string("NULL Pointer provided"));
}

Variant::Variant(class VLink *node) throw (std::string)
{
  if (node != NULL)
    {
      this->__data.ptr = node;
      this->_type = typeId::VLink;
    }
  else
    throw (std::string("NULL Pointer provided"));
}

Variant::Variant(Path *path) throw (std::string)
{
  if (path != NULL)
    {
      this->__data.ptr = path;
      this->_type = typeId::Path;
    }
  else
    throw (std::string("NULL Pointer provided"));
}

Variant::Variant(Argument *arg) throw (std::string)
{
  if (arg != NULL)
    {
      this->__data.ptr = arg;
      this->_type = typeId::Argument;
    }
  else
    throw (std::string("NULL Pointer provided"));
}

Variant::Variant(std::list< Variant_p > l)
{
  this->__data.ptr = (void*)new std::list< Variant_p >(l);
  this->_type = typeId::List;
}

Variant::Variant(std::map<std::string, Variant_p > m)
{
  this->__data.ptr = (void*)new std::map<std::string, Variant_p >(m);
  this->_type = typeId::Map;
}

Variant::Variant(void *user) throw (std::string)
{
  if (user != NULL)
    {
      this->__data.ptr = (void*)user;
      this->_type = typeId::VoidPtr;
    }
  else
    throw (std::string("NULL Pointer provided"));
}

std::string	Variant::toString() throw (std::string)
{
  std::stringstream	res;

  if (this->_type == typeId::Int16)
    res << this->__data.s;
  else if (this->_type == typeId::UInt16)
    res << this->__data.us;
  else if (this->_type == typeId::Int32)
    res << this->__data.i;
  else if (this->_type == typeId::UInt32)
    res << this->__data.ui;
  else if (this->_type == typeId::Int64)
    res << this->__data.ll;
  else if (this->_type == typeId::UInt64)
    res << this->__data.ull;
  else if (this->_type == typeId::Char)
    res << this->__data.c;
  else if ((this->_type == typeId::String || this->_type == typeId::CArray) && this->__data.str != NULL)
    res << *(this->__data.str);
  else if (this->_type == typeId::Path && this->__data.ptr != NULL)
    {
      class Path*	p;
      p = static_cast<class Path*>(this->__data.ptr);
      res << p->path;
    }
  else if (this->_type == typeId::Bool)
    {
      if (this->__data.b)
	res << "True";
      else
	res << "False";
    }
  else if (this->_type == typeId::DateTime && this->__data.ptr != NULL)
    {
      DateTime* vt = (DateTime*)this->__data.ptr;
      res << vt->toString(); 
    }
  else if (this->_type == typeId::List && this->__data.ptr != NULL)
    {
      std::list< Variant_p > l;
      std::list< Variant_p >::iterator lit;
      size_t		size;
      size_t		counter;
 
      l = *(static_cast<std::list< Variant_p > * >(this->__data.ptr));
      res << "[";
      size = l.size();
      counter = 0;
      for (lit = l.begin(); lit != l.end(); lit++)
	{
	  if ((*lit)->type() == typeId::String || (*lit)->type() == typeId::CArray || (*lit)->type() == typeId::Path)
	    res << "'" << (*lit)->toString() << "'";
	  else
	    res << (*lit)->toString();
	  counter++;
	  if (counter != size)
	    res << ", ";
	}
      res << "]";
    }
  else if (this->_type == typeId::Map && this->__data.ptr != NULL)
    {
      std::map<std::string, Variant_p > m;
      std::map<std::string, Variant_p >::iterator mit;
      size_t		size;
      size_t		counter;
 
      m = *(static_cast<std::map<std::string, Variant_p > * >(this->__data.ptr));
      res << "{";
      size = m.size();
      counter = 0;
      for (mit = m.begin(); mit != m.end(); mit++)
	{
	  res << "'";
	  res << mit->first;
	  res << "': ";
	  if (mit->second->type() == typeId::String || mit->second->type() == typeId::CArray || mit->second->type() == typeId::Path)
	    res << "'" << mit->second->toString() << "'";
	  else
	    res << mit->second->toString();
	  counter++;
	  if (counter != size)
	    res << ", ";
	}
      res << "}";
    }
  else if (this->_type == typeId::Node)
    res << " Node * at " << this->__data.ptr;
  else
    throw std::string("Cannot convert type < " + this->typeName() + " > to < std::string >");
  return res.str();
}

std::string	Variant::toHexString() throw (std::string)
{
  std::stringstream	res;
  
  if (this->_type == typeId::UInt16)
    res << "0x" << std::setw(2) << std::setfill('0') << std::hex << this->__data.us;
  else if (this->_type == typeId::UInt32)
    res << "0x" << std::setw(2) << std::setfill('0') << std::hex << this->__data.ui;
  else if (this->_type == typeId::UInt64)
    res << "0x" << std::setw(2) << std::setfill('0') << std::hex << this->__data.ull;
  else if (this->_type == typeId::Int16)
    res << "0x" << std::setw(2) << std::setfill('0') << std::hex << this->__data.s;
  else if (this->_type == typeId::Int32)
    res << "0x" << std::setw(2) << std::setfill('0') << std::hex << this->__data.i;
  else if (this->_type == typeId::Int64)
    res << "0x" << std::setw(2) << std::setfill('0') << std::hex << this->__data.ll;
  else if (this->_type == typeId::Char)
    res << "0x" << std::setw(2) << std::setfill('0') << std::hex << this->__data.c;
  else if ((this->_type == typeId::CArray) || (this->_type == typeId::String))
    {
      std::string::iterator	it;
      std::string		str = *(this->__data.str);

      for (it = str.begin(); it != str.end(); it++)
	{
	  res << std::setw(2) << std::setfill('0') << std::hex << static_cast<unsigned int>(static_cast<unsigned char>(*it));
	  res << " ";
	}
    }
  else
    throw std::string("Cannot represent type < " + this->typeName() + " > to an hexadecimal string");
  return res.str();
}

std::string	Variant::toOctString() throw (std::string)
{
  std::stringstream	res;
  
  res << std::oct << std::setiosflags (std::ios_base::showbase);
  if (this->_type == typeId::UInt16)
    res << this->__data.us;
  else if (this->_type == typeId::UInt32)
    res << this->__data.ui;
  else if (this->_type == typeId::UInt64)
    res << this->__data.ull;
  else if (this->_type == typeId::Int16)
    res << this->__data.s;
  else if (this->_type == typeId::Int32)
    res << this->__data.i;
  else if (this->_type == typeId::Int64)
    res << this->__data.ll;
  else if (this->_type == typeId::Char)
    res << this->__data.c;
  else
    throw std::string("Cannot represent type < " + this->typeName() + " > to an octal string");
  return res.str();
}

uint16_t	Variant::toUInt16() throw (std::string)
{
  uint16_t		res;
  std::stringstream	err;

  if (this->_type == typeId::UInt16)
    res = this->__data.us;
  else if (this->_type == typeId::UInt32)
    if (this->__data.ui <= UINT16_MAX)
      res = static_cast<uint16_t>(this->__data.ui);
    else
      err << "value [ " << this->__data.ui;
  else if (this->_type == typeId::UInt64)
    if (this->__data.ull <= UINT16_MAX)
      res = static_cast<uint16_t>(this->__data.ull);
    else
      err << "value [ " << this->__data.ull;
  else if (this->_type == typeId::Int16)
    if (this->__data.s >= 0)
      res = static_cast<uint16_t>(this->__data.s);
    else
      err << "value [ " << this->__data.s;
  else if (this->_type == typeId::Int32)
    if ((this->__data.i >= 0) && (this->__data.i <= UINT16_MAX))
      res = static_cast<uint16_t>(this->__data.i);
    else
      err << "value [ " << this->__data.i;
  else if (this->_type == typeId::Int64)
    if ((this->__data.ll >= 0) && (this->__data.ll <= UINT16_MAX))
      res = static_cast<uint16_t>(this->__data.ll);
    else
      err << "value [ " << this->__data.ll;
  else if (this->_type == typeId::Char)
    if (this->__data.c >= 0)
      res = static_cast<uint16_t>(this->__data.c);
    else
      err << "value [ " << this->__data.c;
  else if (this->_type == typeId::CArray)
    {
      std::istringstream istr(*(this->__data.str));
      if (!(istr >> res))
	err << "value [ " << *(this->__data.str);
    }
  else if (this->_type == typeId::String)
    {
      std::istringstream istr(*(this->__data.str));
      if (!(istr >> res))
	err << "value [ " << *(this->__data.str);
    }
  else
    throw std::string("type < " + this->typeName() + " > cannot be converted to < uint16_t >");
  if (!(err.str().empty()))
    {
      err << " ] of type < " << this->typeName() << " > does not fit in type < uint16_t >";
      throw err.str();
    }
  else
    return res;
}

int16_t		Variant::toInt16() throw (std::string)
{
  int16_t		res;
  std::stringstream	err;
  
  if (this->_type == typeId::Int16)
    res = this->__data.s;
  else if (this->_type == typeId::Int32)
    if ((this->__data.i >= INT16_MIN) && (this->__data.i <= INT16_MAX))
      res = static_cast<int16_t>(this->__data.i);
    else
      err << "value [ " << this->__data.i;
  else if (this->_type == typeId::Int64)
    if ((this->__data.ll >= INT16_MIN) && (this->__data.ll <= INT16_MAX))
      res = static_cast<int16_t>(this->__data.ll);
    else
      err << "value [ " << this->__data.ll;
  else if (this->_type == typeId::UInt16)
    if (this->__data.us <= INT16_MAX)
      res = static_cast<int16_t>(this->__data.us);
    else
      err << "value [ " << this->__data.us;
  else if (this->_type == typeId::UInt32)
    if (this->__data.ui <= INT16_MAX)
      res = static_cast<int16_t>(this->__data.ui);
    else
      err << "value [ " << this->__data.ui;
  else if (this->_type == typeId::UInt64)
    if (this->__data.ull <= INT16_MAX)
      res = static_cast<int16_t>(this->__data.ull);
    else
      err << "value [ " << this->__data.ull;
  else if (this->_type == typeId::Char)
    res = static_cast<int16_t>(this->__data.c);
  else if (this->_type == typeId::CArray)
    {
      std::istringstream istr(*(this->__data.str));
      if (!(istr >> res))
	err << "value [ " << *(this->__data.str);
    }
  else if (this->_type == typeId::String)
    {
      std::istringstream istr(*(this->__data.str));
      if (!(istr >> res))
	err << "value [ " << *(this->__data.str);
    }
  else
    throw std::string("type < " + this->typeName() + " > cannot be converted to < int16_t >");
  if (!(err.str().empty()))
    {
      err << " ] of type < " << this->typeName() << " > does not fit in type < int16_t >";
      throw err.str();
    }
  else
    return res;
}

uint32_t	Variant::toUInt32() throw (std::string)
{
  uint32_t		res;
  std::stringstream	err;
  
  if (this->_type == typeId::UInt16)
    res = static_cast<uint32_t>(this->__data.us);
  else if (this->_type == typeId::UInt32)
    res = this->__data.ui;
  else if (this->_type == typeId::UInt64)
    if (this->__data.ull <= UINT32_MAX)
      res = static_cast<uint32_t>(this->__data.ull);
    else
      err << "value [ " << this->__data.ull;
  else if (this->_type == typeId::Int16)
    if (this->__data.s >= 0)
      res = static_cast<uint32_t>(this->__data.s);
    else
      err << "value [ " << this->__data.s;
  else if (this->_type == typeId::Int32)
    if (this->__data.i >= 0)
      res = static_cast<uint32_t>(this->__data.i);
    else
      err << "value [ " << this->__data.i;
  else if (this->_type == typeId::Int64)
    if ((this->__data.ll >= 0) && (this->__data.ll <= UINT32_MAX))
      res = static_cast<uint32_t>(this->__data.ll);
    else
      err << "value [ " << this->__data.ll;
  else if (this->_type == typeId::Char)
    if (this->__data.c >= 0)
      res = static_cast<uint32_t>(this->__data.c);
    else
      err << "value [ " << this->__data.c;
  else if (this->_type == typeId::CArray)
    {
      std::istringstream istr(*(this->__data.str));
      if (!(istr >> res))
	err << "value [ " << *(this->__data.str);
    }
  else if (this->_type == typeId::String)
    {
      std::istringstream istr(*(this->__data.str));
      if (!(istr >> res))
	err << "value [ " << *(this->__data.str);
    }
  else
    throw std::string("type < " + this->typeName() + " > cannot be converted to < uint32_t >");
  if (!(err.str().empty()))
    {
      err << " ] of type < " << this->typeName() << " > does not fit in type < uint32_t >";
      throw err.str();
    }
  else
    return res;
}

int32_t		Variant::toInt32() throw (std::string)
{
  int32_t		res;
  std::stringstream	err;
  
  if (this->_type == typeId::Int16)
    res = static_cast<int32_t>(this->__data.s);
  else if (this->_type == typeId::Int32)
    res = this->__data.i;
  else if (this->_type == typeId::Int64)
    if ((this->__data.ll >= INT32_MIN) && (this->__data.ll <= INT32_MAX))
      res = static_cast<int32_t>(this->__data.ll);
    else
      err << "value [ " << this->__data.ll;
  else if (this->_type == typeId::UInt16)
    res = static_cast<int32_t>(this->__data.us);
  else if (this->_type == typeId::UInt32)
    if (this->__data.ui <= INT32_MAX)
      res = static_cast<int32_t>(this->__data.ui);
    else
      err << "value [ " << this->__data.ui;
  else if (this->_type == typeId::UInt64)
    if (this->__data.ull <= INT32_MAX)
      res = static_cast<int32_t>(this->__data.ull);
    else
      err << "value [ " << this->__data.ull;
  else if (this->_type == typeId::Char)
    res = static_cast<int32_t>(this->__data.c);
  else if (this->_type == typeId::CArray)
    {
      std::istringstream istr(*(this->__data.str));
      if (!(istr >> res))
	err << "value [ " << *(this->__data.str);
    }
  else if (this->_type == typeId::String)
    {
      std::istringstream istr(*(this->__data.str));
      if (!(istr >> res))
	err << "value [ " << *(this->__data.str);
    }
  else
    throw std::string("type < " + this->typeName() + " > cannot be converted to < int32_t >");
  if (!(err.str().empty()))
    {
      err << " ] of type < " << this->typeName() << " > does not fit in type < int32_t >";
      throw err.str();
    }
  else
    return res;
}

uint64_t	Variant::toUInt64() throw (std::string)
{
  uint64_t		res;
  std::stringstream	err;
  
  if (this->_type == typeId::UInt16)
    res = static_cast<uint64_t>(this->__data.us);
  else if (this->_type == typeId::UInt32)
    res = static_cast<uint64_t>(this->__data.ui);
  else if (this->_type == typeId::UInt64)
    res = this->__data.ull;
  else if (this->_type == typeId::Int16)
    if (this->__data.s >= 0)
      res = static_cast<uint64_t>(this->__data.s);
    else
      err << "value [ " << this->__data.s;
  else if (this->_type == typeId::Int32)
    if (this->__data.i >= 0)
      res = static_cast<uint64_t>(this->__data.i);
    else
      err << "value [ " << this->__data.i;
  else if (this->_type == typeId::Int64)
    if (this->__data.ll >= 0)
      res = static_cast<uint64_t>(this->__data.ll);
    else
      err << "value [ " << this->__data.ll;
  else if (this->_type == typeId::Char)
    if (this->__data.c >= 0)
      res = static_cast<uint64_t>(this->__data.c);
    else
      err << "value [ " << this->__data.c;
  else if (this->_type == typeId::CArray)
    {
      std::istringstream istr(*(this->__data.str));
      if (!(istr >> res))
	err << "value [ " << *(this->__data.str);
    }
  else if (this->_type == typeId::String)
    {
      std::istringstream istr(*(this->__data.str));
      if (!(istr >> res))
	err << "value [ " << *(this->__data.str);
    }
  else
    throw std::string("type < " + this->typeName() + " > cannot be converted to < uint64_t >");
  if (!(err.str().empty()))
    {
      err << " ] of type < " << this->typeName() << " > does not fit in type < uint64_t >";
      throw err.str();
    }
  else
    return res;
}

int64_t		Variant::toInt64() throw (std::string)
{
  int64_t		res;
  std::stringstream	err;
  
  if (this->_type == typeId::Int16)
    res = static_cast<int64_t>(this->__data.s);
  else if (this->_type == typeId::Int32)
    res = static_cast<int64_t>(this->__data.i);
  else if (this->_type == typeId::Int64)
    res = this->__data.ll;
  else if (this->_type == typeId::UInt16)
    res = static_cast<int64_t>(this->__data.us);
  else if (this->_type == typeId::UInt32)
    res = static_cast<int64_t>(this->__data.ui);
  else if (this->_type == typeId::UInt64)
    if (this->__data.ull <= INT64_MAX)
      res = static_cast<int64_t>(this->__data.ull);
    else
      err << "value [ " << this->__data.ull;
  else if (this->_type == typeId::Char)
    res = static_cast<int64_t>(this->__data.c);
  else if (this->_type == typeId::CArray)
    {
      std::istringstream istr(*(this->__data.str));
      if (!(istr >> res))
	err << "value [ " << *(this->__data.str);
    }
  else if (this->_type == typeId::String)
    {
      std::istringstream istr(*(this->__data.str));
      if (!(istr >> res))
	err << "value [ " << *(this->__data.str);
    }
  else
    throw std::string("type < " + this->typeName() + " > cannot be converted to < int64_t >");
  if (!(err.str().empty()))
    {
      err << " ] of type < " << this->typeName() << " > does not fit in type < int64_t >";
      throw err.str();
    }
  else
    return res;
}

char*	Variant::toCArray() throw (std::string)
{
  char		*res;
  std::string	str;

  try
    {
      res = new char[this->__data.str->size() + 1];
      memcpy(res, this->__data.str->c_str(), this->__data.str->size());
      res[this->__data.str->size()] = '\0';
    }
  catch (std::string e)
    {
      throw std::string("Cannot convert type < " + this->typeName() + " > to type <char*>");
    }
  return res;
}

char	Variant::toChar() throw (std::string)
{
  char			res;
  std::stringstream	err;

  if (this->_type == typeId::Char)
    res = this->__data.c;

  else if (this->_type == typeId::Int16)
    {
      if ((this->__data.s >= INT8_MIN) && (this->__data.s <= INT8_MAX))
	res = static_cast<char>(this->__data.s);
      else
	err << "value [ " << this->__data.s;
    }
  else if (this->_type == typeId::Int32)
    {
      if ((this->__data.i >= INT8_MIN) && (this->__data.i <= INT8_MAX))
	res = static_cast<char>(this->__data.i);
      else
	err << "value [ " << this->__data.i;
    }
  else if (this->_type == typeId::Int64)
    {
      if ((this->__data.ll >= INT8_MIN) && (this->__data.ll <= INT8_MAX))
	res = static_cast<char>(this->__data.ll);
      else
	err << "value [ " << this->__data.ll;
    }
  else if (this->_type == typeId::UInt16)
    {
      if ((this->__data.us >= INT8_MIN) && (this->__data.us <= INT8_MAX))
	res = static_cast<char>(this->__data.us);
      else
	err << "value [ " << this->__data.us;
    }
  else if (this->_type == typeId::UInt32)
    {
      if (this->__data.ui <= INT8_MAX)
	res = static_cast<char>(this->__data.ui);
      else
	err << "value [ " << this->__data.ui;
    }
  else if (this->_type == typeId::UInt64)
    {
      if(this->__data.ull <= INT8_MAX)
	res = static_cast<char>(this->__data.ull);
      else
	err << "value [ " << this->__data.ull;
    }
  else if (this->_type == typeId::CArray)
    {
      std::istringstream istr(*(this->__data.str));
      if (!(istr >> res))
	err << "value [ " << *(this->__data.str);
    }
  else if (this->_type == typeId::String)
    {
      std::istringstream istr(*(this->__data.str));
      if (!(istr >> res))
	err << "value [ " << *(this->__data.str);
    }
  else
    throw std::string("type < " + this->typeName() + " > cannot be converted to < char >");

  if (!(err.str().empty()))
    {
      err << " ] of type < " << this->typeName() << " > does not fit in type < char >";
      throw err.str();
    }
  else
    return res;
}

bool		Variant::toBool() throw (std::string)
{
  if (this->_type == typeId::Bool)
    return this->__data.b;
  else
    throw (std::string("value of type < " + this->typeName() + " > cannot be converted to < bool >"));
}

uint8_t		Variant::type()
{
  return this->_type;
}

std::string	Variant::typeName()
{
  return typeId::Get()->typeToName(this->_type);
}

bool	Variant::operator==(Variant* v)
{
  std::stringstream	tmp;

  if (v == NULL)
    return false;

  try
    {
      if (this->_type == typeId::Char)
	return (this->toChar() == v->toChar());

      else if (this->_type == typeId::Int16)
	return this->toInt16() == v->toInt16();

      else if (this->_type == typeId::Int32)
	return this->toInt32() == v->toInt32();

      else if (this->_type == typeId::Int64)
	return this->toInt64() == v->toInt64();

      else if (this->_type == typeId::UInt16)
	{
	  return this->toUInt16() == v->toUInt16();
	}

      else if (this->_type == typeId::UInt32)
	return this->toUInt32() == v->toUInt32();

      else if (this->_type == typeId::UInt64)
	return this->toUInt64() == v->toUInt64();
      
      else if (this->_type == typeId::Bool)
	return this->toBool() == v->toBool();

      else if (this->_type == typeId::String || this->_type == typeId::CArray)
	{
	  if ((v->type() == typeId::String) || (v->type() == typeId::CArray) || (v->type() == typeId::Char))
	    {
	      std::string	mine;
	      std::string	other;
	      
	      mine = this->toString();
	      other = v->toString();
	      return (mine == other);
	    }
	  else
	    return false;
	}

      else if (this->_type == typeId::DateTime)
        {
          if (v->type() == typeId::DateTime)
            {
              DateTime*    mine;
              DateTime*    other;
              
              mine = (DateTime*)this->__data.ptr;
              other = v->value<DateTime*>();
              return (mine->operator==(*other));
            }
          else
            return false;
        }

      else if (this->_type == typeId::Map)
	{
	  std::map<std::string, Variant_p >		mine;
	  std::map<std::string, Variant_p >		other;
	  std::map<std::string, Variant_p >::iterator	mit;
	  std::map<std::string, Variant_p >::iterator	oit;
	  
	  mine = *(static_cast<std::map<std::string, Variant_p > * >(this->__data.ptr));
	  other = v->value<std::map<std::string, Variant_p > >();
	  if (other.size() == mine.size())
	    {
	      for (mit = mine.begin(), oit = other.begin();
		   mit != mine.end(), oit != other.end();
		   mit++, oit++)
		if ((mit->first != oit->first) || (!(*(mit->second) == oit->second)))
		  return false;
	      return true;
	    }
	  else
	    return false;
	}
      else if (this->_type == typeId::List)
	{
	  std::list< Variant_p >			mine;
	  std::list< Variant_p >			other;
	  std::list< Variant_p >::iterator	mit;
	  std::list< Variant_p >::iterator	oit;

	  mine = *(static_cast<std::list< Variant_p > * >(this->__data.ptr));
	  other = v->value<std::list< Variant_p > >();
	  if (other.size() == mine.size())
	    {
	      for (mit = mine.begin(), oit = other.begin(); 
		   mit != mine.end(), oit != other.end();
		   mit++, oit++)
		if (!(*(*mit) == *oit))
		  return false;
	      return true;
	    }
	  else
	    return false;
	}
      else
	return false;
    }
  catch (std::string e)
    {
      return false;
    }
}

bool	Variant::operator!=(Variant* v)
{
  return !(this->operator==(v));
}

bool	Variant::operator>(Variant* v)
{
  int64_t	ll;
  uint64_t	ull;

  int64_t	oll;
  uint64_t	oull;
  uint8_t	otype;

  if (v == NULL)
    return true;

  if (this->operator==(v))
    return false;

  otype = v->type();
  if ((this->_type == typeId::Char) ||
      (this->_type == typeId::Int16) ||
      (this->_type == typeId::Int32) ||
      (this->_type == typeId::Int64))
    {
      ll = this->toInt64();
      if ((otype == typeId::Char) ||
	  (otype == typeId::Int16) ||
	  (otype == typeId::Int32) ||
	  (otype == typeId::Int64))
	return (ll > v->toInt64());
      
      else if ((ll >= 0) &&
	       ((otype == typeId::UInt16) ||
		(otype == typeId::UInt32) ||
		(otype == typeId::UInt64)))
	{
	  ull = static_cast<uint64_t>(ll);
	  return (ull > v->toUInt64());
	}
      else
	return false;
    }
  else if ((this->_type == typeId::UInt16) ||
	   (this->_type == typeId::UInt32) ||
	   (this->_type == typeId::UInt64))
    {
      ull = this->toUInt64();
      if ((otype == typeId::UInt16) ||
	  (otype == typeId::UInt32) ||
	  (otype == typeId::UInt64))
	return (ull > v->toUInt64());
      else if ((otype == typeId::Char) ||
	       (otype == typeId::Int16) ||
	       (otype == typeId::Int32) ||
	       (otype == typeId::Int64))
	{
	  oll = v->toInt64();
	  if (oll >= 0)
	    {
	      oull = static_cast<uint64_t>(oll);
	      return (ull > oull);
	    }
	  else
	    return true;
	}
      else
	return false;
    }
  else if (this->_type == typeId::String || this->_type == typeId::CArray)
    {
      if ((v->type() == typeId::String) || (v->type() == typeId::CArray) || (v->type() == typeId::Char))
	{
	  std::string	mine;
	  std::string	other;
	  
	  mine = this->toString();
	  other = v->toString();
	  return (mine > other);
	}
      else
	return true;
    }
  else if (this->_type == typeId::DateTime)
    {
      if (v->type() == typeId::DateTime)
        {
          DateTime*        mine;
          DateTime*        other;
          
          mine = (DateTime*)this->__data.ptr;
          other = v->value<DateTime*>();
          return (mine->operator>(*other)); //XXX check for null pointer before deferencing ?
        }
      else
        return false;
    }
  return false;
}

bool	Variant::operator>=(Variant* v)
{
  if (this->operator>(v) || this->operator==(v))
    return true;
  else
    return false;
}

bool	Variant::operator<(Variant* v)
{
  if (this->operator==(v))
    return false;
  else
    return !(this->operator>(v));
}

bool	Variant::operator<=(Variant* v)
{
  if (this->operator<(v) || this->operator==(v))
    return true;
  else
    return false;
}

}
