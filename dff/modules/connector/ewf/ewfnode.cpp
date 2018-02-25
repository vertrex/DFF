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

#include "ewfnode.hpp"

#include <iostream>

#include "typesconv.hpp"

std::string	EWFNode::__getHashIdentifier(uint32_t index) throw()
{
  size_t	id_size;
  uint8_t*	id;
  std::string	identifier;
  
  identifier = "";
  if (libewf_handle_get_hash_value_identifier_size(this->ewfso->ewf_ghandle, index, &id_size, NULL) == 1)
    {
      id = new uint8_t[id_size];
      if (libewf_handle_get_hash_value_identifier(this->ewfso->ewf_ghandle, index, id, id_size, NULL) == 1)
	identifier = std::string((char*)id);
      delete[] id;
    }
  return identifier;
}

std::string	EWFNode::__getHashValue(std::string identifier) throw ()
{
  size_t	val_size;
  uint8_t*	val;
  std::string	value;

  value = "";
  if (libewf_handle_get_utf8_hash_value_size(this->ewfso->ewf_ghandle, (uint8_t*)identifier.c_str(), identifier.size(), &val_size, NULL) == 1)
    {
      val = new uint8_t[val_size];
      if (libewf_handle_get_utf8_hash_value(this->ewfso->ewf_ghandle, (uint8_t*)identifier.c_str(), identifier.size(), val, val_size, NULL) == 1)
	value = std::string((char*)val);
      delete[] val;
    }
  return value;
}

std::string	EWFNode::__getIdentifier(uint32_t index) throw ()
{
  size_t	id_size;
  uint8_t*	id;
  std::string	identifier;

  identifier = "";
  if (libewf_handle_get_header_value_identifier_size(this->ewfso->ewf_ghandle, index, &id_size, NULL) == 1)
    {
      id = new uint8_t[id_size];
      if (libewf_handle_get_header_value_identifier(this->ewfso->ewf_ghandle, index, id, id_size, NULL) == 1)
	identifier = std::string((char*)id);
      delete[] id;
    }
  return identifier;
}

std::string		EWFNode::__getValue(std::string identifier) throw ()
{
  size_t	val_size;
  uint8_t*	val;
  std::string	value;

  value = "";
  if (libewf_handle_get_utf8_header_value_size(this->ewfso->ewf_ghandle, (uint8_t*)identifier.c_str(), identifier.size(), &val_size, NULL) == 1)
    {
      val = new uint8_t[val_size];
      if (libewf_handle_get_utf8_header_value(this->ewfso->ewf_ghandle, (uint8_t*)identifier.c_str(), identifier.size(), val, val_size, NULL) == 1)
	value = std::string((char*)val);
      delete[] val;
    }
  return value;
}

Attributes	EWFNode::_attributes()
{
  Attributes 	attr;
  uint32_t	numval;
  std::string	identifier;
  std::string	value;
  
  
  if (libewf_handle_set_header_values_date_format(this->ewfso->ewf_ghandle, LIBEWF_DATE_FORMAT_CTIME, NULL) == 1)
    {
      if (libewf_handle_get_number_of_header_values(this->ewfso->ewf_ghandle, &numval, NULL) == 1)
	{
	  for (uint32_t i = 0; i != numval; i++)
	    {
	      try
		{
		  identifier = this->__getIdentifier(i);
		  if (!identifier.empty())
		    {
		      value = this->__getValue(identifier);
		      if (!value.empty())
			attr[identifier] = Variant_p(new Variant(value));
		    }
		}
	      catch (std::exception)
		{
		}
	    }
	}
    }
  if (libewf_handle_get_number_of_hash_values(this->ewfso->ewf_ghandle, &numval, NULL) == 1)
    {
      for (uint32_t i = 0; i != numval; i++)
	{
	  try
	    {
	      identifier = this->__getHashIdentifier(i);
	      if (!identifier.empty())
		{
		  value = this->__getHashValue(identifier);
		  if (!value.empty())
		    attr[identifier] = Variant_p(new Variant(value));
		}
	    }
	  catch (std::exception)
	    {
	    }
	}
    }

  return attr;
}


EWFNode::EWFNode(std::string Name, uint64_t size, Node* parent, ewf* fsobj, std::list<Variant_p > origPath): Node(Name, size, parent, fsobj)
{
  this->originalPath = origPath;
  this->ewfso = fsobj;
}

EWFNode::~EWFNode()
{
}
