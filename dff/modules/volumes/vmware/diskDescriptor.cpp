/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2013 ArxSys
 *
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
 *  MOUNIER Jeremy <jmo@digital-forensic.org>
 *
 */

#include <algorithm>

#include "vmdk.hpp"
#include "diskDescriptor.hpp"

#include "exceptions.hpp"
#include "node.hpp"

using namespace DFF;

diskDescriptor::diskDescriptor(Node *nodeDesc, int type)
{
  this->_nodeDesc = nodeDesc;
  this->_type = type;

  if (type == 0)
    this->readDiskDescriptor(this->_nodeDesc, 0, this->_nodeDesc->size());
  else
    this->readMonoDiskDescriptor(this->_nodeDesc);

  this->getLinesDiskDescriptor(this->_data);

  this->parseLineDiskDescriptor();

  this->createExtentNames();

  this->setParentFileName();
  this->setCID();
  this->setPCID();
    
}

diskDescriptor::~diskDescriptor()
{
}

void	diskDescriptor::readDiskDescriptor(Node *nodeDesc, unsigned int offset, unsigned int size)
{

  VFile *vmdk = nodeDesc->open();

  this->_data = (char*)malloc(size);
  if (this->_data != NULL)
    {
      memset(this->_data, '\0', size);
      // Read descriptor
      try
	{
	  vmdk->seek(offset);
	  vmdk->read(this->_data, size - 1);
	}
      catch (envError & e)
	{
  	  vmdk->close();
	  std::cerr << "Error reading vmdk descriptor : arg->get(\"parent\", &_node) failed." << std::endl;
	  throw e;
	}
    }
  
  vmdk->close();

}

void	diskDescriptor::readMonoDiskDescriptor(Node *nodeDesc)
{

  sparseExtentHeader header;
  VFile *vfile = nodeDesc->open();

  try
    {
      vfile->seek(0);
      vfile->read(&header, sizeof(SparseExtentHeader));
    }
  catch (envError & e)
    {
      std::cerr << "Error reading vmdk descriptor : arg->get(\"parent\", &_node) failed." << std::endl;
      vfile->close();
      throw e;
    }

  vfile->close();

  uint32_t descoffset = (header.descriptorOffset * SECTOR_SIZE);
  uint32_t descsize = (header.descriptorSize * SECTOR_SIZE);

  this->readDiskDescriptor(nodeDesc, descoffset, descsize);
}

void	diskDescriptor::parseLineDiskDescriptor()
{
  std::list<char*>::iterator	i;
  unsigned int cp = 0;
  unsigned int len;
  // Is Key Value structure 
  bool	isKV = false;
  // Is Extent structure : 'R'W SPARSE ....
  bool	isEX = false;

  for (i = this->_lines.begin(); i != this->_lines.end(); i++)
    {
      char* pTmp = *i;
      isKV = false;
      isEX = false;
      // clean start of key's line
      while (*pTmp == ' ' || *pTmp == '\t')
	pTmp++;

      char *pStart = pTmp;
      cp = 0;

      // If start is R, think that is an extent line
      if (*pTmp == 'R')
	isEX = true;

      // Get key len
      len = strlen(*i);
      while (cp != len)
	{
	  if (*pTmp == '=')
	    {
	      isKV = true;
	      break;
	    }
	  pTmp++;
	  cp++;
	}
      // If = is detected
      if (isKV)
	{
	  char* key = (char*)malloc(cp + 1);
	  memset(key, '\0', cp + 1);
	  memcpy(key, pStart, cp);
	  
	  // clean start of value's line ( = and others)
	  pTmp++;
	  while (*pTmp == ' ' || *pTmp == '\t')
	    {
	      cp++;
	      pTmp++;
	    }
	  int vsize = len - cp;	  
	  char* value = (char*)malloc(vsize + 1);
	  memset(value, '\0', vsize + 1);
	  memcpy(value, pTmp, vsize);

	  // create KV string and clean it
	  std::string skey = key;
	  std::string::iterator kend_pos = std::remove(skey.begin(), skey.end(), ' ');
	  skey.erase(kend_pos, skey.end());

	  std::string svalue = value;
	  std::string::iterator vend_pos = std::remove(svalue.begin(), svalue.end(), '"');
	  svalue.erase(vend_pos, svalue.end());

	  this->_map.insert(std::pair<std::string, std::string>(skey, svalue));

	}
      //if = is not detected and line start with 'R'
      else if (!isKV && isEX)
	{
	  char* extent = (char*)malloc(cp + 1);
	  memset(extent, '\0', cp + 1);
	  memcpy(extent, pStart, cp);
	  
	  std::string sextent = extent;
	  this->_extents.push_back(sextent);
	}
    }

}

void	diskDescriptor::getLinesDiskDescriptor(char *descData)
{
  char* pTmp = descData;
  int	llen = 0;

  while (*pTmp != '\0')
    {
      char *pStart = pTmp;
      // get Line length
      while (*pTmp != '\n' && *pTmp != '\0')
	{
	  pTmp++;
	  llen++;
	}

      char* line = (char*)malloc(llen +1);
      memset(line, '\0', llen + 1);
      memcpy(line, pStart, llen);
      
      this->_lines.push_back(line);

      if (*pTmp != '\0')
	{
	  llen = 0;
	  pTmp++;
	}
    }
}


std::string		diskDescriptor::parseExtentName(std::string str)
{

  std::string res = str;
  size_t found;

  found = res.find("\"");
  res.erase(0,found + 1);
  res.erase(res.size() - 1,1);
  return res;
}

int		diskDescriptor::createExtentNames()
{
  for( std::list<std::string>::iterator ext=this->_extents.begin(); ext!=this->_extents.end(); ++ext)
    {
      std::string extname = parseExtentName((*ext));
      this->_extNames.push_back(extname);
    }
    return (0);
}

void	diskDescriptor::setParentFileName()
{
  this->_parentFileName = this->_map[PARENT_FILE_NAME];    
}
void	diskDescriptor::setCID()
{

  this->_CID = this->_map[CID];
}

void	diskDescriptor::setPCID()
{
  this->_PCID = this->_map[PCID];
}

std::string	diskDescriptor::parentFileName()
{
  return this->_parentFileName;
}

std::string	diskDescriptor::getCID()
{
  return this->_CID;
}

std::string	diskDescriptor::getPCID()
{
  return this->_PCID;
}

std::list<std::string>	diskDescriptor::getExtentNames()
{
  return this->_extNames;
}
