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

#ifndef __DISKDESCRIPTOR_HPP__
#define __DISKDESCRIPTOR_HPP__

#ifndef WIN32
  #include <stdint.h>
#elif _MSC_VER >= 1600
  #include <stdint.h>
#else
  #include "wstdint.h"
#endif

#define CID "CID"
#define PCID "parentCID"
#define PARENT_FILE_NAME "parentFileNameHint"
#define CID_NOPARENT "ffffffff"

#include <string>
#include <list>
#include <map>

namespace DFF
{
class Node;
}

class	diskDescriptor
{
public:
  // type: 0=Sparse 2Gb extent text descriptor, 1=descriptor embeded into extent
  diskDescriptor(DFF::Node	*nodeDesc, int type);
  ~diskDescriptor();

  /* Read disk descriptor from and fill _descData buffer*/
  void	readDiskDescriptor(DFF::Node *nodeDesc, uint32_t offset, uint32_t size);
  void	readMonoDiskDescriptor(DFF::Node *nodeDesc);

  /* Split _descData into lines*/
  void	getLinesDiskDescriptor(char *descData);
  /* Fill _descMap (all key=value system) and _descExtents */
  void	parseLineDiskDescriptor();

  std::string		parseExtentName(std::string str);
  int			createExtentNames();

  std::list<std::string>	getExtentNames();

  void	setParentFileName();

  void	setCID();
  void	setPCID();

  std::string	parentFileName();
  std::string		getCID();
  std::string		getPCID();


private:

  DFF::Node			*_nodeDesc;

  int			_type;
  // Text Disk Description 
  char*			_data;
  std::list<char*>		_lines;
  std::list<std::string>		_extents;
  std::list<std::string>		_extNames;
  std::map<std::string, std::string>	_map;

  std::string		_CID;
  std::string 		_PCID;
  std::string		_parentFileName;

};

#endif
