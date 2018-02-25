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
 *  Christophe Malinge <cma@digital-forensic.org>
 */

#include "wlocalnode.hpp"
#include "datetime.hpp"
#include <windows.h>

WLocalNode::WLocalNode(std::string Name, uint64_t size, Node* parent, fso* fsobj, uint8_t type, std::string origPath): Node(Name, size, parent, fsobj)
{
  switch (type)
  {
    case DIR:
      this->setDir();
      break;
    case FILE:
      this->setFile();
      break;
    default:
      break;
  }
  this->originalPath = origPath;
}

WLocalNode::~WLocalNode()
{
}

Attributes		WLocalNode::_attributes(void)
{
  WIN32_FILE_ATTRIBUTE_DATA	info;
  Attributes                    attr;
   
	
  attr["original path"] = Variant_p(new Variant(this->originalPath));
  if (!GetFileAttributesExA(this->originalPath.c_str(), GetFileExInfoStandard, &info))
    return (attr);
	
  attr["modified"] = Variant_p(new Variant(this->wtimeToDateTime(&(info.ftLastWriteTime))));
  attr["accessed"] = Variant_p(new Variant(this->wtimeToDateTime(&(info.ftLastAccessTime))));
  attr["creation"] = Variant_p(new Variant(this->wtimeToDateTime(&(info.ftCreationTime))));

  return (attr);
}


DateTime*				WLocalNode::wtimeToDateTime(FILETIME *tt)
{
  if (tt == NULL)
    return (new DateTime(0));

  SYSTEMTIME	st;
  if (FileTimeToSystemTime(tt, &st) == 0)
    return (new DateTime(0));

  return (new DateTime(st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond));
}
