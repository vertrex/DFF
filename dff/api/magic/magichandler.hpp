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
 *  Frederic B. <fba@digital-forensic.org>
 */


#include <string>

#include "node.hpp"
#include "datatype.hpp"
#include "export.hpp"

class MagicHandler : public DataTypeHandler
{
private:
  std::string	__magic(void* buffer, uint32_t size);
public:
  EXPORT MagicHandler();
  EXPORT ~MagicHandler();
  EXPORT virtual std::string	type(Node* node);
};
