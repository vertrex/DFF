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

#ifndef __MAGICHANDLER_HPP__
#define __MAGICHANDLER_HPP__

#include "datatype.hpp"
#include "vfile.hpp"
#include <magic.h>

namespace DFF
{

class MagicType : public DataTypeHandler
{
protected:
  magic_t	_ctx;
  std::string	_mfile;
  bool		_ready;
  void*		_buff;
public:
  EXPORT MagicType(std::string name, int flags) throw (std::string);
  EXPORT ~MagicType();
  EXPORT virtual std::string	type(Node* node) = 0;
  EXPORT bool			setMagicFile(std::string mfile) throw (std::string);
  EXPORT std::string		magicFile();
};

class MagicHandler : public MagicType
{
private:
  EXPORT			MagicHandler() : MagicType("magic", MAGIC_NONE) {}
  EXPORT			~MagicHandler() {}
  MagicHandler&			operator=(MagicHandler&);
  MagicHandler(const MagicHandler&);
public:
  EXPORT static MagicHandler*	Get() throw (std::string);
  EXPORT virtual std::string	type(Node* node);
};

class MimeHandler : public MagicType
{
private:
  EXPORT			MimeHandler() : MagicType("magic mime", MAGIC_MIME) {}
  EXPORT			~MimeHandler() {}
  MimeHandler&			operator=(MimeHandler&);
  MimeHandler(const MimeHandler&);
public:
  EXPORT static MimeHandler*	Get() throw (std::string);
  EXPORT virtual std::string	type(Node* node);
};

}
#endif
