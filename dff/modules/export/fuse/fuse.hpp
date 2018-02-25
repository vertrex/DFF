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

#ifndef __FUSE_HH__
#define __FUSE_HH__

#define FUSE_USE_VERSION 26
#include <fuse.h>
#include "mfso.hpp"

using namespace DFF;

class fuse : public mfso
{
private:
  struct fuse_args	__arguments;
  struct fuse_chan*	__channel;
  struct fuse*		__handle;
  std::string		__mnt;
  void			__cleanContext();
  void			__addArgument(std::string arg) throw (std::string);
public:
  fuse();
  ~fuse();
  virtual void		start(std::map<std::string, Variant_p > args);
};

#endif 
