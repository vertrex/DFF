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

#ifndef __BITLOCKER_HH__
#define __BITLOCKER_HH__

#include "libbde.h"

#include "fso.hpp"
#include "node.hpp"
#include "threading.hpp"
#include "fdmanager.hpp"

using namespace DFF;

class BitLockerVolumeNode;

class BitLocker : public DFF::fso
{
public:
  BitLocker();
  ~BitLocker();
 
  virtual void		start(std::map<std::string, Variant_p > args);
  void                  setEncryptionKey(std::map<std::string, Variant_p >& args);
  void                  openVolume(void);

  int32_t		vopen(Node* handle);
  int32_t 		vread(int fd, void *buff, unsigned int size);
  int32_t 		vclose(int fd);
  uint64_t 		vseek(int fd, uint64_t offset, int whence);
  int32_t		vwrite(int fd, void *buff, unsigned int size) { return 0; };
  uint32_t		status(void);
  uint64_t		vtell(int32_t fd);
private:
  mutex_def(__io_mutex);
  Node*			__parent;
  FdManager*            __fdm;
  libbde_volume_t*      __volume;
  BitLockerVolumeNode*  __volumeNode;
};
#endif
