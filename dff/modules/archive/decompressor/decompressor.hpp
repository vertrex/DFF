/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *  
 * See http: *www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 * 
 * Author(s):
 *  Solal Jacob <sja@digital-forensic.org>
 */

#ifndef __DECOMPRESSOR_HH__
#define __DECOMPRESSOR_HH__

#ifdef WIN32
typedef __int64 ssize_t;
#endif

#include <archive.h>
#include <archive_entry.h>

#include "fso.hpp"
#include "exceptions.hpp"
#include "fdmanager.hpp"
#include "node.hpp"
#include "vfile.hpp"



//struct archive;

namespace DFF
{
class Node;
class VFile;
class FdManager;
}

#define ArchiveDataBufferSize           16384

class DecompressorFdinfo : public DFF::fdinfo
{
public:
  DecompressorFdinfo();
  archive*      arch;
  uint64_t      archiveReadOffset;
};

class ArchiveData 
{
public:
  ArchiveData(DFF::Node* node);
  ~ArchiveData();

  DFF::Node*    node;
  DFF::VFile*   vfile;
  void*         buffer;
};

class Decompressor : public DFF::fso
{
public:
  Decompressor();
  ~Decompressor();
  void                  start(DFF::Attributes args);
  archive*              newArchive(void);
  void                  createNodeTree(archive* archiv);
  archive*              openNodeArchive(DFF::Node* node);

  int32_t 		vopen(DFF::Node *n);
  int32_t 		vread(int32_t fd, void *rbuff, uint32_t size);
  uint64_t		vseek(int32_t fd, uint64_t offset, int32_t whence);
  uint32_t		status(void);
  uint64_t		vtell(int32_t fd);
  int32_t 		vclose(int32_t fd);
  int32_t		vwrite(int fd, void *buff, unsigned int size); 
  void                  setStateInfo(const std::string&);
  DFF::Node*            rootNode(void) const;

  static int	        archiveOpen(archive *, void *dffarchivedata);
  static ssize_t	archiveRead(archive *,void *dffarchivedata , const void **_buffer);
  static int64_t	archiveSeek(archive *, void *dffarchivedata, int64_t offset, int whence);
  static int	        archiveClose(archive *, void *dffarchivedata);
private:
  DFF::Node*            __rootNode;
  DFF::FdManager*       __fdManager;
};

#endif
