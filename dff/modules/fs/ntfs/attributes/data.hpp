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

#ifndef __DATA_HH__ 
#define __DATA_HH__

#include "ntfs_common.hpp"
#include "mftattributecontent.hpp"

#define NTFS_TOKEN_MASK   1
#define NTFS_SYMBOL_TOKEN 0
#define NTFS_TOKEN_LENGTH 8
/* (64 * 1024) = 65536 */
#define NTFS_MAX_UNCOMPRESSION_BUFFER_SIZE 65536

class CompressionInfo
{
public:
  CompressionInfo(uint64_t runSize);
  ~CompressionInfo();
  char*  uncomp_buf;           // Buffer for uncompressed data
  char*  comp_buf;             // buffer for compressed data
  size_t comp_len;            // number of bytes used in compressed data
  size_t uncomp_idx;          // Index into buffer for next byte
  size_t buf_size_b;          // size of buffer in bytes (1 compression unit)
};

class Data : public MFTAttributeContent
{
public:
  Data(MFTAttribute* mftAttribute);
  ~Data();
  static MFTAttributeContent*	create(MFTAttribute* mftAttribute);
  const std::string             typeName(void) const;
  Attributes                    _attributes(void);
  uint64_t                      uncompress(uint8_t* buff, uint64_t size, uint64_t offset, uint32_t compressionBlockSize);
private:
  uint64_t                      __readBlock(VFile* fs, RunList run, uint8_t** data, int64_t runSize, uint64_t* lastValidOffset, uint32_t compressionBlockSize);
  void                          __uncompressBlock(CompressionInfo* comp); 
};

#endif
