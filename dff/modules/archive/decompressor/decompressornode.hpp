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

#ifndef __DECOMPRESSOR_NODE_HH__
#define __DECOMPRESSOR_NODE_HH__

#include "node.hpp"
#include "variant.hpp"

class Decompressor;
struct archive;
struct archive_entry;

using namespace DFF;

class DecompressorNode : public DFF::Node
{
public:
  DecompressorNode(std::string name, uint64_t size, Node* parent, Decompressor* decompressor, archive_entry* entry);
  ~DecompressorNode();
  struct archive*       archive(void) const;
  void                  archive(struct archive* archiv);
  Attributes            _attributes();
private:
  struct archive*                 __archive;
  std::map<std::string, uint64_t> __timeAttributes;
};

#endif
