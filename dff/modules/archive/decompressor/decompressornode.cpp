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

#include <archive.h>
#include <archive_entry.h>

#include "datetime.hpp"

#include "decompressor.hpp"
#include "decompressornode.hpp"

using namespace DFF;

DecompressorNode::DecompressorNode(std::string name, uint64_t size, Node* parent, Decompressor* decompressor, archive_entry* entry) : Node(name, size, parent, decompressor), __archive(NULL)
{
  uint64_t time = 0;
  if (archive_entry_atime_is_set(entry) && (time = archive_entry_atime(entry)))
      this->__timeAttributes["accessed"] = time;
 
  if (archive_entry_birthtime_is_set(entry) && (time = archive_entry_birthtime(entry)))
    this->__timeAttributes["birthtime"] = time;
  
  if (archive_entry_ctime_is_set(entry) && (time = archive_entry_ctime(entry)))
    this->__timeAttributes["created"] = time;

  if (archive_entry_mtime_is_set(entry) && (time = archive_entry_mtime(entry)))
    this->__timeAttributes["modified"] = time;
}

DecompressorNode::~DecompressorNode()
{
}

archive*        DecompressorNode::archive(void) const
{
 return (this->__archive);
}

void            DecompressorNode::archive(struct archive* archiv)
{
  this->__archive = archiv;
}

Attributes       DecompressorNode::_attributes()
{
  Attributes attributes;

  std::map<std::string, uint64_t>::const_iterator timeAttribute = this->__timeAttributes.begin();
  for (; timeAttribute != this->__timeAttributes.end(); ++timeAttribute)
     attributes[timeAttribute->first] = Variant_p(new Variant(new DateTime(timeAttribute->second)));

  return (attributes);
}
