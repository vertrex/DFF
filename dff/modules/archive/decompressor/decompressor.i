/* 
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
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
 *  Solal Jacob <sja@digital-forensic.org>
 */

%module decompressor 

%include "windows.i"
%include "exception.i"

%{
#include "mfso.hpp"
#include "exceptions.hpp"
#include "fso.hpp"
#include "rootnode.hpp"
#include "node.hpp"
#include "vlink.hpp"
#include "decompressor.hpp"
%}

%import "../../../api/vfs/libvfs.i"

%include "decompressor.hpp"


%pythoncode
%{
from dff.api.module.module import * 
from dff.api.types.libtypes import * 

class decompressor(Module):
  def __init__(self):
    Module.__init__(self, 'uncompress', Decompressor)
    self.conf.addArgument({"name": "file",
                           "description": "Path to an archive or compressed file",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addConstant({"name": "mime-type",
                           "description": "managed mime type",
                           "type" : typeId.String,
                           "values" : ["archive/zip", "archive/rar", "archive/tar", "archive/cab", "archive/7zip", "archive/bzip2", "archive/gzip", "archive/lzma", "archive/cpio", "archive/xz", "archive/lzip", "archive/zlib", "filesystem/iso9660"]}) #filetype .iso because is not detect by magic as buffer is too small 0x2000 and need more than 0x8000 for iso 
    self.conf.description = "Unarchive & decompress zip, rar, cab, 7zip, iso9660, tar, ..."
    self.tags = "Archive"
%}
