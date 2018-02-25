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

%module ntfs
 
%include "std_string.i"
%include "std_list.i"
%include "std_set.i"
%include "std_map.i"
%include "std_vector.i"
%include "windows.i"

%ignore NTFS::fsNode;
%ignore NTFS::bootSectorNode;
%ignore NTFS::rootDirectoryNode;
%ignore NTFS::orphansNode;
%ignore NTFS::unallocatedNode;

%{
#include "ntfs.hpp"
%}

%import "../../../api/vfs/libvfs.i"
%include "ntfs.hpp"

%pythoncode
%{
from dff.api.module.module import * 
from dff.api.types.libtypes import * 

class ntfs(Module):
  def __init__(self):
    Module.__init__(self, 'ntfs', NTFS)
    self.conf.addArgument({"name": "file",
                           "description": "Path to a file containing NTFS",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addArgument({"name" : "recovery",
                           "description" : "If set the module will try to recover files and folders by carving MFT in unallocated clusters",
                           "input": Argument.Empty})
    self.conf.addArgument({"name" : "advanced-attributes",
                           "description" : "Provides advanced attributes for nodes",
                           "input": Argument.Empty})
    self.conf.addArgument({"name" : "no-bootsector-check",
                           "description" : "If set the module will continue even if the bootsector is corrupted",
                           "input": Argument.Empty})
    self.conf.addConstant({"name": "mime-type",
                           "description": "managed mime type",
                           "type" : typeId.String,
                           "values" : ["filesystem/ntfs"]})
    self.conf.addArgument({"name" : "drive-name",
                          "description": "Use this drive name to link reparse point and symlink",
                          "input" : Argument.Optional|Argument.Single|typeId.String,
                          "values": ["C:"]})
    self.conf.description = "Creates a tree from a NTFS file system, for regular and deleted/orphan files and folders.\nIt also provides human-readable dump of MFT or Indexex entries."
    self.tags = "File systems"
%}
