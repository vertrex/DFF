/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2013 ArxSys
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
 *  Romain Bertholon <rbe@digital-forensic.org>
 *
 */

#include "pyrun.swg"

%module  EXTFS

%include "std_string.i"
%include "std_list.i"
%include "std_set.i"
%include "std_map.i"
%include "std_vector.i"
%include "windows.i"

%{
#include "extfs.hpp"
%}

%import "../../../api/vfs/libvfs.i"

%include "extfs.hpp"

/*
namespace std
{
}; */

%pythoncode
%{

__dff_module_extfs_version__ = "1.0.0"

from dff.api.module.module import *
from dff.api.types.libtypes import Argument, typeId, Parameter

class EXTFS(Module):
  """This module parses extented file system (EXT 2/3/4) and tries to recover deleted data."""
  def __init__(self):

    Module.__init__(self, 'extfs', Extfs)

    self.conf.addArgument({"name": "file",
                           "description": "file containing an EXT 2, 3 or 4 file system",
                           "input": Argument.Required|Argument.Single|typeId.Node})

    self.conf.addArgument({"name": "blockpointers",
                           "description": "Add block pointer as extfs extended attributes",
                           "input": Argument.Empty})

    self.conf.addArgument({"name": "dont_parse_fs",
                           "description": "Parse the entire file system.",
                           "input": Argument.Empty})

    self.conf.addArgument({"name": "ils",
                           "description": "List inodes",
                           "input": Argument.Optional|typeId.String|Argument.Single,
                           "parameters":{"type":Parameter.Editable}
                         })

    self.conf.addArgument({"name": "blk",
                           "description": "Block allocation status",
                           "input": Argument.Optional|typeId.String|Argument.Single,
                           "parameters":{"type":Parameter.Editable}
                          })

    self.conf.addArgument({"name": "fsstat",
                           "description": "File system statistic",
                           "input": Argument.Empty})

    self.conf.addArgument({"name": "istat",
                           "description": "Inode statistics",
                           "input": Argument.Optional|typeId.String|Argument.Single,
                           "parameters": {"type": Parameter.Editable}
                          })

    self.conf.addArgument({"name": "fsck",
                           "description": "check if the number of allocated block matches inode's size",
                           "input": Argument.Empty})
  

    self.conf.addArgument({"name": "jstat",
                           "description": "journal statistics",
                           "input": Argument.Empty})

    self.conf.addArgument({"name": "slack",
                           "description": "Create slack nodes",
                           "input": Argument.Empty})

    self.conf.addArgument({"name": "SB_check",
                           "description": "check superblock validity",
                           "input": Argument.Empty})

    self.conf.addArgument({"name": "i_orphans",
                           "description": "Parse orphan inodes",
                           "input": Argument.Empty})

    self.conf.addArgument({"name": "root_inode",
                           "description": "Root inode number",
                           "input": Argument.Optional|Argument.Single|typeId.UInt64,
                           "parameters": {"type": Parameter.Editable,
                                          "predefined": [2]}
                           })

    self.conf.addArgument({"name": "SB_addr",
                           "description": "Super block address specified manualy",
                           "input": Argument.Optional|Argument.Single|typeId.UInt64,
                           "parameters": {"type": Parameter.Editable,
                                          "predefined": [1024]}
                           })

    self.conf.addConstant({"name": "mime-type", 
                           "type": typeId.String,
                           "description": "managed mime type",
                           "values": ["filesystem/ext"]})
    self.tags = "File systems"
%}
