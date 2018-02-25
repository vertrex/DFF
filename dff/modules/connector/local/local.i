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
 *  Solal J. <sja@digital-forensic.org>
 */

#include "pyrun.swg"

%module  LOCAL
%include "std_string.i"
%include "std_list.i"
%include "std_set.i"
%include "std_map.i"
%include "windows.i"

%{
#include "rootnode.hpp"
#include "mfso.hpp"
#include "exceptions.hpp"
#include "local.hpp"
%}

%import "../../../api/vfs/libvfs.i"

%include "local.hpp"

%pythoncode
%{

__dff_module_LOCAL_version__ = "1.0.0"

from dff.api.module.module import *
from dff.api.types.libtypes import *
from dff.api.vfs import vfs
class LOCAL(Module):
  """Add files from your drives to the VFS"""
  def __init__(self):
    Module.__init__(self, 'local', local)
    self.conf.addArgument({"input": Argument.Optional|Argument.Single|typeId.Node, 
                           "name": "parent", 
                           "description": "files or folders will be added as child(ren) of this node or as the root node by default",
                           "parameters": {"type": Parameter.Editable,
                           "predefined": [vfs.vfs().getnode("/")]}
                          })
    self.conf.addArgument({"input": Argument.Required|Argument.List|typeId.Path,  
                           "name": "path", 
                           "description": "Path to the files or folders located on your drives."})
    self.tags = "Connectors"
%}
