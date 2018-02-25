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

%module  AFF
%include "std_string.i"
%include "std_list.i"
%include "std_set.i"
%include "std_map.i"
%include "windows.i"

%{
#include "mfso.hpp"
#include "rootnode.hpp"
#include "exceptions.hpp"
#include "aff.hpp"
%}

%import "../../../api/vfs/libvfs.i"

%include "aff.hpp"

%pythoncode
%{

__dff_module_AFF_version__ = "1.0.0"

from dff.api.module.module import *
from dff.api.types.libtypes import *
from dff.api.vfs import vfs
class AFF(Module):
  """Load AFF v3 files"""
  def __init__(self):
    Module.__init__(self, 'aff', aff)
    self.conf.addArgument({"input": Argument.Required|Argument.Single|typeId.Node, 
                           "name": "parent", 
                           "description": "Path where the AFF dump will be mounted. Root node by default",
                       "parameters": {"type": Parameter.Editable,
                                          "predefined": [vfs.vfs().getnode("/")]}
                          })
    self.conf.addArgument({"input": Argument.Required|Argument.List|typeId.Path,  
                           "name": "path", 
                           "description": "Path to AFF files or folder on your operating system."})
    self.conf.addArgument({"input": Argument.Optional|Argument.Single|typeId.UInt32,
                           "name": "cache size",
                           "description": "Size of the pages cache, one page is 16 megabytes",
                           "parameters": {"type": Parameter.Editable, 
                                          "predefined" : [2]}
                         })
    self.tags = "Connectors"
%}
