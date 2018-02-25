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

%module  DEVICES 
%include "std_string.i"
%include "std_list.i"
%include "std_set.i"
%include "std_map.i"
%include "windows.i"



%{
#include "mfso.hpp"
#include "devices.hpp"
#include "rootnode.hpp"
%}

%import "../../../api/vfs/libvfs.i"

%include "devices.hpp"

%pythoncode
%{

__dff_module_devices_version__ = "1.0.0"

from dff.api.module.module import *
from dff.api.types.libtypes import *
from dff.api.vfs import vfs
class DEVICES(Module):
  """Access devices connected to your computer."""
  def __init__(self):
    Module.__init__(self, 'devices', devices)
    self.tags = "Connectors"  
    self.conf.addArgument({"input": Argument.Required|Argument.Single|typeId.Node, 
                           "name": "parent", 
                           "description": "Devices will be mount as child of this node or at root node by default.",
                           "parameters": {"type": Parameter.Editable,
                                          "predefined": [vfs.vfs().getnode("/")]}
                          })
    self.conf.addArgument({"input": Argument.Required|Argument.Single|typeId.Path,  
                           "name": "path", 
                           "description": "Path to the local device on your operating system."})
    self.conf.addArgument({"input": Argument.Required|Argument.Single|typeId.UInt64,
                        "name": "size",
                        "description": "Size of the device."})
    self.conf.addArgument({"input": Argument.Optional|Argument.Single|typeId.String,
                        "name": "name",
                        "description": "Name to associate to the corresponding node."})
    self.icon = ":dev_hd.png"
%}
