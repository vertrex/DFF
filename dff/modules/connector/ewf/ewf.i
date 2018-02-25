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

%module  EWF 
%include "std_string.i"
%include "std_list.i"
%include "std_set.i"
%include "std_map.i"
%include "windows.i"

%{
#include "exceptions.hpp"
#include "rootnode.hpp"
#include "mfso.hpp"
#include "ewf.hpp"
%}

%import "../../../api/vfs/libvfs.i"

%include "ewf.hpp"


%pythoncode
%{

__dff_module_EWF_version__ = "1.0.0"

from dff.api.module.module import *
from dff.api.types.libtypes import *
from dff.api.vfs import vfs
class EWF(Module):
  """EWF connector, load E01 dump"""
  def __init__(self):
    Module.__init__(self, 'ewf', ewf)
    self.conf.addArgument({"input": Argument.Optional|Argument.Single|typeId.Node, 
                           "name": "parent", 
                           "description": "Path where the EWF dump will be mounted",
                       "parameters": {"type": Parameter.Editable,
                                          "predefined": [vfs.vfs().getnode("/")]}
                          })
    self.conf.addArgument({"input": Argument.Required|Argument.List|typeId.Path,  
                           "name": "files", 
                           "description": "EWF files to open"})
    self.tags = "Connectors"
%}
