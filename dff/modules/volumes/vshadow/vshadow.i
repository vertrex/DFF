/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2014 ArxSys
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
 *  Frederic Baguelin <fba@digital-forensic.org>
 */

#include "pyrun.swg"

%module VSHADOW
%include "std_string.i"
%include "std_list.i"
%include "std_set.i"
%include "std_map.i"
%include "windows.i"

%{
#include "rootnode.hpp"
#include "exceptions.hpp"
#include "vshadow.hpp"
%}

%import "../../../api/vfs/libvfs.i"

%include "vshadow.hpp"

%pythoncode
%{
from dff.api.module.module import *
from dff.api.types.libtypes import *
class VSHADOW(Module):
  """Reconstructs Windows NT Volume Shadow Snapshot (VSS)"""
  def __init__(self):
    Module.__init__(self, 'vshadow', Vshadow)
    self.conf.addArgument({"input":Argument.Required|Argument.Single|typeId.Node,
                           "name": "file",
                           "description": "Path to the source file"})
    self.conf.addArgument({"name":"offset",
                           "description":"define volume offset",
                           "input": Argument.Optional|Argument.Single|typeId.UInt64})
    self.conf.addConstant({"name":"mime-type",
                           "type":typeId.String,
                           "description":"managed mime type",
                           "values":["volume/vshadow"]})
    self.tags = "Volumes"
    self.icon = ":disksfilesystems"
%}
