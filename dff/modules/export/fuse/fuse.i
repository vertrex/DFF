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

%module  FUSE 
%include "std_string.i"
%include "std_list.i"
%include "std_set.i"
%include "std_map.i"
%include "windows.i"

%exception;

%{
#include "exceptions.hpp"
#include "fuse.hpp"
%}

%import "../../../api/vfs/libvfs.i"

%include "fuse.hpp"

%pythoncode
%{

__dff_module_fuse_version__ = "1.0.0"

from dff.api.module.module import Module
from dff.api.types.libtypes import Argument, typeId

class FUSE(Module):
  """Mount DFF VFS directly on your system and use your traditional browser and tools on files"""
  def __init__(self):
    Module.__init__(self, 'fuse', fuse)
    self.conf.addArgument({"input": Argument.Required|Argument.Single|typeId.Path,
                           "name": "path",
                           "description":"Path where to mount DFF VFS in system."})
    self.conf.addArgument({"input": Argument.Optional|Argument.Single|typeId.String,
                           "name": "mount_options",
	                    "description": """Specify fuse mount options. By default allow_other is set but be sure to 
                            have user_allow_other in /etc/fuse.conf If you want other to be able to browse the mount point.
                            By setting this argument your options will be used and though allow_other will be disable.
                           """})
    self.tags = "Export"
%}
