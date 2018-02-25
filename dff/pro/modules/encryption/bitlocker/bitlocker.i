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

%module  BITLOCKER
%include "std_string.i"
%include "std_list.i"
%include "std_set.i"
%include "std_map.i"
%include "windows.i"

%{
#include "rootnode.hpp"
#include "mfso.hpp"
#include "bitlocker.hpp"
%}

%import "../../../../api/vfs/libvfs.i"

%include "bitlocker.hpp"

%pythoncode
%{

__dff_module_BITLOCKER_version__ = "1.0.0"

from dff.api.module.module import *
from dff.api.types.libtypes import *
from dff.api.vfs import vfs
class BITLOCKER(Module):
  """BitLocker decrypter"""
  def __init__(self):
    Module.__init__(self, 'bitlocker', BitLocker)
    self.conf.addArgument({"input": Argument.Required|Argument.Single|typeId.Node, 
                           "name": "parent", 
                           "description": "Path of the BitLocker partition",
                          })
    self.conf.addArgument({"input": Argument.Optional|Argument.Single|typeId.Node,
                           "name" : "startup-key-node",
                           "description" : "Path of a node containing the startup key (.BEK)"
                          })
    self.conf.addArgument({"input": Argument.Optional|Argument.Single|typeId.Path,
                           "name" : "startup-key-file",
                           "description" : "Path of a file containing the startup key (.BEK)"
                          })
    self.conf.addArgument({"input": Argument.Optional|Argument.Single|typeId.String,
                           "name" : "recovery-password",
                           "description" : "Recovery password"
                          })
    self.conf.addArgument({"input": Argument.Optional|Argument.Single|typeId.String,
                           "name" : "passphrase",
                           "description" : "password / passphrase"
                          })
    self.conf.addArgument({"input": Argument.Optional|Argument.Single|typeId.String,
                           "name" : "volume-keys",
                           "description" : "full volume encryption key and tweak key formatted in base 16 and separated by :"
                          })
    self.conf.addConstant({"name": "mime-type",
                           "type": typeId.String,
                           "description": "managed mime type",
                           "values": ["volume/bitlocker"]})

    self.tags = "Encryption"
%}
