# DFF -- An Open Source Digital Forensics Framework
#
# This program is free software, distributed under the terms of
# the GNU General Public License Version 2. See the LICENSE file
# at the top of the source tree.
# 
# See http://www.digital-forensic.org for more information about this
# project. Please do not directly contact any of the maintainers of
# DFF for assistance; the project provides a web site, mailing lists
# and IRC channels for your use.
# 
# Author(s):
#  Jeremy MOUNIER < jmo@arxsys.fr>
#

__dff_module_winreg_version__ = "1.0.0"

import re

from dff.api.vfs.libvfs import mfso
from dff.api.module.module import Module 
from dff.api.module.manager import ModuleProcessusManager
from dff.api.types.libtypes import Argument, typeId

from hive import RHive
from registrymanager import RegistryManager

ModuleProcessusManager().register(RegistryManager("winreg"))

HKLM = ["^SYSTEM", "^SOFTWARE", "^SAM", "^SECURITY"]
HKU = ["^NTUSER.DAT", "^DEFAULT", "^USRCLASS.DAT"]

class WINREG(mfso):
    def __init__(self):
        mfso.__init__(self, "winreg")
        self.name = "winreg"
        self.__disown__()

    def start(self, args):
       self.hive = args['file'].value()
       if args.has_key("verbose"):
           self.verbose = True
       else:
           self.verbose = False
       if args.has_key('mount'):
         self.mount = True
       else:
          self.mount = False
       phive = self.getHive()
       if self.mount and phive:
         phive.mount()

    def splitPath(self, path):
        if path:
            rpath = path[1:len(path)]
            return rpath.split('\\')
        else:
            return None

    def getHive(self):
        try:
	    phive = RHive(self.hive, self, self.verbose)
	    return phive
        except AttributeError:
            return None

    def regType(self):
        try:
            fn = self.hive.name()
            for hname in HKLM:
                if re.match(hname, fn, re.IGNORECASE):
                    return ("HKLM" + "\\" + hname[1:], self.hive) 
            for hname in HKU:
                if re.match(hname, fn, re.IGNORECASE):
                    return ("HKU", self.hive)
            return None
        except AttributeError:
            return None

class winreg(Module):
  """This module permits to virtualy reconstruct windows registry hives files located in the VFS."""
  def __init__(self):
    Module.__init__(self, "winreg", WINREG)
    self.conf.addArgument({"name": "file",
                           "description": "Registry hive file",
                           "input": Argument.Required|Argument.Single|typeId.Node})

    self.conf.addArgument({"name": "verbose",
                           "description": "Display module progression",
                           "input": Argument.Empty})

    self.conf.addArgument({"name": "mount",
                           "description": "Mount registry key and value in the VFS (This can consume lots of memory)",
                           "input": Argument.Empty})

    self.conf.addConstant({"name": "mime-type", 
 	                   "type": typeId.String,
 	                   "description": "managed mime type",
 	                   "values": ["windows/registry"]})
    self.tags = "Databases"
    self.flags = ["noscan"]
    self.scanFilter = 'path in [$*Users*$, $*Documents and Settings*$] and name matches "NTUSER.DAT" or path matches $*system32/config*$'
    self.icon = ":password.png"
