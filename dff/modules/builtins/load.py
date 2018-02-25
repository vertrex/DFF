# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2013 ArxSys
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
#  Solal Jacob <sja@digital-forensic.org>
# 

__dff_module_load_version__ = "1.0.0"

from dff.api.vfs import *
from dff.api.module.module import *
from dff.api.loader import *
from dff.api.types.libtypes import Argument, typeId

class LOAD(Script):
  def __init__(self):
    Script.__init__(self, "load")
    self.loader = loader.loader()

  def start(self, args):
    paths = args['files'].value()
    for vpath in paths:
      path = vpath.value()
      self.loader.do_load(path.path)

class load(Module):
  """Load an external module"""
  def __init__(self):
   Module.__init__(self, "load", LOAD)
   self.conf.addArgument({"name": "files",
                          "description": "local files or folders containing modules",
                          "input": Argument.List|Argument.Required|typeId.Path})
   self.tags = "builtins"
