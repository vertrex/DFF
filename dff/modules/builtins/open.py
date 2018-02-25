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

__dff_module_open_version__ = "1.0.0"

from dff.api.vfs import *
from dff.api.module.module import *
from dff.api.exceptions.libexceptions import *
from dff.api.loader import *
from dff.api.taskmanager.taskmanager import TaskManager
from dff.api.taskmanager.scheduler import sched 
from dff.api.types.libtypes import Argument, typeId, ConfigManager

from dff.ui.console.utils import VariantTreePrinter

class Open(Script):
  def __init__(self):
    Script.__init__(self, "open")
    self.loader = loader.loader()
    self.cm = ConfigManager.Get()
    self.vtreeprinter = VariantTreePrinter()
    self.lmodules = self.loader.modules
    self.taskmanager = TaskManager()

  def start(self, args):
    node = args["file"].value()
    self.open(node)

  def open(self, node):
    try:
      mod = node.compatibleModules()[0]
      conf = self.cm.configByName(mod)
      argsnode = conf.argumentsByFlags(typeId.Node|Argument.Required)
      if len(argsnode) == 1:
        argnode = argsnode[0]
        margs = {argnode.name(): node}
        args = conf.generate(margs)
        self.taskmanager.add(mod, args, ["thread", "gui"], True)
      else:
        print "There are more than 1 file to provides"
      print  "applying module " + mod + " on " + node.absolute()
    except IndexError:
      typeattr = node.attributesByName("type")
      if typeattr.type() == typeId.List:
        res = self.vtreeprinter.fillList(1, typeattr.value())
        print  "No module registered to handle following types " + res


class open(Module): 
  """Automatically apply module in background on a file. The module is determined by the file type."""
  def __init__(self):
   Module.__init__(self, "open", Open)
   self.conf.addArgument({"name": "file",
                          "description": "file to open",
                          "input": Argument.Single|Argument.Required|typeId.Node})
   self.tags = "builtins"
