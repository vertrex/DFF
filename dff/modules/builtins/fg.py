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
__dff_module_fg_version__ = "1.0.0"

from Queue import Empty

from dff.api.taskmanager.processus import ProcessusManager 
from dff.api.module.module import Module
from dff.api.module.script import Script
from dff.api.types.libtypes import Argument, typeId

from dff.ui.console.utils import VariantTreePrinter

class FG(Script):
  def __init__(self):
    Script.__init__(self, "fg")
    self.processusManager = ProcessusManager()
    self.vtreeprinter = VariantTreePrinter()
	
  def start(self, args):
    jobs = args["pid"].value()
    for proc in self.processusManager:
      if jobs == proc.pid:
        print "Displaying processus: " + str(proc.pid) + " name: " + str(proc.name) + " state: " + str(proc.state) + "\n"
        try :
	  text = self.processusManager[jobs].stream.get(0)
	  while text:
	    print text
	    text = self.processusManager[jobs].stream.get(0)
        except Empty:
          pass
        print self.vtreeprinter.fillMap(0, proc.res)
       

class fg(Module):
  """Switch to a process in background"""
  def __init__(self):
   Module.__init__(self, "fg", FG)
   self.conf.addArgument({"name": "pid",
                          "description": "Process id (use jobs to list process id)",
                          "input": Argument.Single|Argument.Required|typeId.UInt32})
   self.tags = "builtins"
   self.flags = ["console"]
