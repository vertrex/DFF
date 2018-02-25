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
__dff_module_history_version__ = "1.0.0"

from dff.api.vfs import *
from dff.api.module.module import *
from dff.api.module.script import *
from dff.api.types.libtypes import Variant, typeId, Argument

import dff.ui.history as hist

class HISTORY(Script):
  def __init__(self):
    Script.__init__(self, "history")
    self.h = hist.history()


  def start(self, args):
    if len(args) > 1:
      self.res["error"] = Variant("too many arguments")
    elif args.has_key("clear"):
      self.h.clear()
    elif args.has_key("last"):
      last = args["last"].value()
      if last > len(self.h.hist):
        last = 0
      else:
        last = len(self.h.hist) - last
      for i in xrange(last, len(self.h.hist)):
        print (str(i) + '\t' + self.h.hist[i]).strip('\n')
    else:
      for i in xrange(0, len(self.h.hist)):
        print (str(i) + '\t' + self.h.hist[i]).strip('\n')

class history(Module):
  """Display an history of all launched command"""
  def __init__(self):
   Module.__init__(self, "history", HISTORY)
   self.conf.addArgument({"name": "clear",
                          "description": "clear the history",
                          "input": Argument.Empty})
   self.conf.addArgument({"name": "last",
                          "description": "lists only the last n lines",
                          "input": Argument.Single|Argument.Optional|typeId.UInt32})
   self.tags = "builtins"
