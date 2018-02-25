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

__dff_module_link_version__ = "1.0.0"

from dff.api.module.module import *
from dff.api.exceptions.libexceptions import *
from dff.api.types.libtypes import Argument, typeId, Variant

class LINK(Script):
  def __init__(self):
    Script.__init__(self, "link")

  def start(self, args):
    dest = args["dest"].value()
    node = args["file"].value()
    self.vfs.link(node, dest)
    self.res["result"] = Variant(str("linked " + dest.path() + "/" + node.name() + " created").replace("//", "/"))    


class link(Module):
  def __init__(self):
   """Create a link to a file"""
   Module.__init__(self, "link", LINK)
   self.conf.addArgument({"name": "file",
                           "description": "File to link to",
                           "input": Argument.Required|Argument.Single|typeId.Node})
   self.conf.addArgument({"name": "dest",
                           "description": "File pointing to the link",
                           "input": Argument.Required|Argument.Single|typeId.Node})
   self.tags = "builtins"
