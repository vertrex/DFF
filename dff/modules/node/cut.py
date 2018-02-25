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

__dff_module_cut_version__ = "1.0.0"

from struct import unpack

from dff.api.vfs import *
from dff.api.module.module import *
from dff.api.vfs.libvfs import *

from dff.api.types.libtypes import Variant, VMap, Parameter, Argument, typeId
from dff.api.vfs.libvfs import AttributesHandler

from dff.modules.spare import SpareNode

class CutNode(Node):
   def __init__(self, mfso, parent, name, startOff, size):
     self.startOff = startOff
     self.ssize = size
     self.pparent = parent
     if self.ssize == None or self.ssize == 0 or self.ssize < 0:
	self.ssize = parent.size() - startOff 
     Node.__init__(self, name + "-" + hex(startOff), self.ssize, None, mfso)
     self.__disown__()
     self.name = name

   def fileMapping(self, fm):
     fm.push(0, self.ssize, self.pparent, self.startOff) 
      
   def _attributes(self):
      attr = VMap()
      attr["start offset"] = Variant(self.startOff)
      return attr
 

class Cut(mfso):
    def __init__(self):
       mfso.__init__(self, "Cut")
       self.name = "Cut"
       self.__disown__()

    def start(self, args):
       self._if = args["input"].value()
       self._of = args["output"].value()
       self.start = args["start_offset"].value()
       self.size = args["size"].value()
       self.nof = CutNode(self, self._if, self._of, self.start, self.size)
       self.nof.__disown__()
       self.registerTree(self._if, self.nof) 


class cut(Module): 
  """This module allows you to cut a node from a starting offset"""
  def __init__(self):
    Module.__init__(self, "cut", Cut)
  
    self.conf.addArgument({"input": Argument.Required|Argument.Single|typeId.Node,
                           "name": "input",
                           "description": "Node to cut"
                           })
    self.conf.addArgument({"input": Argument.Required|Argument.Single|typeId.String,
                           "name": "output",
                           "description": "Output name of the created node"
                           })
    self.conf.addArgument({"input": Argument.Required|Argument.Single|typeId.UInt64,
                           "name": "start_offset",
                           "description": "Start address of the new node"
                           })
    self.conf.addArgument({"input": Argument.Required|Argument.Single|typeId.UInt64,
                           "name": "size",
                           "description": "Size to read. If not specified, read until EOF"
                           })
    self.icon = ":editcut"
    self.tags = "Node"
