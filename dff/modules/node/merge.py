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
#  Romain Bertholon < rbe@arxsys.fr>
#

__dff_module_merge_version__ = "1.0.0"

from struct import unpack

from dff.api.vfs import *
from dff.api.module.module import *
from dff.api.types.libtypes import Variant, VList, VMap, Argument, Parameter, typeId
from dff.api.vfs.libvfs import *

class MergeNode(Node):
   def __init__(self, name, size, parent, mfso, files):
      Node.__init__(self, name, size, parent, mfso)
      self.files = files
      self.__disown__()

   def fileMapping(self, fm):
      offset = 0
      for f in self.files:
         node = f.value()
         fm.push(offset, node.size(), node, 0)
         offset += node.size()
      
   def _attributes(self):
      i = 1
      attr = VMap()
      vlist = VList()
      for f in self.files:
         node = f.value()         
         vlist.append(Variant(node.absolute()))
      attr["concatanated files (ordered)"] = Variant(vlist)
      return attr

class MERGE(mfso):
    def __init__(self):
       mfso.__init__(self, "merge")
       self.__disown__()

    def start(self, args):
       self.files = args['files'].value()
       if args.has_key("output"):
          name = args["output"].value()
       else:
          name = self.files[0].value().name() + "..." + self.files[len(self.files) - 1].value().name()
       if args.has_key("parent"):
          parent = args["parent"].value()
       else:
          parent = self.files[0].value().parent()
       size = 0
       for f in self.files:
          size += f.value().size()
       self.merge_node = MergeNode(name, size, None, self, self.files)
       self.merge_node.__disown__()
       self.registerTree(parent, self.merge_node)


class merge(Module):
  """This module concatenates two or more files."""
  def __init__(self):
    Module.__init__(self, "merge", MERGE)
    self.conf.addArgument({"input": Argument.Required|Argument.List|typeId.Node,
                           "name": "files",
                           "description": "these files will be concatenated in the order they are provided",
                           "parameters": {"type": Parameter.Editable,
                                          "minimum": 2}
                           })
    self.conf.addArgument({"input": Argument.Optional|Argument.Single|typeId.String,
                           "name": "output",
                           "description": "the name of file corresponding to the concatenation"
                           })
    self.conf.addArgument({"input": Argument.Optional|Argument.Single|typeId.Node,
                           "name": "parent",
                           "description": "parent of the resulting output file (default will be basefile)"
                           })
    self.tags = "Node"
