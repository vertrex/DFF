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
#  Frederic Baguelin <fba@digital-forensic.org>
# 
__dff_module_cut_version__ = "1.0.0"

from struct import unpack

from dff.api.vfs import *
from dff.api.module.module import *
from dff.api.vfs.libvfs import *
from dff.api.types.libtypes import Variant, VMap, Parameter, Argument, typeId
from dff.api.vfs.libvfs import AttributesHandler

from dff.modules.spare import SpareNode

class SplitNode(Node):
   def __init__(self, mfso, parent, origin, soffset, size):
     self.soffset = soffset
     self.ssize = size
     self.pparent = parent
     self.origin = origin
     if self.ssize == None or self.ssize == 0 or self.ssize < 0:
	self.ssize = parent.size() - soffset
     start = hex(soffset)
     lenstart = len(start[2:])
     if lenstart < 16:
         start = "0x" + ("0" * (16 - lenstart)) + start[2:]
     end = hex(soffset + size)
     lenend = len(end[2:])
     if lenend < 16:
         end = "0x" + ("0" * (16 - lenend)) + end[2:]
     Node.__init__(self, start + "-" + end, self.ssize, parent, mfso)
     self.__disown__()


   def fileMapping(self, fm):
     fm.push(0, self.ssize, self.origin, self.soffset)


   def _attributes(self):
      attr = VMap()
      attr["start offset"] = Variant(self.soffset)
      return attr
 

class Split(mfso):
    def __init__(self):
        mfso.__init__(self, "Split")
        self.name = "Split"
        self.__disown__()
        

    def __split(self, root, chunksize):
        nodesize = self.origin.size()
        chunks = nodesize / chunksize
        vmap = VMap()
        vmap["complete chunks"] = Variant(chunks)
        for idx in xrange(0, chunks*chunksize, chunksize):
            snode = SplitNode(self, root, self.origin, idx, chunksize)
        lastchunk = nodesize % chunksize
        if lastchunk != 0:
            snode = SplitNode(self, root, self.origin, self.origin.size() - lastchunk, lastchunk)
            vmap["truncated chunk (size)"] = Variant(lastchunk)
        self.res[str(chunksize) + " bytes split"] = Variant(vmap)
    

    def start(self, args):
        self.origin = args["file"].value()
        if args.has_key("start-offset"):
            self.soffset = args["start-offset"].value()
        else:
            self.soffset = 0
        self.chunklist = args["chunk-sizes"].value()
        nodesize = self.origin.size()
        err = ""

        if self.soffset < 0:
            err += "start offset (" + str(self.soffset) + ") must be equal or greater to 0\n"
        if self.soffset >= nodesize:
            err += "start offset (" + str(self.soffset) + ") must be lesser than size of provided node\n"
        if not err:
            for vchunksize in self.chunklist:
                cerr = ""
                chunksize = vchunksize.value()
                if chunksize <= 0:
                    cerr += "size of chunk (" + str(chunksize) + " bytes) must be positive\n"
                if chunksize >= nodesize:
                    cerr += "size of chunk (" + str(chunksize) + " bytes) must be lesser than size of provided node\n"
                if not cerr:
                    root = Node(self.origin.name() + " splitted by " + str(chunksize), 0, None, self)
                    root.__disown__()
                    self.__split(root, chunksize)
                    self.registerTree(self.origin, root)
                else:
                    err += cerr
        if err:           
            self.res["error"] = Variant(err)


class split(Module):
    """This module allows you to cut a node from a starting offset"""
    def __init__(self):
        Module.__init__(self, "split", Split)
        self.conf.addArgument({"input": Argument.Required|Argument.Single|typeId.Node,
                               "name": "file",
                               "description": "Input node which will be splitted"
                               })
        self.conf.addArgument({"input": Argument.Optional|Argument.Single|typeId.UInt64,
                               "name": "start-offset",
                               "description": "Offset from start splitting",
                               "parameters": {"type": Parameter.Editable,
                                              "predefined": [0]}
                               })
        self.conf.addArgument({"input": Argument.Required|Argument.List|typeId.UInt64,
                               "name": "chunk-sizes",
                               "description": "specifies the size for each chunk",
                               "parameters": {"type": Parameter.Editable,
                                              "predefined": [512, 1024, 2048, 4096, 8192]}
                               })
        self.icon = ":editcut"
        self.tags = "Node"
