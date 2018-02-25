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
#  Frederic B. <fba@digital-forensic.org>

__dff_module_carverui_version__ = "1.0.0"
import string
import time
from typeSelection import filetypes

from dff.api.module.module import Module
from dff.api.module.script import Script
from dff.api.events.libevents import EventHandler, event
from dff.api.types.libtypes import typeId, Argument, Parameter
from dff.api.taskmanager.taskmanager import TaskManager
from dff.api.types.libtypes import typeId, Argument, Parameter, VList, VMap, Variant

class CarverUi(Script):
    def __init__(self):
        Script.__init__(self, "carverui")
        self.tm = TaskManager()

    def start(self, args):
        if args.has_key("start-offset"):
            startoff = args["start-offset"].value()
        else:
            startoff = 0
        if args.has_key("block-aligned"):
            aligned = True
        else:
            aligned = False
        patterns = VList()
        for mimetype in filetypes.keys():
            if mimetype in args:
                vsubtypes = args[mimetype].value()
                for subtype in filetypes[mimetype].keys():
                    if subtype in vsubtypes:
                        pattern = VMap()
                        descr = filetypes[mimetype][subtype]                        
                        for p in descr:
                            header = VMap()
                            header["needle"] = Variant(p[0], typeId.String)
                            header["size"] = Variant(len(p[0]), typeId.UInt32)

                            footer = VMap()
                            footer["needle"] = Variant(p[1], typeId.String)
                            footer["size"] = Variant(len(p[1]), typeId.UInt32)

                            pattern["filetype"] = Variant(subtype, typeId.String)
                            pattern["header"] = Variant(header)
                            pattern["footer"] = Variant(footer)
                            pattern["window"] = Variant(int(p[2]), typeId.UInt32)
                            if aligned:
                                pattern["aligned"] = Variant(True, typeId.Bool)
                            else:
                                pattern["aligned"] = Variant(False, typeId.Bool)
                            patterns.append(pattern)                            
        margs = VMap()
        margs["patterns"] = Variant(patterns)
        margs["file"] = args["file"]
        margs["start-offset"] = Variant(startoff, typeId.UInt64)
        proc = self.tm.add("carver", margs, ["console"])
        if proc:
            proc.event.wait()

    def c_display(self):
        pass


class carverui(Module):
  """Search for header and footer of a selected mime-type in a node and create the corresponding file.
     You can use this modules for finding deleted data or data in slack space or in an unknown file system."""
  def __init__(self):
    Module.__init__(self, 'carverui', CarverUi)
    self.conf.addArgument({"name": "file",
                           "input": typeId.Node|Argument.Single|Argument.Required,
                           "description": "Node to search data in"})
    self.conf.addArgument({"name": "block-aligned",
                           "input": Argument.Empty,
                           "description": "if setted only search signatures at the begining of blocks (faster but less accurate)"})
    self.conf.addArgument({"name": "start-offset",
                           "input": typeId.UInt64|Argument.Single|Argument.Optional,
                           "description": "offset from which to start carving"})
    for mimetype in filetypes.keys():
        predefined = []
        for subtype in filetypes[mimetype].keys():
            predefined.append(subtype)
        self.conf.addArgument({"name": mimetype,
                               "input": typeId.String|Argument.List|Argument.Optional,
                               "description": "managed types",
                               "parameters": {"type": Parameter.NotEditable,
                                              "predefined": predefined}
                               })
    self.tags = "builtins"
