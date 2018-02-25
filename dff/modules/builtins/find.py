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

__dff_module_find_version__ = "1.2.0"

from dff.api.vfs.libvfs import Node, VLink
from dff.api.module.module import Module, Script
from dff.api.events.libevents import EventHandler
from dff.api.types.libtypes import typeId, Variant, Argument
from dff.api.filters.libfilters import Filter

class FIND(Script, EventHandler):
    def __init__(self):
        Script.__init__(self, "find")
        EventHandler.__init__(self)
        self.nodes = []
        self.nodescount = 1
        self.oldcur = 0


    def start(self, args):
        self.nodes = []
        self.nodescount = 1
        self.oldcur = 0

        fname = args["filter_name"].value()
        expression = args["expression"].value()
        root_node = args["root_node"].value()
        if args.has_key("verbose"):
            self.verbose = True
        else:
            self.verbose = False
        if args.has_key("recursive"):
            recursive = True
        else:
            recursive = False
        f = Filter(fname)
        f.connection(self)
        try:
            f.compile(expression)
        except RuntimeError:
            self.res["error"] = Variant("provided expression is not valid")
        f.process(root_node, recursive)
        self.res["total of matching nodes"] = Variant(len(self.nodes))
        if args.has_key("save_result"):
            si_node = self.vfs.getnode("/Bookmarks")
            if si_node == None:
                root = self.vfs.getnode("/")
                si_node = Node("Bookmarks", 0, root)
                si_node.__disown__()
            fnode = Node(fname, 0, si_node)
            fnode.__disown__()
            for node in self.nodes:
                vl = VLink(node, fnode, node.name())
                vl.__disown__()


    def Event(self, e):
        if e.type == 0x200:
            self.nodescount = e.value.value()
            self.res["total nodes"] = Variant(self.nodescount)
        elif e.type == 0x201:
            cur = e.value.value()
            progress = (cur * 100) / self.nodescount
            if progress > self.oldcur:
                self.stateinfo = str(progress) + " % (matching node: " + str(len(self.nodes)) + ")"
        elif e.type == 0x202:
            node = e.value.value()
            if self.verbose == True:
                print node.absolute()
            self.nodes.append(node)


class find(Module):
    """Find files and folders based on provided filter expression"""
    def __init__(self):
        Module.__init__(self, "find", FIND)
        self.conf.addArgument({"name": "filter_name",
                               "description": "Name of the filter",
                               "input": Argument.Single|Argument.Required|typeId.String})
        self.conf.addArgument({"name": "expression",
                               "description": 'Expression provided to filter engine (e.g: name == w("*.jp?g", i)',
                               "input": Argument.Single|Argument.Required|typeId.String})
        self.conf.addArgument({"name": "root_node",
                               "description": "node from which apply filter expression",
                               "input": Argument.Single|Argument.Required|typeId.Node})
        self.conf.addArgument({"name": "recursive",
                               "description": "apply filter expression in recursive way (on all thre subtree from provided root_node)",
                               "input": Argument.Empty})
        self.conf.addArgument({"name": "save_result",
                               "description": "save results by creating links to matching nodes",
                               "input": Argument.Empty})
        self.conf.addArgument({"name": "verbose",
                               "description": "outputs matching node on console during processing",
                               "input": Argument.Empty})
        self.tags = "builtins"
