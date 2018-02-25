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

__dff_module_ls_version__ = "1.0.0"

from dff.api.vfs.vfs import vfs, VLink, ABSOLUTE_ATTR_NAME
from dff.api.module.module import Module
from dff.api.module.script import Script
from dff.api.types.libtypes import typeId, Argument, Parameter, Variant
from dff.ui.console.utils import ColumnView, bytesToHuman

import os


class LevelStats():  
  def __init__(self, extattrs):
    self.maxname = 0
    self.size = 0
    self.children = 0
    self.mime = 0
    self.links = 0
    self.files = 0
    self.delfiles = 0
    self.folders = 0
    self.delfolders = 0
    self.extattrs = {extattr : 0 for extattr in extattrs}


class LS(Script):

  sortkeys = {"size": lambda Node: Node.size(),
              "name": lambda Node: Node.name().lower(),
              "deleted": lambda Node: Node.isDeleted(),
              "extension": lambda Node: Node.extension(),
              "mime": lambda Node: Node.dataType()}
  

  def __init__(self) :
    Script.__init__(self, "ls")
    self.vfs = vfs()


  def start(self, args):
    try:
      self.nodes = args["nodes"].value()
    except IndexError:
      self.nodes = [Variant(self.vfs.getcwd())]
    self.attributes = list()
    seen_attrs = set()
    if args.has_key('recursive'):
      self.depth = -1
    else:
      self.depth = 1
    if args.has_key('long'):
      self.long = True
    else:
      self.long = False
    if args.has_key('human-readable'):
      self.human = True
    else:
      self.human = False
    if args.has_key('sort'):
      skey = args["sort"].toString()
      if LS.sortkeys.has_key(skey):
        self.ksort = LS.sortkeys[args["sort"].toString()]
      else:
        self.attributes.append(skey)
        seen_attrs.add(skey)
        self.ksort = lambda Node: Node.attributesByName(skey, ABSOLUTE_ATTR_NAME)[0].value() if len(Node.attributesByName(skey, ABSOLUTE_ATTR_NAME)) else "N/A"
    else:
      self.ksort = LS.sortkeys["name"]
    if args.has_key("attributes"):
      vl = args["attributes"].value()
      self.attributes += [arg.toString() for arg in vl if arg.toString() not in seen_attrs and not seen_attrs.add(arg.toString())]
    if args.has_key('reverse'):
      self.reverse = True
    else:
      self.reverse = False
    self._res = self.launch()


  def isRoot(self, node):
    if node.hasChildren():
      try:
        pfsobj = node.children()[0].fsobj().this
      except AttributeError:
        pfsobj = None
      try:
        nfsobj = node.fsobj().this
      except AttributeError:
        nfsobj = None
      return pfsobj != nfsobj
    else:
      return False


  def walk(self, top, ksort=lambda Node: Node.name().lower(), depth=-1):
    if depth == 0:
      return
    children = top.children()
    items, folders = [], []
    count = len(children)
    lstat = LevelStats(self.attributes)
    i = 0
    while i != count:
      child = children[i]
      if child.hasChildren() or child.isDir():
        folders.append(child)
      self.stat(child, lstat)
      items.append(child)
      i += 1
    yield top, sorted(items, key=ksort, reverse=self.reverse), lstat
    folders = sorted(folders, key=ksort, reverse=self.reverse)
    for folder in folders:
      for x in self.walk(folder, ksort, depth-1):
        yield x


  def launch(self):
    ncount = len(self.nodes)
    lstat = LevelStats(self.attributes)
    if ncount > 1:
      folders = []
      files = []
      i = 0
      while i != ncount:
        node = self.nodes[i].value()
        if node.hasChildren() or node.isDir():
          folders.append(node)
        else:
          self.stat(node, lstat)
          files.append(node)
        i += 1
      self.render(sorted(files, key=self.ksort, reverse=self.reverse), lstat, absolute=True)
      folders = sorted(folders, key=self.ksort, reverse=self.reverse)
      for folder in folders:
        for (cur, items, lstat) in self.walk(folder, self.ksort, self.depth):
          self.render(items, lstat, cur)
    else:
      if self.nodes[0].value().isFile():
        self.stat(self.nodes[0].value(), lstat)
        self.render([self.nodes[0].value()], lstat)
      for (cur, items, lstat) in self.walk(self.nodes[0].value(), self.ksort, self.depth):
        if self.depth == -1:
          self.render(items, lstat, cur)
        else:
          self.render(items, lstat)


  def stat(self, node, lstat):
    if not self.long:
      return
    if isinstance(node, VLink):
      lstat.links += 1
    else:
      if node.hasChildren() or node.isDir():
        #if self.isRoot(node):
        #  lstat.files += 1
        lstat.folders += 1
        if node.isDeleted():
          lstat.delfolders += 1
      else:
        lstat.files += 1
        if node.isDeleted():
          lstat.delfiles += 1
    if self.human:
      size = bytesToHuman(node.size())
    else:
      size = str(node.size())
    if len(size) > lstat.size:
      lstat.size = len(size)
    if len(str(node.childCount())) > lstat.children:
      lstat.children = len(str(node.childCount()))
    mime = node.dataType()
    if len(mime) > lstat.mime:
      lstat.mime = len(mime)
    for attr in self.attributes:
      attrlen = 3 # N/A
      val = node.attributesByName(attr, ABSOLUTE_ATTR_NAME)
      if len(val):
        if val[0].type() == typeId.DateTime:
          dateTime = val[0].value()
          if dateTime:
            attrlen = len(str(dateTime))
        else:
          attrlen = len(val[0].toString())
      if attrlen > lstat.extattrs[attr]:
        lstat.extattrs[attr] = attrlen


  def renderLong(self, node, lstat, absolute=False):
    fmt = "{:s}  {:>" + str(lstat.children) + "d}  {:>" + str(lstat.size) + "s}  {:<" + str(lstat.mime) +  "s}"
    lattrs = []
    for attr in self.attributes:
      attrval = "N/A"
      val = node.attributesByName(attr, ABSOLUTE_ATTR_NAME)
      if len(val):
        if val[0].type() == typeId.DateTime:
          DateTime = val[0].value()
          if DateTime:
            attrval = str(DateTime)
        else:
          attrval = val[0].toString()
      lattrs.append(attrval)
      fmt += "  {:>" + str(lstat.extattrs[attr]) + "s}"
    fmt += "  {:s}"
    if absolute:
      name = node.absolute()
    else:
      name = node.name()
    if isinstance(node, VLink):
      name += " -> " + node.linkAbsolute()
      h = "l"
    else:
      if node.hasChildren():
        h = "d"
      else:
        h = "f"
    if node.isDeleted():
      h += "d"
    else:
      h += "-"
    if node.isFile():
      if self.human:
        size = bytesToHuman(node.size())
      else:
        size = str(node.size())
    else:
      size = str(0)
    mime = node.dataType()
    if len(lattrs):
      lattrs.append(name)
      buff = fmt.format(h, node.childCount(), size, mime, *lattrs)
    else:
      buff = fmt.format(h, node.childCount(), size, mime, name)
    return buff
    

  def render(self, items, lstat, head=None, absolute=False):
    if not len(items):
      return
    buff = ""
    if head:
      print head.absolute() + ":"
      print "total {0} ({1}) -- folders: {2} ({3}) / files {4} ({5})".format(str(lstat.folders + lstat.files),
                                                                             str(lstat.delfolders + lstat.delfiles),
                                                                             str(lstat.folders), str(lstat.delfolders),
                                                                             str(lstat.files), str(lstat.delfiles))
    counter = len(items)
    i = 0
    if self.long:
      while i != counter:
        print self.renderLong(items[i], lstat, absolute)
        i += 1
      print
    else:
      cv = ColumnView()
      for row in cv.iterRows([item.name() for item in items]):
        print row
      if self.depth == -1:
        print


class ls(Module):
  """List file and directory"""
  def __init__(self):
   Module.__init__(self, "ls", LS)
   self.conf.addArgument({"name": "nodes",
                          "description": "files to list",
                          "input": Argument.List|Argument.Optional|typeId.Node})
   self.conf.addArgument({"name": "long",
                          "description": "Display more information for each files",
                          "input": Argument.Empty})
   self.conf.addArgument({"name": "recursive",
                          "description": "enables recursion on folders",
                          "input": Argument.Empty})
   self.conf.addArgument({"name": "human-readable",
                          "description": "outputs information in human readable style",
                          "input": Argument.Empty})
   self.conf.addArgument({"name": "reverse",
                          "description": "reverse order while sorting",
                          "input": Argument.Empty})
   self.conf.addArgument({"name": "sort",
                          "description": "Sort ouput by provided key. By default, sort by name alphabetically. If the provided key is not based on predefined attributes, a column will be added to show associated values after default fields",
                          "input": Argument.Optional|Argument.Single|typeId.String,
                          "parameters": {"type": Parameter.Editable,
                                         "predefined": ["size", "name", "deleted", "extension", "mime"]}})
   self.conf.addArgument({"name": "attributes",
                          "description": "If long format, provided attributes will be output in the same order after default fields. If sort is provided with an attribute not listed here, it will be output before this list.",
                          "input": Argument.Optional|Argument.List|typeId.String})
   self.tags = "builtins"
