# -*- coding: utf-8 -*-
# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2011 ArxSys
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
 
from dff.api.vfs.vfs import vfs
from dff.api.vfs.libvfs import mfso 
from dff.api.module.module import Module, Script
from dff.api.types.libtypes import Argument, typeId
from dff.api.filters.libfilters import Filter

from dff.pro.api.report.manager import ReportManager
from dff.pro.api.report.fragments import NodeListFragment

class categorize(Module):
  """Categorize and bookmark file by types"""
  def __init__(self):
    Module.__init__(self, "categorize", Categorize)
    self.depends = ["File systems", "partition", "compound", "metaexif"] #not really depend on it but force apply fs ... 
    self.icon = ":module2"
    self.tags = "Analyse"

class Categorize(Script):
  def __init__(self):
    Script.__init__(self, "Categorize")
    self.name = "Categorize"
    self.vfs = vfs()

  def search(self, query):
    filters = Filter("")
    filters.compile(query)
    filters.process(self.root, True)
    return filters.matchedNodes() 

  def createSearchPage(self, categoryName, pageName, query):
    try:
      page = self.reportManager.createPage(categoryName, pageName)
      nodes = self.search(query)
      page.addNodeList(pageName, nodes) # XXX can add special attribute columns ex: author for doc 
      self.reportManager.addPage(page)        
    except Exception as e:
      print 'modules.report as an exception ' + str(e)
      print 'category : ', categoryName, pageName 

  def start(self, args):
    self.reportManager = ReportManager()
    self.root = self.vfs.getnode("/")

    self.createSearchPage("Media", "Image", '(mime in ["image"])')
    self.createSearchPage("Media", "Video", '(mime in ["video"])')
    self.createSearchPage("Media", "Audio", '(mime in ["audio"])')
    self.createSearchPage("Document", "PDF", 'magic matches "PDF document"')
    self.createSearchPage("Document", "Word", 'magic matches "OpenDocument Text" or name matches /.*\.doc$/ or magic matches "Microsoft Word"')
    self.createSearchPage("Document", "PowerPoint", 'magic matches "OpenDocument Presentation" or name matches /.*\.ppt$/ or magic matches "Micrsoft PowerPoint"')
    self.createSearchPage("Document", "Excel", 'magic matches "OpenDocument SpreedSheet" or name matches /.*\.xls$/ or magic matches "Microsoft Excel"')
    self.createSearchPage("Document", "Text", '(magic matches "Unicode text" or magic matches "ASCII text") and not magic matches "HTML document"')
    self.createSearchPage("Document", "HTML", 'magic matches "HTML"')

  #def updateWidget(self):
    #pass


