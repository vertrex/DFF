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
#  Jeremy MOUNIER <jmo@digital-forensic.org>
#  Solal Jacob <sja@digital-forensic.org>
# 

__dff_module_gen_nodes_version__ = "1.0.0"

import os

from dff.api.types.libtypes import Variant, RCVariant
from dff.api.events.libevents import EventHandler,event 

from dff.api.report.fragments import TableFragment, NodeListFragment, TextFragment, DetailTableFragment, ChatFragment

class PageConfiguration(EventHandler):
   def __init__(self, category, title, options=None):
       EventHandler.__init__(self)
       self.__title = title
       self.__category = category
       self.__options = options
       self.fragments = []
       self.__selected = True

   def selected(self, state = None):
      if state != None:
        self.__selected = state
      return self.__selected

   def category(self):
      return self.__category

   def remove(self):
      self.__category.removePage(self) 

   def moveBefore(self):
      self.__category.movePageBefore(self)

   def moveAfter(self):
      self.__category.movePageAfter(self)

   def title(self):
      title = self.__title
      if type(self.__title) == unicode:
        title.encode('UTF-8', 'replace')
      return title 

   def contentFileName(self):
      content = self.__title + ".js"
      if type(content) == unicode:
        content.encode('UTF-8', 'replace')
      return content

   def extractPath(self):
      extractPath = os.path.join(self.__category.name(), self.__title)
      if type(extractPath) == unicode:
        extractPath = extractPath.encode('UTF-8', 'replace')
      return extractPath

   def fullPath(self):
      fullPath = self.__category.name() + "/" + self.__title
      if type(fullPath) == unicode:
        fullPath = fullPath.encode('UTF-8', 'replace')
      return fullPath

   def contentRelativePath(self):
      relativePath = self.__category.name() + "/" + self.__title + "/" + self.contentFileName()
      if type(relativePath) == unicode:
        relativePath = relativePath.encode('UTF-8', 'replace')
      return relativePath

class ReportPage(PageConfiguration):
    EventExportStart = 0x200
    EventExportFinish = 0x201
    EventExportFragments = 0x202

    def Event(self, event):
        self.notify(event)
        
    def addChats(self, title, chats):
       chatFragment = ChatFragment(title, chats)
       chatFragment.connection(self)
       self.fragments.append(chatFragment)
       return chatFragment

    def addTable(self, title, head, data):
        tableFragment = TableFragment(title, head, data)
        tableFragment.connection(self)
        self.fragments.append(tableFragment)
        return tableFragment

    def add(self, fragment):
       self.fragments.append(fragment)
   
    def addDetailTable(self, title, head):
        detailTableFragment = DetailTableFragment(title, head)
        detailTableFragment.connection(self)
        self.fragments.append(detailTableFragment)
        return detailTableFragment

    def addText(self, title, data):
        textFragment = TextFragment(title, data)
        textFragment.connection(self)
        self.fragments.append(textFragment)
        return textFragment

    def addNodeList(self, title, nodes, thead = NodeListFragment.DefaultHeader, view=NodeListFragment.ListView):
        nodesFragment = NodeListFragment(title, nodes, thead, view)
        nodesFragment.connection(self)
        self.fragments.append(nodesFragment)
        return nodesFragment

    def exportSize(self, exportContent = True):
       size = 0
       for frag in self.fragments:
          size += frag.writeSize(exportContent) 
       return size

    def exportJSON(self, report_path, exportContent = True):
        self.__notify(ReportPage.EventExportStart, self.title())
        content_abspath = os.path.join(report_path, self.contentRelativePath())
	if os.name == "nt":
	  content_abspath = content_abspath.decode('UTF-8', 'replace')
        with open(content_abspath, 'w') as f:
            relativePath = self.contentRelativePath()
            f.write('DFF_DB.setDatabase("' + relativePath + '", [')
            self.__notify(ReportPage.EventExportFragments, len(self.fragments))
            for frag in self.fragments:
                  frag.writeJSON(f, self.fullPath(), report_path, exportContent)
                  f.write(',\n')
            f.write("])")
        self.__notify(ReportPage.EventExportFinish, self.title())

    def dumpsJSON(self):
        relativePath = self.contentRelativePath()
        if os.name == 'nt':
          relativePath = relativePath.replace('\\', '\\\\')
        buff = ('DFF_DB.setDatabase("' + relativePath + '", [')
        for frag in self.fragments:
           rbuff = frag.dumpsJSON()
           if type(rbuff) == unicode:
             rbuff = rbuff.encode('UTF-8', 'replace') 
           buff += rbuff
           buff += ',\n'
        buff += "])"
        return buff

    def __notify(self, eventType, value):
      e = event()
      e.thisown = False
      e.type = eventType
      e.value = RCVariant(Variant(value))
      self.notify(e)
