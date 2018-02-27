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

import os, json, sys
import dff.api.report

from collections import OrderedDict
from distutils import dir_util, sysconfig

from dff.api.types.libtypes import Variant, RCVariant
from dff.api.events.libevents import EventHandler, event
from dff.api.report.page import ReportPage
from dff.api.report.fragments import NodeListFragment

class ReportCategory(object):
  def __init__(self, name):
     self.__name = name
     self.__pages = []
     self.__selected = True

  def name(self):
     return self.__name

  def selected(self, state = None):
     if state:
       self.__selected = state
     return self.__selected

  def page(self, pageTitle):
     for page in self.__pages:
       if pageTitle == page.title():
         return page

  def addPage(self, newPage, overwrite = True):
     """Add a page to a category, overwrite it if the page already exist"""
     if overwrite == True:
       for page in self.__pages:
         if newPage.title() == page.title():
           self.__pages.remove(page)
     self.__pages.append(newPage)

  def movePageBefore(self, page):
     try:
        index = self.__pages.index(page)
        if index != 0:
          self.__pages.pop(index)
          self.__pages.insert(index - 1, page)
          return True
     except ValueError:
         pass
     return False 

  def movePageAfter(self, page):
     try:
        index = self.__pages.index(page)
        if index != len(self.__pages) - 1:
          self.__pages.pop(index)
          self.__pages.insert(index + 1, page)
          return True
     except ValueError:
        pass
     return False

  def removePage(self, page):
     self.__pages.remove(page)

  def pages(self):
     return self.__pages 

  def __len__(self):
     return len(self.__pages)

  def __iter__(self):
     for page in self.__pages:
        yield page 

  def __getitem__(self, pageTitle):
     for page in self.__pages:
        if page.title() == pageTitle:
          return page

class ReportManager(object):
  """ Singleton report class
  Refer to __ReportManager
  """
  if hasattr(sys, 'frozen'):
    TemplatePath = os.path.join(os.path.dirname(sys.executable), "resources", 'templates')
  else:
    TemplatePath = dff.api.report.__path__[0] + '/templates/'
  __instance = None
  EventExportCategoryStart = 0x301
  EventExportCategoryFinish = 0x302
  EventExportCategories = 0x303
  EventExportPages = 0x304
  EventExportItems = 0x305
  EventNewCategory = 0x306
  EventNewPage = 0x307
  class __ReportManager(EventHandler):
    def __init__(self):
      EventHandler.__init__(self)
      self.__categories = []
      self.__exportCancel = False
      self.setExportPath()

    def setNodeDetailedAttributes(self, attributes):
       NodeListFragment.DetailedAttributes = attributes

    def setNodeHeaderAttributes(self, attributes):
       NodeListFragment.HeaderAttributes = attributes
       uniqueName = set()
       for name, attribute in attributes:       
         uniqueName.add(name)
       NodeListFragment.HeaderAttributesName = list(uniqueName)

    def Event(self, event):
       if self.__exportCancel:
         raise Exception("Export cancel")
       self.notify(event)

    def exportCancel(self):
       self.__exportCancel = True

    def exportPath(self):
       return self.export_path

    def setExportPath(self, path=None):
      """ (Re)set the local absolute export Path 

      @type path: string
      @param path: Absolute local path

      If path is not specified, the local export path will be (re)set to its default value (~/dff-report)
      Overwise it sets the export_path variable to path
      """
      if not path:
        self.export_path = os.path.join(os.path.expanduser('~'), 'dff-report')
      else:
        self.export_path = path

    def categories(self):
       return self.__categories

    def category(self, categoryName):
      """ Return an existing category or create one"""
      if type(categoryName) == unicode:
        categoryName = categoryName.encode('UTF-8', 'replace')
      for category in self.__categories:
         if categoryName == category.name():
           return category
      category = ReportCategory(categoryName)
      self.__categories.append(category)
      self.__notify(ReportManager.EventNewCategory, category.name())
      return category 
  
    def removeCategory(self, category):
      self.__categories.remove(category) 

    def moveCategoryBefore(self, category):
      try:
        index = self.__categories.index(category)
        if index != 0:
          self.__categories.pop(index)
          self.__categories.insert(index - 1, category)
          return True
      except ValueError:
         pass
      return False 

    def moveCategoryAfter(self, category):
      try:
        index = self.__categories.index(category)
        if index != len(self.__categories) - 1:
          self.__categories.pop(index)
          self.__categories.insert(index + 1, category)
          return True
      except ValueError:
        pass
      return False

    def createPage(self, categoryName, pageTitle):
       if type(categoryName) == type(unicode):
         categoryName = categoryName.encode('UTF-8', 'replace')
       category = self.category(categoryName)
       page = ReportPage(category, pageTitle)
       return page
      
    def addPage(self, page):
       """Add a ReportPage to the managed categories, add the category if doesn't exist yet"""
       category = page.category()
       category.addPage(page)
       page.connection(self)
       self.__notify(ReportManager.EventNewPage, category.name())

    def index(self):
      """ Get the full index map used to generate the base content structures and links
      It takes the pages map and convert if to structured data list
      @return: Index map whith categories and pages data
      """
      index = OrderedDict()
      for category in self.__categories:
        if category.selected():
          page_data = []
          for page in category.pages():
            if page.selected():
              section_map = {}
              section_map["title"] = page.title()
              section_map["content"] = page.contentRelativePath() 
              page_data.append(section_map)
              index[category.name()] = page_data
      return index


    def totalItems(self):
       """Calculate the number of category, pages, fragment and subfragment, and notify listner,
       this is usefull for progressbar"""
       items = 0
       totalCategories = len(self.__categories)
       totalPages = 0
       totalFragments = 0
       totalElements = 0
       for category in self.__categories:
          totalPages += len(category)
          for page in category:
             totalFragments += len(page.fragments)
             for fragment in page.fragments:
                totalElements += len(fragment.elements())
       total = totalCategories + totalPages + totalFragments + totalElements
       return total

    def pathToUrl(self, path):
       url = os.path.join(ReportManager.TemplatePath, path)
       if os.name == "nt":
           url = "/" + url.replace("\\", "/")
       return url

    def exportPreview(self):
       self.bufferMap = {}
       indexBuff = self.dumpsIndex()
       url = self.pathToUrl('index.js')
       self.bufferMap[url] = indexBuff
       for category in self.__categories:
        if category.selected():
          for page in category:
            if page.selected():
              buff = page.dumpsJSON()
              self.bufferMap[self.pathToUrl(page.contentRelativePath())] = buff
       return self.bufferMap

    def exportSize(self, exportContent = True):
       size = 0
       for category in self.__categories:
          if category.selected():
             for page in category:
                if page.selected():
                   size += page.exportSize(exportContent)
       return size       

    def export(self, exportContent = True):
      #XXX throw error rather than returning True/False to display a message after exporting ?
      self.__exportCancel = False
      dir_util._path_created = {}
      if self.__exportTemplate():
        self.__writeIndex()
        self.__notify(ReportManager.EventExportItems, self.totalItems())
        self.__notify(ReportManager.EventExportCategories, len(self.__categories))
        for category in self.__categories:
          if category.selected():
            self.__notify(ReportManager.EventExportCategoryStart, category.name())
            self.__notify(ReportManager.EventExportPages, len(category))
            for page in category:
              if page.selected():
                if not self.__makePath(page):
                  return False
                try:
                  page.exportJSON(self.export_path, exportContent)
                except Exception as e:
                  print 'ReportManager.export page failed ' + str(e)
		  print 'failed to export', page.title(), page.category().name()
          self.__notify(ReportManager.EventExportCategoryFinish, category.name())
      return True 
   
    def __notify(self, eventType, value):
       """Sent event evenType containing value
       """
       e = event()
       e.thisown = False
       e.type = eventType
       if type(value) == unicode:
         value = value.encode('UTF-8')
       e.value = RCVariant(Variant(value))
       self.notify(e) 

    def join(self, a, b):
      if os.name == "nt":
	if type(a) == unicode:
	  a = a.encode('UTF-8', 'replace')
 	if type(b) == unicode:
	  b = b.encode('UTF-8', 'replace')
      if os.name == "nt":
	result = a + "\\" + b
	return result.decode('UTF-8', 'replace')
      return a + '/' + b

    def __makePath(self, page):
      try:
        dir_util.mkpath(self.join(self.export_path, page.extractPath()))
        filespath = self.join(self.export_path, self.join(page.extractPath(), 'files'))
        dir_util.mkpath(filespath)

        thumbspath = self.join(self.export_path, self.join(page.extractPath(), 'thumbs'))
        dir_util.mkpath(thumbspath)
        return True
      except Exception as e:
        print "ReportManager.__makePath exception " + str(e)
        return True 

    def __writeIndex(self):
      """ Write the Index map as JSON file at the root of the report
      """
      index_filepath = os.path.join(self.export_path, "index.js")
      if os.name == "nt":
        index_filepath = os.path.join(self.export_path, "index.js").decode('UTF-8', 'replace')
      else:
        index_filepath = os.path.join(self.export_path, "index.js")
      with open(index_filepath, 'w') as f:
        f.write('DFF_REPORT_INDEX = \n')
        json.dump(self.index(), f)

    def dumpIndex(self, stream):
       stream.write('DFF_REPORT_INDEX = \n')
       json.dump(self.index(), stream)  

    def dumpsIndex(self):
       buff = 'DFF_REPORT_INDEX = \n' 
       buff += json.dumps(self.index())
       return buff 

    def __exportTemplate(self):
      if os.path.exists(ReportManager.TemplatePath):
        dir_util.copy_tree(ReportManager.TemplatePath, self.export_path)
        return True
      return False

  def __init__(self):
     if ReportManager.__instance is None:
       ReportManager.__instance = ReportManager.__ReportManager()

  def __setattr__(self, attr, value):
     setattr(self.__instance, attr, value)

  def __getattr__(self, attr):
     return getattr(self.__instance, attr)
