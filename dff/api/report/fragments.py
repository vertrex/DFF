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
import json

from collections import OrderedDict
from StringIO import StringIO

from PyQt4.QtGui import QApplication
from PyQt4.QtCore import QByteArray, QBuffer, QIODevice

from dff.api.events.libevents import EventHandler, event
from dff.api.types.libtypes import typeId, Variant, RCVariant, VMap, VList, DateTime 
from dff.api.vfs.libvfs import VFS, ABSOLUTE_ATTR_NAME
from dff.api.vfs.extract import Extract

from dff.ui.gui.thumbnail import Thumbnailer 

class ReportPageFragment(EventHandler):
    EventWriteStart = 0x100
    EventWriteFinish = 0x101
    EventWriteElements = 0x102
    EventWriteElementStart = 0x103
    EventWriteElementFinish = 0x104
    def __init__(self, title):
      
      self.title = title
      if type(self.title) == unicode:
        self.title = title.encode('UTF-8', 'replace')
      EventHandler.__init__(self)

    def Event(self, event):
        self.notify(event)

    def notifyWrite(self, eventType, value):
       e = event()
       e.thisown = False
       e.type = eventType
       try:
         e.value = RCVariant(Variant(value))
       except Exception as error:
	 print 'report.fragments.notifyWrite ', error, value
	 e.value = RCVariant(Variant(""))
       self.notify(e)  

    def elements(self):
       """Return fragments elements as list"""
       raise Exception("ReportPageFragment.elements method is not implemented.")
 
    def writeSize(self, exportContent): 
       """Return an aproximate size of data written by writeJSON__"""
       raise Exception("ReportPageFragment.writeSize method is not implemented.")

    def writeJSON__(self, fd, pagePath, reportPath, exportContent):
       raise Exception("ReportPageFragment.writeJSON method is not implemented.")

    def writeJSON(self, fd, pagePath, reportPath, exportContent):
       self.notifyWrite(ReportPageFragment.EventWriteStart, self.title)
       self.writeJSON__(fd, pagePath, reportPath, exportContent)
       self.notifyWrite(ReportPageFragment.EventWriteFinish, self.title)


class TabFragment(ReportPageFragment): #ReportPageTextFragment
    def __init__(self, title):
        ReportPageFragment.__init__(self, title)
        self.data = {}

    def elements(self):
       return [self.data]

    def addTab(self, title, fragment):
        self.data[title] = json.load(StringIO(fragment.dumpsJSON()))

    def dumpsJSON(self):
        buff = '{"title": "' + self.title + '",' + '"widget":"tab", "data":'
        buff += json.dumps(self.data)
        buff += "}"
        return buff

    def writeSize(self, exportContent):
        return 0

    def writeJSON__(self, fd, page_path, report_path, exportContent = True):
        buff = '{"title": "' + self.title + '",' + '"widget":"tab", "data":'
        fd.write(buff)
        json.dump(self.data, fd)
        fd.write("}")

class TextFragment(ReportPageFragment): #ReportPageTextFragment
    def __init__(self, title, data):
        ReportPageFragment.__init__(self, title)
        self.data = data

    def elements(self):
       return [self.data]

    def dumpsJSON(self):
        buff = '{"title": "' + self.title + '",' + '"widget":"text", "data":'
        buff += json.dumps(self.data)
        buff += "}"
        return buff

    def writeSize(self, exportContent):
       return 0

    def writeJSON__(self, fd, page_path, report_path, exportContent = True):
        buff = '{"title": "' + self.title + '",' + '"widget":"text", "data":'
        fd.write(buff)
        json.dump(self.data, fd)
        fd.write("}")

class TableFragment(ReportPageFragment):
    def __init__(self, title, head_list, rows):
        ReportPageFragment.__init__(self, title)
        self.title = title
        self.thead = head_list
        self.data = rows

    def elements(self):
       return [self.data]

    def dumpsJSON(self):
        buff = '{"title": "' + self.title + '",' + '"widget":"table", "thead" :'
        buff += json.dumps(self.thead)
        buff += ', "data" : '
        buff += json.dumps(self.data)
        buff += "}"
        return buff

    def writeSize(self, exportContent):
        return 0

    def writeJSON__(self, fd, page_path, report_path, exportContent = True):
        buff = '{"title": "' + self.title + '",' + '"widget":"table", "thead":'
        fd.write(buff)
        json.dump(self.thead, fd)
        bdata = ', "data" : '
        fd.write(bdata)
        json.dump(self.data, fd)
        fd.write("}")

class ChatFragment(ReportPageFragment):
    def __init__(self, title, chats):
        ReportPageFragment.__init__(self, title)
        self.title = title
        self.data = chats

    def elements(self):
       return [self.data]

    def dumpsJSON(self):
        buff = '{"title": "' + self.title + '",' + '"widget":"chat"'
        buff += ', "data" : '
        buff += json.dumps(self.data)
        buff += "}"
        return buff

    def writeSize(self, exportContent):
        return 0

    def writeJSON__(self, fd, page_path, report_path, exportContent = True):
        buff = '{"title": "' + self.title + '",' + '"widget":"chat"'
        fd.write(buff)
        bdata = ', "data" : '
        fd.write(bdata)
        json.dump(self.data, fd)
        fd.write("}")

class DetailTableFragment(ReportPageFragment):
    def __init__(self, title, head_list):
        ReportPageFragment.__init__(self, title)
        self.title = title
        self.thead = head_list
        self.rows = []
        self.thumbData = {}

    def addRow(self, data, detail=None, thumbData=None): #thumbData is a tuple (thumbnailname, thumbmailrawdata)
        if len(data) != len(self.thead) : return False
        row = {}
        for x in range(len(self.thead)):
           row[self.thead[x]] = data[x]
        if detail:
            row["row_details"] = json.load(StringIO(detail.dumpsJSON())) #XXX
        if thumbData:
            row["thumb"] = thumbData[0]
            self.thumbData[thumbData[0]] = thumbData[1]
        self.rows.append(row)
        return True

    def elements(self):
        return self.rows

    def dumpsJSON(self): #XXX pour l affichage ds dff 
        #XXX if self.thumbData:
        #XXX transfert to file 
        #XXX set row['thumb'] to file path 
        #en dff affiche dynamiquement  !
        buff = '{"title": "' + self.title + '",' + '"widget": "detail_table", "thead":'
        buff += json.dumps(self.thead)
        buff += ', "data" : '
        buff += json.dumps(self.rows)
        buff += "}"
        return buff

    def writeSize(self, exportContent):
        return 0

    def writeJSON__(self, fd, page_path, report_path, exportContent = True): 
        self.thumbpath = page_path + "/" + 'thumbs'
        for row in self.rows:
          try:
            thumbname = row['thumb']
            thumbdata = self.thumbData[thumbname]
            row['thumb'] = self.thumbpath + "/"+ thumbname + '.jpg'
            self.exportThumbnail(report_path, row['thumb'], thumbdata)
          except KeyError:
            pass

        buff = '{"title": "' + self.title + '",' + '"widget":"detail_table", "thead":'
        fd.write(buff)
        json.dump(self.thead, fd)
        bdata = ', "data" : '
        fd.write(bdata)
        json.dump(self.rows, fd)
        fd.write("}")

    def exportThumbnail(self, reportPath, thumbPath, data):  #XXX extract data thumbnail for test skype temporary
       exportPath = os.path.join(reportPath, thumbPath)
       with open(exportPath, 'wb') as f:
         f.write(data)

def getTags(node):
   s = ""
   tags = node.tags()
   for tag in tags:
     s += tag.name() + ","
   if s != "":
     s = s[:-1]  
   return str(s)

class NodeListFragment(ReportPageFragment):
    DefaultHeader = [{'title':'name', 'callback' : lambda Node: Node.name()},
                     {'title':'size', 'callback' : lambda Node: Node.size()},
                     {'title':'tags', 'callback' : lambda Node: getTags(Node)},
                    ]
    ListView = 0
    GalleryView = 1
    DetailedAttributes = None
    HeaderAttributes = None
    HeaderAttributesName = None
    def __init__(self, title, nodes, thead, view):
        ReportPageFragment.__init__(self, title)
        self.nodes = nodes
        self.thead = thead
        self.view = view
        self.extract = Extract()
        self.filepath = None
        self.thumbpath = None
        if QApplication.instance():
          self.gui = True
        else:
          self.gui = False
        #XXX header don't support '.' in name
    def addNode(self, node):
        self.nodes.append(node)

    def elements(self):
       return self.nodes

    def dumpsJSON(self):
        thead = []
        for head in self.thead : 
          thead.append(head['title'])
        if NodeListFragment.HeaderAttributes:
          for attribute in NodeListFragment.HeaderAttributes:
            thead.append(attribute)     
        buff = '{"title": "' + self.title + '",' + '"widget": "node_list", "thead":'
        buff += json.dumps(thead)
        buff += ', "view" : '+ str(self.view) +', "data" : ['
        for node in self.nodes:
          try :
            rowjson = {}
            rowjson['widget'] = 'node'
            for head in self.thead:
                cb = head['callback'](node)
                if type(cb) == str:
                  cb = cb.decode('utf-8', 'replace').encode('utf-8')
                rowjson[head['title']] = cb
                if self.gui: #Need qt gui for QPixmap or will crash in console
                  #print 'self as GUI !', QApplication.instance()
                  self.thumbnailer = Thumbnailer()
                  if self.thumbnailer.isThumbnailable(node):
                    rowjson["thumb"] = "dff-node-thumbnail://" + node.absolute().decode('utf-8', 'replace').encode('utf-8')
                  self.thumbnailer.unregister()
            rowjson['row_details'] = {'widget': 'node_attribute', 'data': self.attributesToMap(node.attributes()) }
            buff += json.dumps(rowjson)
            buff += ","
          except UnicodeError as e:
               print "Can't dump node " + str(node.absolute()) + " : " + str(e) 
        buff += "]}"
        return buff

    def writeSize(self, exportContent):
       size = 0
       if exportContent:
         for node in self.nodes:
            size += node.size()
       return size 

    def writeJSON__(self, fd, page_path, report_path, exportContent = True):
        self.filepath =  page_path + "/" + 'files'
        self.thumbpath = page_path + "/" + 'thumbs'
        buff = '{"title": "' + self.title + '",' + '"widget": "node_list", "thead":'
        fd.write(buff)
        thead = []
        for head in self.thead : 
           thead.append(head['title'])
        #XXX header don't support '.' in name
        if NodeListFragment.HeaderAttributesName:
          for name in NodeListFragment.HeaderAttributesName:
            thead.append(name)
        json.dump(thead, fd)
        bdata = ', "view" : '+ str(self.view) +', "data" : ['
        fd.write(bdata)
        self.notifyWrite(ReportPageFragment.EventWriteElements, len(self.nodes))
        for node in self.nodes:
          self.notifyWrite(ReportPageFragment.EventWriteElementStart, node.absolute())
          try :
            filename = None
            if exportContent:
              filename = self.exportNode(node, self.filepath, report_path)
            self.nodeToJSON(node, filename, fd, report_path, page_path, True)
            fd.write(',\n')
          except Exception as e:
            print "Can't write node " + str(node.absolute()) + " : " + str(e) 
          self.notifyWrite(ReportPageFragment.EventWriteElementFinish, node.absolute())
        fd.write("]}")

    def attributesToMap(self, attributes):
       attributesMap = {}
       for key, variantMap in attributes.iteritems():
          vmap =  self.recurseVariant(variantMap, {}, '')
          if len(vmap):
            attributesMap[key] = vmap
       attributesMap = OrderedDict(sorted(attributesMap.items(), key=lambda t : t[0])) 
       return attributesMap
        
    def recurseVariant(self, variant, varMap, keyPath):
       if isinstance(variant, VMap):
         for key, vvar in variant.iteritems():
           if len(keyPath): 
             self.recurseVariant(vvar, varMap, keyPath + '.' + str(key)) 
           else:
             self.recurseVariant(vvar, varMap, str(key)) 
       if isinstance(variant, VList):
         l = []
         for i in range(len(variant)):
           self.recurseVariant(variant[i], varMap, keyPath + ' (' + str(i) + ')')
       if isinstance(variant, Variant) or isinstance(variant, RCVariant): 
         val = variant.value()
         if isinstance(val, VMap) or isinstance(val, VList):
           self.recurseVariant(val, varMap, keyPath)
         else:
           if isinstance(val, DateTime):
             try:
               val = str(val)
             except:
               val = "Invalid"
           if type(val) == str:
             val = val.decode('utf-8', 'replace').encode('utf-8')
           translated = False
           if NodeListFragment.DetailedAttributes:
             for (finalName, attributeName) in NodeListFragment.DetailedAttributes: #HeaderAttributes depend of this because it's attribute filled in the table will use the result of this function called by attributesMap if there is no detailed attributes there will no translation and the header can't be filled 
               if keyPath == attributeName:
                 varMap[finalName] = val
           if not translated: 
               varMap[keyPath] = val
       varMap = OrderedDict(sorted(varMap.items(), key=lambda t : t[0])) 
       return varMap

    def findInAttributesMap(self, attribute, attributesMap):
      for module in attributesMap:
        moduleAttributes = attributesMap.get(module)
        if moduleAttributes:
          result = moduleAttributes.get(attribute)
          if result:
            return result
      return "" 

    def nodeToJSON(self, node, filename, fd, report_path, page_path, thumb=False):
        rowjson = {}
        rowjson['widget'] = 'node'
        attrMap = self.attributesToMap(node.attributes())
        for head in self.thead:
            cb = head['callback'](node)
            if type(cb) == str:
              cb = cb.decode('utf-8', 'replace').encode('utf-8')
            rowjson[head['title']] = cb
        if NodeListFragment.HeaderAttributes:
          for (name, attribute) in NodeListFragment.HeaderAttributes:
             result = self.findInAttributesMap(name, attrMap)
             rowjson[name] = result
        if filename:
          rowjson["file"] = self.filepath + "/" + filename
          if thumb and self.gui:
            if self.exportThumbnail(report_path, self.thumbpath, filename + '.jpg', node):
              rowjson["thumb"] = self.thumbpath + "/" + filename + '.jpg'
        rowjson['row_details'] = {'widget': 'node_attribute', 'data': attrMap }
        try:
          json.dump(rowjson, fd)
        except UnicodeError as e:
          print 'report.fragment.nodeToJSON failed ' + str(e)
          print rowjson

    def exportThumbnail(self, report_path, thumbpath, name, node, size = None):
        self.thumbnailer = Thumbnailer()
        if self.thumbnailer.isThumbnailable(node):
          pixmap = self.thumbnailer.generate(node, iconSize = 256, frames = 10, blocking = True)
          self.thumbnailer.unregister()
          if pixmap:
            try:
                exportPath = os.path.join(report_path, os.path.join(thumbpath, name))
                array = QByteArray()
                qfile = QBuffer(array)
                qfile.open(QIODevice.ReadWrite)
                pixmap.save(qfile, 'JPG')
                qfile.seek(0)
                with open(exportPath, 'wb') as f:
                    f.write(qfile.read(qfile.size()))
                qfile.close()
                return True
            except Exception as e:
                qfile.close()
                return False
          else:
            return False

    def exportNode(self, node, path, report_path):
        abspath = os.path.join(report_path, path)
        try :
          local_path = self.extract.extractFile(node, abspath)
        except Exception as e:
          pass

        if local_path:
            return os.path.basename(local_path)
        else:
            return None
