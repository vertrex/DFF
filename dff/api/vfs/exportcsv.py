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

from dff.api.vfs.vfs import  vfs
from dff.api.types.libtypes import Variant, typeId, Argument, Parameter
from dff.api.taskmanager.scheduler import sched

class NodesAttributesMap(object): #Event Handler and put in attributes.py to be reused or put in cpp?
  def __init__(self):
    self.attributesMap = {}
 
  def fromRoot(self, root):
     self.totalCounts = self.root.totalChildrenCount()
     self.walk(self.root)
     self.setAttributes()

  def fromNodes(self, nodes):
    self.attributesMap = {}
    self.totalCounts = self.root.totalChildrenCount()
    for node in nodes:
      self.getAttributes(node)       
    self.setAttributes()
    return self.attributesMap

  def fromTimelineNodes(self, nodes):
    self.totalCounts = self.root.totalChildrenCount()
    for timelineNode in timelineNode:
      se.f.getAttributes(timelineNode.node())
    self.setAttributes()
    #XXX add soecial attribute TIMELINE_ATTRIBUTE 
    return self.attributesMap 

  def walk(self, node):
     #self.stateinfo = "Gathering all attributes : " + str(self.totalCount) + "/" + str(self.totalCounts) + " nodes parsed."
     self.getAttributes(node)
     if node.hasChildren():
       childrens = node.children()
       for child in childrens:
	  self.walk(child) 
 
  def getAttributes(self, node):
     try:
       attrs = node.attributesNames(0)
       for attr in attrs:
         if attr.find('.') != -1:
	   moduleName = attr.split('.')[0]
  	   try:
	     self.attributesMap[moduleName].add(str(attr))
           except KeyError:
	     self.attributesMap[moduleName] = set()
	     self.attributesMap[moduleName].add(str(attr))
  	   self.attributesSet.add(str(attr))
     except :
	 print "can't parse attributes by name for node " + str(node.absolute())
     self.totalCount += 1

  def setAttributes(self):
     for module in self.attributesMap:
	self.attributesMap[module] = list(self.attributesMap[module])
        self.attributesMap[module].sort()
     defaultAttribute = list()
     defaultAttribute.insert(0, "name")
     defaultAttribute.insert(1, "path")
     defaultAttribute.insert(2, "absolute")
     defaultAttribute.insert(3, "module")
     defaultAttribute.insert(4, "has children")
     defaultAttribute.insert(5, "child count")
     defaultAttribute.insert(6, "is deleted")
     defaultAttribute.insert(7, "size")
     defaultAttribute.insert(8, "extension")
     self.attributesMap['default'] = defaultAttribute

class CSV(object): #EventHandler ? 
  def __init__(self):
     self.vfs = vfs()
     self.totalCount = 0
     self.totalCounts = 0
     self.count = 0
     self.fileSplit = 1 #current splitted file	
     self.csvfile = None
     self.outputpath = None
     self.split = False 

  def exportRoot(self, outputpath, root, attributes, split = False):
     """Recursively export nodes to csv from root"""
     self.outputpath = outputpath
     self.attributesSet = attributes
     self.split = split
     self.totalCounts = self.root.totalChildrenCount() 
     self.touchFile()
     self.walkWriteNode(root)
     self.csvfile.close()

  def exportNodes(self, outputpath, nodes, attributes, split = False):
     """Export nodes list to csv"""
     self.outputpath = outputpath
     self.attributesSet = attributes
     self.split = split
     self.totalCounts = len(nodes) 
     self.touchFile()
     for node in nodes:
       self.writeNode(node)
     self.csvfile.close()
      
  def exportTimeLineNodes(self):
    pass
    #same as before with 
    #for timeLineNode in timelineNode.node()
        #self.getAttributes(timelineNode.node())

  def touchFile(self):
     buff = ""
     for attr in self.attributesSet:
         buff += '"' + str(attr)  + '",'
     buff += "\n"    
 
     if self.split:
       outputpath = self.outputpath.split('.csv')[0] + '-' + str(self.fileSplit) + '.csv'	
     else:
       outputpath = self.outputpath
     if self.csvfile:
       self.csvfile.close()
     self.csvfile = open(outputpath, 'wb')
     self.csvfile.write(buff)

  def writeNode(self, node):
     self.count += 1
     #self.stateinfo = "Writing node attributes (" + str(self.count) + "/" + str(self.totalCount) + ")"
     if self.split and (self.count % (65534) == 0):
	self.fileSplit += 1
	self.touchFile()	

     attributesFound = {}
     self.commonAttributes(node, attributesFound)
     try :
       nodeAttributes = node.attributes() 
       self.modulesAttributes(nodeAttributes, attributesFound)
     except :
	 print "can't get attributes for node " + str(node.absolute())
     self.writeAttributes(attributesFound) 

  def walkWriteNode(self, node):
     self.writeNode(node)
     if node.hasChildren():
       childrens = node.children()
       for child in childrens:
	  self.walkWriteNode(child)     

  def recurseVariantType(self, keyname, var, attributesFound):
	if var.type() == typeId.Map:
	   vmap = var.value()
           for key, vvar in vmap.iteritems():
	      if len(keyname):
		keypath = keyname + "." + str(key)
	      else:
		keypath = str(key)
	      self.recurseVariantType(keypath, vvar, attributesFound)
        else:
	  self.setVariantValue(attributesFound, keyname, var)

  def modulesAttributes(self, nodeAttributes, attributesFound):
     var = Variant(nodeAttributes)
     self.recurseVariantType("",  var, attributesFound)

  def setVariantValue(self, attributesFound, key, var):
     if var.type() == typeId.DateTime:
        dateTime = var.value()
        if dateTime:
	  attributesFound[key] = str(dateTime)
          return 
     elif var.type() == [typeId.Int16, typeId.UInt16, typeId.Int32, typeId.UInt32, typeId.Int64, typeId.UInt64, typeId.Char, typeId.String, typeId.CArray]:
	  attributesFound[key] = str(var.toString())
	  return 
     elif var.type() == typeId.Node:
	  attributesFound[key] = str(var.value().absolute())
     elif var.type() == typeId.Path:
	  attributesFound[key] = str(var.value().path)
     elif var.type() == typeId.List:
	  attributesFound[key] = str(var.value())
     else:
	  attributesFound[key] = str(var.value())

  def commonAttributes(self, node, attributesFound):
     attributesFound["name"] = node.name()
     attributesFound["path"] = node.path()
     attributesFound["absolute"] = node.absolute()                  
     if node.fsobj():
       attributesFound["module"] = node.fsobj().name
     attributesFound["has children"] = node.hasChildren()
     if node.hasChildren():
       attributesFound["child count"] = node.childCount()
     attributesFound["is deleted"] = node.isDeleted()
     attributesFound["size"] = node.size()
     attributesFound["extension"] = node.extension()
     tags = node.tags()
     for tag in tags:
       tagList.append(tag.name())
       attributesFound["tags"] = str(tagList) #unicode ?
     #XXX timeline common attributes here ? 

  def writeAttributes(self, attributesFound):
     buff = ""
     for attr in self.attributesSet:
        try:
	  val = attributesFound[attr]
          buff +=  '"' + str(val) + '",' 
        except KeyError:
	  buff += ','
     buff += '\n'
     self.csvfile.write(buff) 
