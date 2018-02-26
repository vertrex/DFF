# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2011 ArxSys
# 
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
from elasticsearch import Elasticsearch

from dff.api.module.script import Script 
from dff.api.module.module import Module
from dff.api.types.libtypes import Variant, RCVariant, VList, VMap, Argument, Parameter, typeId, DateTime 
from dff.api.vfs.vfs import vfs
from dff.api.vfs.libvfs import TagsManager

class ElasticConnection():
  DefaultAttribute = ['name', 'path', 'absolute', 'module', 'has children', 'child count', 'is deleted', 'size']
  def __init__(self, es, indexName):
    self.es = es
    self.indexName = indexName

  def writeMeta(self, index, node):
    try:
      attributesMap = self.attributesToMap(node)
      text  = self.nodeText(node)
      if len(text):
        attributesMap["text"] = self.nodeText(node)
      self.es.index(index=self.indexName, doc_type="dff-node", id=node.uid(), body=attributesMap)
      return True
    except Exception as e:
      print 'Indexation error ', e
    return False

  def nodeText(self, node): 
     if str(node.dataType()).find("text") != -1:
       try:
         vfile = node.open()
         buff = vfile.read() #Write only <= 10 MB of content  
         vfile.close()       
         return buff 
       except Exception as e:
         print "Can't read node content " + str(node.absolute()) + " Error: " 
         print str(e) 
     return ""

  def attributesToMap(self, node):
    attributesMap = self.defaultAttributes(node)
    self.recurseVariantType("", Variant(node.attributes()), attributesMap)
    return attributesMap #+ data & json !
   
  def defaultAttributes(self, node):
     m = {}
     m["name"] = node.name()
     m["path"] = node.path()
     m["absolute"] = node.absolute()
     if node.fsobj():
       m["module"] = node.fsobj().name
     m["has children"] = node.hasChildren()
     if node.hasChildren():
       m["child count"] = node.childCount()
     m["is deleted"] = node.isDeleted()
     m["size"] = node.size()
     return m 
    
  def recurseVariantType(self, keyname, var, attributesFound):
	if var.type() == typeId.Map:
	   vmap = var.value()
           for key, vvar in vmap.iteritems():
	      if len(keyname):
		keypath = keyname + "_" + str(key)
	      else:
		keypath = str(key)
	      self.recurseVariantType(keypath, vvar, attributesFound)
        else:
	  self.setVariantValue(attributesFound, keyname, var)

  def setVariantValue(self, attributesFound, key, var):
     if var.type() == typeId.DateTime:
        datetime = var.value()
        if datetime:
	  attributesFound[key] = datetime.toPyDateTime()
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

class ElasticIndexer(Script):
  def __init__(self):
   Script.__init__(self, "elasticindexer")
   self.index = None
   self.service = None
   self.indexedTag = None
 
  def start(self, args):
   try:
     node  = args['node'].value()
   except :
     node = vfs().getnode("/")
   try:
     indexName = args['index_name'].value().lower()
   except IndexError:
     indexName = "dff"

   self.indexedTag = TagsManager.get().tag("indexed").id()
   self.es = Elasticsearch()
   self.es.indices.create(indexName, ignore=400)
   self.elasticConnection = ElasticConnection(self.es, indexName)

   self.total = node.totalChildrenCount() + 1
   self.currentCount = 0  
   self.walk(node)

  def walk(self, node):
   if self.elasticConnection.writeMeta(self.index, node):
     node.setTag(self.indexedTag)
   self.currentCount += 1
   self.stateinfo = "Indexed " + str(self.currentCount) + '/' + str(self.total)

   children = node.children() 
   for child in children:
     self.walk(child) 

class elasticsearchindexer(Module): 
  """This modules index nodes metadata and text content trough elasticsearch."""
  def __init__(self):
    Module.__init__(self, "elasticsearchindexer", ElasticIndexer)
    self.conf.addArgument({"name": "index_name",
			   "input": Argument.Optional|Argument.Single|typeId.String,
			   "description": "Elastic search index name",
			   "parameters": {"type" : Parameter.Editable, 
					  "predefined": ["dff"]}})
    self.flags = ["single", "generic"]
    self.tags = "Analyse"
    #self.icon = "splunk.jpg"
    self.depends = ['File systems',  'Volumes'] 
    tagsManager = TagsManager.get()
    tagsManager.add("indexed") 
