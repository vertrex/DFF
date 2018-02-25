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
import threading, json
from collections import OrderedDict

import splunklib.client as client

from dff.api.module.script import Script 
from dff.api.module.module import Module
from dff.api.types.libtypes import Variant, RCVariant, VList, VMap, Argument, Parameter, typeId, DateTime 
from dff.api.vfs.vfs import vfs
from dff.api.vfs.libvfs import TagsManager

class SplunkConnection():
  DefaultAttribute = ['name', 'path', 'absolute', 'module', 'has children', 'child count', 'is deleted', 'size']
  def __init__(self):
    pass

  def writeMeta(self, index, node):
    try:
      sdump = json.dumps(self.attributesToMap(node))
      moduleName = "DFF_Module"
      if node.fsobj():
        moduleName = node.fsobj().name
      index.submit(sdump, source = "DFF_" + str(moduleName), sourcetype="DFFAttributes")
      #must use attach that cause a threading problem in splunk ?
      #cn = index.attach(source = "DFF_" + str(moduleName), sourcetype="DFFAttributes")
     #DUMP NODE DATA CONTENT
     #if str(node.dataType()).find("text") != -1:
       #sdump = sdump[0:-1]
       #sdump += ', "data": ' #"'       
       #cn.write(sdump) 
       #self.writeNodeContent(cn, node)
       #cn.write('}')
       ##cn.write('"}')
     #else:
      #cn.write(sdump)
      #cn.close()
      return True
    except Exception as e:
      print e
    return False

  def writeNodeContent(self, cn, node): 
     try:
       vfile = node.open()
       buff = vfile.read(10*1024*3) #Write only <= 10 MB of content  
       jbuff = json.dumps(buff)
       cn.write(jbuff)
       vfile.close()        
     except Exception as e:
       print "Can't send node content " + str(node.absolute()) + " Error: " 
       print str(e) 

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
		keypath = keyname + "." + str(key)
	      else:
		keypath = str(key)
	      self.recurseVariantType(keypath, vvar, attributesFound)
        else:
	  self.setVariantValue(attributesFound, keyname, var)

  def setVariantValue(self, attributesFound, key, var):
     if var.type() == typeId.DateTime:
        vtime = var.value()
        if vtime:
	  attributesFound[key] = str(vtime)
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

class SplunkIndexer(Script):
  def __init__(self):
   Script.__init__(self, "splunk")
   self.index = None
   self.service = None
   self.indexedTag = None
 
  def start(self, args):
   node  = args['node'].value()
   try:
     indexName = args['index_name'].value().lower()
   except IndexError:
     indexName = "dff"

   try:
     shost, sport = args['host'].value().split(':')
     sport = int(sport)
   except IndexError:
     shost, sport = ('localhost', 8089)
  
   try:
     susername = args['user_name'].value()
   except IndexError:
     susername = 'admin'

   try:
     spassword = args['password'].value()
   except IndexError:
     spassword = 'DFFSplunk'

   if not self.service:
     self.service = client.connect(host=shost, port=sport, username=susername, password=spassword)
     assert isinstance(self.service, client.Service)

   if not self.indexedTag:
     tagsManager = TagsManager.get()
     try:
       self.indexedTag = tagsManager.tag("indexed").id()
     except KeyError:
       self.indexedTag = tagsManager.add("indexed") 

   if not self.index:
     if not indexName in self.service.indexes:
       self.index = self.service.indexes.create(indexName) 
     else:
       self.index = self.service.indexes[indexName]

   self.splunkConnection = SplunkConnection()
   self.total = node.totalChildrenCount() + 1
   self.currentCount = 0  
   self.walk(node)

  def walk(self, node):
   if self.splunkConnection.writeMeta(self.index, node):
     node.setTag(self.indexedTag)
   self.currentCount += 1
   self.stateinfo = "Splunked " + str(self.currentCount) + '/' + str(self.total)

   children = node.children() 
   for child in children:
     self.walk(child) 

class splunk(Module): 
  """This modules index nodes metadata trough splunk."""
  def __init__(self):
    Module.__init__(self, "splunk", SplunkIndexer)
    self.conf.addArgument({"name": "node",
                           "description": "Node to index",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addArgument({"name": "host",
			   "input": Argument.Optional|Argument.Single|typeId.String,
			   "description": "Splunk host:port",
			   "parameters": {"type" : Parameter.Editable, 
					  "predefined": ["localhost:8089"]}})
    self.conf.addArgument({"name": "index_name",
			   "input": Argument.Optional|Argument.Single|typeId.String,
			   "description": "Splunk index",
			   "parameters": {"type" : Parameter.Editable, 
					  "predefined": ["dff"]}})
    self.conf.addArgument({"name": "login",
			   "input": Argument.Optional|Argument.Single|typeId.String,
			   "description": "Splunk server user login",
			   "parameters": {"type" : Parameter.Editable, 
					  "predefined": ["admin"]}})
    self.conf.addArgument({"name": "password",
			   "input": Argument.Optional|Argument.Single|typeId.String,
			   "description": "Splunk server user password",
			   "parameters": {"type" : Parameter.Editable, 
					  "predefined": ["password"]}})
    self.flags = ["single", "generic"]
    self.tags = "Analyse"
    self.icon = "splunk.jpg"
    self.depends = ['File systems', 'Volumes', 'Databases', 'Metadata', 'Mailbox', 'Malware'] 
