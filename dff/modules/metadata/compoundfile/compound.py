# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2013 ArxSys
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

__dff_module_compound_version__ = "1.0.0"

import datetime, sys, traceback

from dff.api.module.script import Script 
from dff.api.module.module import Module
from dff.api.module.manager import ModuleProcessusHandler
from dff.api.vfs.libvfs import AttributesHandler, VFS, mfso, Node
from dff.api.types.libtypes import Argument, typeId, VMap, Variant

from mscfb import CompoundDocumentHeader
from msoleps import  PropertySetStream
from msdoc import WordDocument
from msoshared import OfficeDocumentSectionCLSID
from msppt import PPT
from vba import VBA, decompress_stream

def error():
   err_type, err_value, err_traceback = sys.exc_info()
   for n in  traceback.format_exception_only(err_type, err_value):
     print n
   for n in traceback.format_tb(err_traceback):
     print n

class CompoundDocumentParser(object):
  def __init__(self, node, args, mfsobj = None):
     self.node = node
     self.attr = {} 
     self.extraAttr = []
     self.codePage = None
     try :   
        self.cdh = CompoundDocumentHeader(node, mfsobj)
	self.cdh.parseDocument(not 'no-extraction' in args)
     except :
	#error()
	raise Exception("Can't parse document")
     streams = self.cdh.streams()
     for stream in streams:
        if stream.objectType =="StorageObject":
          if stream.objectName == "VBA": 
            if not 'no-vba-detection' in args:
              VBA(self, mfsobj, stream, args)
	elif stream.objectType == "StreamObject":
	  try:
	     if stream.objectName == "WordDocument":
	       if not 'no-extraction' in args:
	         wd = WordDocument(stream)
	         if not 'no-text' in args:
	           wd.createTextNodes()
	         if not 'no-pictures' in args:
	           wd.createPictureNodes()
	     elif stream.objectName == "Pictures":
	       if not ('no-pictures' in args or 'no-extraction' in args):
	         ppt = PPT(stream)
	         ppt.createPictureNodes()
	     else:
               self.setPropertySetStreamAttributes(stream, args)
	  #except RuntimeError, e: #not a PropertySetStream
	    #pass	 
          except :
            pass
	    #error()
        if not 'no-extraction' in args:
	  del stream 

  def setPropertySetStreamAttributes(self, stream, args):
    propertySet = PropertySetStream(stream, OfficeDocumentSectionCLSID.keys())
    for clsid in OfficeDocumentSectionCLSID.iterkeys():
      section = propertySet.sectionCLSID(clsid)
      if section:
        (sectionName, sectionIDS) = OfficeDocumentSectionCLSID[clsid]
        mattr = VMap() 
        for k, v in sectionIDS.iteritems():
          Property = section.PropertyList.propertyID(k)
          if Property and Property.Variant.Value:
            p = section.PropertyList.propertyID(k).Variant.Value
            if p and isinstance(p, Variant): #Thumbnail is type node
              if v == 'Total editing time': #special case see msoshared.py
                p = Variant(str(datetime.timedelta(seconds=(p.value()/10000000))))
              elif v == 'Code page':
                codePage = p.value()
                if isinstance(codePage, long):
                  self.codePage = 'cp' + str(codePage)
              elif self.codePage and (v == "Title" or v == "Subject" or v == "Author" or v == "Comments" or v == "Last Author"):
                p = Variant(p.value().decode(self.codePage).encode('UTF-8'))
              else:
                p = Variant(p)
              mattr[v] =  p
        stream.setExtraAttributes((sectionName, mattr,))
        if not 'no-root_metadata' in args:	
          self.extraAttr.append((sectionName, stream.parent().name(), mattr,))
 
  def _attributes(self):
     vmap = VMap()
     vmap["Compound document"] = self.cdh._attributes()
     for (name, parent, attr) in self.extraAttr:
	vmap[name + ' (' + parent + ')'] = attr
     return vmap	

class MetaCompoundHandler(AttributesHandler, ModuleProcessusHandler):
  def __init__(self):
    AttributesHandler.__init__(self, "metacompound")
    ModuleProcessusHandler.__init__(self, "metacompound")
    self.__disown__()
    self.nodeAttributes = {}
    self.vfs = VFS.Get()
 
  def setAttributes(self, node, classAttributes):
    self.nodeAttributes[node.uid()] = classAttributes 

  def update(self, processus):
    pass

  def nodes(self, root):
    nodes = []
    rootAbsolute = root.absolute()
    for node in self.nodeAttributes.keys():
      node = self.vfs.getNodeById(node)
      if node.absolute().find(rootAbsolute) == 0:
	nodes.append(node)
    return nodes

  def attributes(self, node):
    try:
      classAttributes = self.nodeAttributes[node.uid()]
      return classAttributes._attributes()
    except KeyError:
      attr = VMap()
      attr.thisown = False
      return attr

class MetaCompound(mfso):
  def __init__(self):
   mfso.__init__(self, 'metacompound')
   self.__disown__()
   self.handler = MetaCompoundHandler()
   self.vbaCompressed = {}

  def setVBACompressed(self, node, offset):
    self.vbaCompressed[node.uid()] = offset

  def start(self, args):
    try:
      largs = []
      node = args['file'].value()	
      for arg in ['no-extraction', 'no-text', 'no-pictures', 'no-root_metadata', 'no-vba-detection', 'no-vba-decompression']:
	try:
	  value =  args[arg].value()
	  if value:
	    largs.append(arg)
	except IndexError:
	  pass
      self.stateinfo = "Registering node: " + str(node.name())
      p = CompoundDocumentParser(node, largs, self)
      self.handler.setAttributes(node, p)
      node.registerAttributes(self.handler)
      self.stateinfo = ""
    except (KeyError, Exception):
      self.stateinfo = "Error"

  def vread(self, fd, buff, size):
      try:
        fi = self._mfso__fdmanager.get(fd)
        compressedOffset = self.vbaCompressed.get(fi.node.uid())
        if compressedOffset is None:
          return mfso.vread(self, fd, buff, size)
        maxOffset = fi.node.size() 
        endOffset = fi.offset + size
        if endOffset > maxOffset:
          endOffset  = maxOffset
        if fi.offset == endOffset:
          return (0, "") 
        vfile = fi.node.parent().open()
        vfile.seek(compressedOffset)
        decomp = decompress_stream(vfile.read())[fi.offset:endOffset]
        vfile.close()
        sizeRead = endOffset - fi.offset
        fi.offset = endOffset
        return (sizeRead, decomp)
      except Exception as e:
        return (0, "")

class compound(Module): 
  """This module extracts metadata and content of compound files (doc,xls,msi, ...)"""
  def __init__(self):
    Module.__init__(self, "compound", MetaCompound)
    self.conf.addArgument({"name": "file",
                           "description": "Extract metadata and content of this file",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addConstant({"name": "mime-type", 
 	                   "type": typeId.String,
 	                   "description": "compatible extension",
 	                   "values": ["windows/compound", "document/word", "document/excel", "document/powerpoint"]})
    self.conf.addArgument({"name": "no-extraction",	
			   "description" : "Don't create nodes for files stored inside compound documents",
			   "input": Argument.Empty})
    self.conf.addArgument({"name": "no-text",	
			   "description" : "Don't extract text from word document",
			   "input": Argument.Empty})
    self.conf.addArgument({"name": "no-pictures",	
			   "description" : "Don't extract pictures from word and powerpoint documents",
			   "input": Argument.Empty})
    self.conf.addArgument({"name" : "no-root_metadata",
			   "description" : "Don't apply metadata on the root document",
			   "input": Argument.Empty})
    self.conf.addArgument({"name" : "no-vba-detection",
                           "description": "Don't try to detect malicious VBA macro",
                           "input": Argument.Empty})
    self.conf.addArgument({"name" : "no-vba-decompression",
                           "description": "Don't decompress VBA macro",
                           "input": Argument.Empty})
    #self.flags = ["single"]
    self.tags = "Metadata"
    self.icon = ":document.png"
