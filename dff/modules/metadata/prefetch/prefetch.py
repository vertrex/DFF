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

__dff_module_prefetch_version__ = "1.0.0"

import sys, traceback
from struct import unpack

from dff.api.module.script import Script 
from dff.api.module.module import Module
from dff.api.module.manager import ModuleProcessusHandler
from dff.api.types.libtypes import Variant, VMap, VList, Argument, typeId, MS64DateTime
from dff.api.vfs.libvfs import AttributesHandler, VFS

from dff.modules.structparser import Struct, Header, ResolveAttributesMap, AttributesVMap


class PrefetchParser():
  PrefetchMagic = [("\x11\x00\x00\x00\x53\x43\x43\x41", "prefetch_XP", "Windowx XP"),
		    ("\x17\x00\x00\x00\x53\x43\x43\x41", "prefetch_Vista", "Windows Vista"),
		    ("\x1a\x00\x00\x00\x53\x43\x43\x41", "prefetch_Windows8", "Windows 8")]

  PrefetchHeader = ({ "info" : { "os":"windows" , "arch":"x86", "name" : "prefetch" },
	             "descr" : {
			          "prefetch_XP" : ((0x98),
				  {
				    "Standard" : (0x98, 0, "prefetch_standard"),
				    "LastExecutionTime"  : (8, 0x78),
				    "NumberOfExecution" : (4, 0x90)
				  }),
				  "prefetch_Vista" : ((0xf0),
			          {
				    "Standard" : (0x98, 0, "prefetch_standard"),
				    "LastExecutionTime" : (8, 0x80),
				    "NumberOfExecution" : (4, 0x98)
				  }),
                                  "prefetch_Windows8" : ((0xD4),
			          {
				    "Standard" : (0x98, 0, "prefetch_standard"),
				    "LastExecutionTime" : (8, 0x80),
                                    #timeinfo
				    "NumberOfExecution" : (4, 0xD0)
				  }),
  				  "prefetch_standard" : ((0x98),
  				  {
				    "Header" : (8, 0),
				    "HeaderSize" : (4, 0x54),
				    #"ApplicationName" : (?, 0x10),
				    "FileSize" : (4, 0xc),
				    "FirstFilePathBlock" : (4, 0x64),
				    "FirstFilePathSize" : (4, 0x68),
				    "VolumeInformationBlock" :  (4, 0x6c, "*VolumeInformationBlock"),
				  }),

				  "VolumeInformationBlock" : ((0x28),
				  {
	    			    "VolumePathOffset" : (4, 0x00),
    				    "VolumePathLength" : (4, 0x04),
    				    "VolumeCreationDate" : (8, 0x08),
    				    "VolumeSerialNumber" : (4, 0x10),
    				    "OffsetToBlob1" : (4, 0x14), 
    				    "LengthOfBlob1" : (4, 0x18),
    				    "OffsetToFolderPaths" : (4, 0x1c),
    				    "NumberOfFolderPaths" : (4, 0x20),
   				    "Unknown1" : (4, 0x24)
				  })
			       }
		    })

  PrefetchAttributesMap = {
	"Version" : ("version_name", str),
	"Last execution" : ("prefetch.LastExecutionTime", MS64DateTime),
	"Number of execution" : ("prefetch.NumberOfExecution", int),
	"Prefetch list" : ("prefetchFileList", list),
	"Volume creation" : ("prefetch.Standard.VolumeInformationBlock.VolumeCreationDate", MS64DateTime),
	"Number of folder paths" : ("prefetch.Standard.VolumeInformationBlock.NumberOfFolderPaths", int),
	"Serial number" : ("prefetch.Standard.VolumeInformationBlock.VolumeSerialNumber", int),
	"Volume path" : ("volumePath", str),
	"Volume prefetch list" : ("VolumePrefetchList", list)
	} 

  def __init__(self, node): 
     self.node = node
     self.vfile = node.open()
     self.attr = {} 

     try :
       self.header = Header(self.PrefetchHeader)

       self.vfile.seek(0)
       magic_data = self.vfile.read(8)
       prefetch_version = None
       for magic, version, version_name in self.PrefetchMagic:
	  if magic_data == magic:
	    prefetch_version = getattr(self.header, version)
	    self.version_name = version_name
       if not prefetch_version:
	 self.vfile.close
         #print 'Wrong magic number not a prefetch file : ' + node.absolute()
	 return 

       self.vfile.seek(0)
       self.data = self.vfile.read(prefetch_version.ssize)
       self.prefetch = Struct(self.header, self.vfile, prefetch_version, self.data)

       self.vfile.seek(self.prefetch.Standard.FirstFilePathBlock)
       self.data  = self.vfile.read(self.prefetch.Standard.FirstFilePathSize)
       self.prefetchFileList = unicode(self.data.decode('utf-16')).split("\x00")
       try:
         self.prefetchFileList.remove('')
       except ValueError as e:
        print e
	pass
       self.prefetchFileList = map(lambda x : (x, str), self.prefetchFileList)
       self.vfile.seek(self.prefetch.Standard.VolumeInformationBlock.VolumePathOffset + self.prefetch.Standard.VolumeInformationBlock.pointer)
       self.volumePath = self.vfile.read(self.prefetch.Standard.VolumeInformationBlock.VolumePathLength *2).decode('UTF-16').encode("UTF-8", "replace")

       self.VolumePrefetchList = []
       self.vfile.seek(self.prefetch.Standard.VolumeInformationBlock.pointer + self.prefetch.Standard.VolumeInformationBlock.OffsetToFolderPaths)
       pathSize = unpack('h', self.vfile.read(2))[0]
       count = 0
       while (pathSize > 0 and count < self.prefetch.Standard.VolumeInformationBlock.NumberOfFolderPaths):
         self.VolumePrefetchList.append((unicode(self.vfile.read(pathSize * 2+2).decode('UTF-16')).encode("UTF-8", "replace"), str))
	 count += 1
         pathSize = unpack('h', self.vfile.read(2))[0]

       self.vfile.close()
     except :
        print 'prefetch error on node ', node.absolute()
	err_type, err_value, err_traceback = sys.exc_info()
	for n in  traceback.format_exception_only(err_type, err_value):
	  print n
      	for n in traceback.format_tb(err_traceback):
	  print n
	self.vfile.close()
	raise Exception("Init error")

  def attributesMap(self):
    try:
      return ResolveAttributesMap(self, self.PrefetchAttributesMap)	
    except:
      pass

class PrefetchHandler(AttributesHandler, ModuleProcessusHandler):
  def __init__(self):
    AttributesHandler.__init__(self, "prefetch")
    ModuleProcessusHandler.__init__(self, "prefetch")
    self.__disown__()
    self.nodeAttributes = {}
    self.vfs = VFS.Get()
 
  def setAttributes(self, node, attributes):
    self.nodeAttributes[node.uid()] = attributes

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
      attr = self.nodeAttributes[node.uid()]
      return AttributesVMap(attr)
    except KeyError:
      attr = VMap()
      return attr

class Prefetch(Script):
  def __init__(self):
   Script.__init__(self, "prefetch")
   self.handler = PrefetchHandler()

  def start(self, args):
    try:
      node = args['file'].value()
      p = PrefetchParser(node)
      arg = p.attributesMap()
      self.stateinfo = "Registering node: " + str(node.name())
      self.handler.setAttributes(node, arg)
      node.registerAttributes(self.handler)
    except (KeyError, Exception):
      pass

class prefetch(Module): 
  """This module parses metadata of prefetch files and sets then to node's attributes"""
  def __init__(self):
    Module.__init__(self, "prefetch", Prefetch)
    self.conf.addArgument({"name": "file",
                           "description": "parses metadata of this file",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    #self.conf.addConstant({"name": "extension-type", 
    #	                   "type": typeId.String,
    # 	                   "description": "compatible extension",
    # 	                   "values": ["pf"]})
    self.conf.addConstant({"name": "mime-type", 
 	                   "type": typeId.String,
 	                   "description": "compatible extension",
 	                   "values": ["windows/prefetch"]})
    self.flags = ["single"]
    self.tags = "Metadata"
