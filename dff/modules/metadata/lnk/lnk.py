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

__dff_module_lnk_version__ = "1.0.0"

from struct import unpack

from dff.api.module.script import Script 
from dff.api.module.module import Module
from dff.api.module.manager import ModuleProcessusHandler
from dff.api.types.libtypes import Variant, VMap, VList, Argument, typeId
from dff.api.vfs.libvfs import AttributesHandler, VFS, VLink

from dff.modules.structparser import Struct, Header, FlagsList, ResolveAttributesMap, AttributesVMap 

from dff.modules.lnk.lnkheader import FileAttributesFlags, LinkFlags, ShowCommandFlagsMap, HotKeysLowFlagsMap, HotKeysHighFlagsMap, LinkInfoFlags, DriveTypeMaps, NetworkProviderType, CommonNetworkRelativeLinkFlags, ExtraDataBlockMaps, FillAttributesFlags, FontFamily, PropertyType, PropertyTypeConverter, SerializedPropertyHeader, DataBlockHeader, ShellLinkHeader, LPWSTR, LnkAttributesMap
from dff.modules.lnk.lnkitem import ItemType, ItemTypeConverter, UnicodeBuff, UUID

import sys, os, traceback

class LNKParser():
  def __init__(self, node):
   try: 
     self.node = node
     self.vfile = node.open()

     self.header = Header(ShellLinkHeader)
     self.vfile.seek(0)
     self.data = self.vfile.read(self.header.ShellLinkHeader.ssize)
     self.shellLink = Struct(self.header, self.vfile, self.header.ShellLinkHeader, self.data)

     self.shellLink.FileAttributes = FlagsList(self.shellLink.FileAttributes, FileAttributesFlags)
     self.shellLink.LinkFlags = FlagsList(self.shellLink.LinkFlags, LinkFlags)
     self.shellLink.LinkCLSID = UUID(self.shellLink.LinkCLSID)

     try :
	self.shellLink.ShowCommand = ShowCommandFlagsMap[self.shellLink.ShowCommand]
     except KeyError:
	self.shellLink.ShowCommand = str(hex(self.shellLink.ShowCommand))

     if ("HasLinkTargetIDList",str) in self.shellLink.LinkFlags:
	self.getLinkTargetIDList()

     if ("HasLinkInfo", str) in self.shellLink.LinkFlags:
	self.getLinkInfo()

     for dataName in ("HasName", "HasRelativePath", "HasWorkingDir", "HasArguments", "HasIconLocation"):
	self.readStringData(dataName)

     if self.vfile.tell() < self.vfile.node().size():
     	self.getDataBlock()	

     self.vfile.close()

   except :
      err_type, err_value, err_traceback = sys.exc_info()
      print traceback.format_exception_only(err_type, err_value)
      print traceback.format_tb(err_traceback)
      self.vfile.close()

  def getLinkInfo(self):
	linkInfoStartOffset = self.vfile.tell()
	self.data = self.vfile.read(self.header.LinkInfo.ssize)
	self.linkInfo = Struct(self.header, self.vfile, self.header.LinkInfo, self.data)

	self.linkInfoAttr = {}
	self.linkInfoAttr["Link info header size"] = (self.linkInfo.HeaderSize, int)
	self.linkInfo.Flags = FlagsList(self.linkInfo.Flags, LinkInfoFlags)
	self.linkInfoAttr["Link info flags"] = (self.linkInfo.Flags, list)

        if ("VolumeIDAndLocalBasePath", str) in self.linkInfo.Flags:
	   self.vfile.seek(linkInfoStartOffset + self.linkInfo.VolumeIDOffset)
	   sizeMax = self.linkInfo.StructSize - self.vfile.tell() + linkInfoStartOffset 
	   buff = self.vfile.read(sizeMax)

	   VolumeIDStruct = Struct(self.header, self.vfile, self.header.VolumeID, buff)
	   VolumeIDAttr = {}
	
	   try :
  	     VolumeIDAttr["Drive type"] = (DriveTypeMaps[VolumeIDStruct.DriveType], str)
	   except KeyError:
	     pass	
	   VolumeIDAttr["Drive serial number"] = (VolumeIDStruct.DriveSerialNumber, int)
	   if VolumeIDStruct.LabelOffset != 0x14: 
	     pos = buff[VolumeIDStruct.LabelOffset:].find('\x00')
	     if pos != -1:
	       VolumeIDAttr["Volume label"] = (buff[VolumeIDStruct.LabelOffset:VolumeIDStruct.LabelOffset+pos+1], str)
	   else:
	     LabelOffsetUnicode = buff[16:20]
	     VolumeIDAttr["Volume label (Unicode)"]= (UnicodeBuff(buff[LabelOffsetUnicode:]), str)
	
	   if len(VolumeIDAttr):
	     self.linkInfoAttr["Volume ID"] = (VolumeIDAttr, dict)
 
	   self.vfile.seek(linkInfoStartOffset + self.linkInfo.LocalBasePathOffset)
	   sizeMax = self.linkInfo.StructSize - self.vfile.tell() + linkInfoStartOffset
	   buff = self.vfile.read(sizeMax)
	   pos = buff.find('\x00')
	   if pos != -1:
	     self.linkInfoAttr["Local base path"] = (buff[:pos], str)

	   if self.linkInfo.HeaderSize >= 0x24:
	     self.vfile.seek(linkInfoStartOffset + self.linkInfo.LocalBasePathUnicode)
	     sizeMax = self.linkInfo.StructSize - self.vfile.tell() + linkInfoStartOffset
	     buff = self.vfile.read(sizeMax)
	     self.linkInfoAttr["Local base path (Unicode)"] = (UnicodeBuff(buff), str)

	elif ("CommonNetworkRelativeLinkAndPathSuffix", str) in self.linkInfo.Flags:
	   self.vfile.seek(linkInfoStartOffset + self.linkInfo.CommonNetworkRelativeLinkOffset)
	   sizeMax = self.linkInfo.StructSize - self.vfile.tell() + linkInfoStartOffset
	   buff = self.vfile.read(sizeMax)

	   CommonNetworkRelativeLinkStruct = Struct(self.header, self.vfile, self.header.CommonNetworkRelativeLink, buff) 
	   CommonNetworkRelativeLinkAttr = {}			
 
	   CommonNetworkRelativeLinkStruct.LinkFlags = FlagsList(CommonNetworkRelativeLinkStruct.LinkFlags, CommonNetworkRelativeLinkFlags)
	   CommonNetworkRelativeLinkAttr["Link flags"] = (CommonNetworkRelativeLinkStruct.LinkFlags, list) 
	   if ("ValidDevice", str) in CommonNetworkRelativeLinkStruct.LinkFlags:
		#XXX UNTESTED
	     if CommonNetworkRelativeLinkStruct.NetNameOffset > 0x14:
	 	DeviceNameUnicodeOffset = unpack("I", buff[24:28])[0]
		pos = buff[DeviceNameUnicodeOffset:].find('\x00\x00')
		if pos != -1:
		   CommonNetworkRelativeLinkAttr["Deivce name (unicode)"] = (unicode(buff[DeviceNameUnicodeOffset:DeviceNameUnicodeOffset+pos+3].decode('UTF-16')), str)
	     else:
	       pos = buff[CommonNetworkRelativeLinkStruct.DeviceNameOffset:].find('\x00')
	       if pos != -1:
		 CommonNetworkRelativeLinkAttr["Device name"] = (buff[CommonNetworkRelativeLinkStruct.DeviceNameOffset:CommonNetworkRelativeLinkStruct.DeviceNameOffset + pos+1], str)
	
 	   if ("ValidNetType", str) in CommonNetworkRelativeLinkStruct.LinkFlags:
	     if CommonNetworkRelativeLinkStruct.NetNameOffset > 0x14:
	 	NetNameUnicodeOffset = unpack("I", buff[20:24])[0]
		pos = buff[NetNameUnicodeOffset:].find('\x00\x00')
		if pos != -1:
		   CommonNetworkRelativeLinkAttr["Net name (unicode)"] = (unicode(buff[NetNameUnicodeOffset:NetNameUnicodeOffset+pos+3].decode('UTF-16')), str)
	     else:
	       pos = buff[CommonNetworkRelativeLinkStruct.NetNameOffset:].find('\x00')
	       if pos != -1:
		 CommonNetworkRelativeLinkAttr["Net name"] = (buff[CommonNetworkRelativeLinkStruct.NetNameOffset:CommonNetworkRelativeLinkStruct.NetNameOffset + pos+1], str)
	     
	     try:
	      CommonNetworkRelativeLinkAttr["Provider type"] = (NetworkProviderType[CommonNetworkRelativeLinkStruct.NetworkProviderType], str)
	     except KeyError:
	      CommonNetworkRelativeLinkAttr["Provider type"] = (CommonNetworkRelativeLinkStruct.NetworkProviderType, int)

	   self.vfile.seek(linkInfoStartOffset + self.linkInfo.CommonPathSuffixOffset)
	   sizeMax = self.linkInfo.StructSize - self.vfile.tell() + linkInfoStartOffset
	   buff = self.vfile.read(sizeMax)
	   pos = buff.find('\x00')
	   if pos != -1:
	     self.linkInfoAttr["Common path suffix"] = (buff[:pos], str)
	   if self.linkInfo.HeaderSize >= 0x24:
	     pass
	     #print "get unicode common suffix " 
	  
	   if len(CommonNetworkRelativeLinkAttr):
	     self.linkInfoAttr["Common network relative link"] = (CommonNetworkRelativeLinkAttr, dict)

	self.vfile.seek(linkInfoStartOffset + self.linkInfo.StructSize)

  def getLinkTargetIDList(self):
	self.vfile.seek(self.header.ShellLinkHeader.ssize)
	idListSize = unpack("H", self.vfile.read(2))[0]
	count = 0
	idcount = 1 
	self.linkTargetIDList = {} 
	while count < idListSize:
	  ItemIDSize = unpack("H", self.vfile.read(2))[0]
	  if ItemIDSize == 0:
		break
	  IDdata = self.vfile.read(ItemIDSize - 2)
	  IDtype = unpack("B", IDdata[0:1])[0]

	  try :
	    IDtypeName = ItemType[IDtype]
	    isUnicode = ("IsUnicode", str) in self.shellLink.LinkFlags
	    self.linkTargetIDList["ID(" + str(idcount) + ") " + str(IDtypeName)] = ItemTypeConverter[IDtypeName](IDdata, isUnicode)
	  except : #complkete
		pass
	      #err_type, err_value, err_traceback = sys.exc_info()
	      #print traceback.format_exception_only(err_type, err_value)
      	      #print traceback.format_tb(err_traceback)
	      #print "ID LIST TYPE NOT PARSED " + str(hex(IDtype)) + ' ' + str(self.node.absolute()) + ' ' + str(idcount) + ' offset ' + str(hex(self.vfile.tell() - len(IDdata))) + ' ' + str(len(IDdata))
	  idcount += 1 
	  count += ItemIDSize

  def getDataBlock(self):
     dataBlockHeader = Header(DataBlockHeader)
     pos = None 
     while (self.vfile.tell() < self.vfile.node().size() - 4) and (pos != self.vfile.tell()):
	pos = self.vfile.tell()
	data = self.vfile.read(dataBlockHeader.DataBlockStandard.ssize)
	standard = Struct(dataBlockHeader, self.vfile, dataBlockHeader.DataBlockStandard, data)
	try:
	  self.vfile.seek(pos)
	  dataBlockType = ExtraDataBlockMaps[standard.BlockSignature]
	  data = self.vfile.read(standard.BlockSize)
	  try:	
	    setattr(self, dataBlockType, Struct(dataBlockHeader, self.vfile, getattr(dataBlockHeader, dataBlockType), data))
	    if dataBlockType == 'ConsoleDataBlock':
		self.ConsoleDataBlock.FillAttributes = FlagsList(self.ConsoleDataBlock.FillAttributes, FillAttributesFlags)
		self.ConsoleDataBlock.PopupFillAttributes = FlagsList(self.ConsoleDataBlock.PopupFillAttributes, FillAttributesFlags)
		try : 
		  self.ConsoleDataBlock.FontFamily = FontFamily[self.ConsoleDataBlock.FontFamily]
	        except KeyError:
		  pass
		self.ConsoleDataBlock.FaceName = UnicodeBuff(self.ConsoleDataBlock.FaceName)

	    if dataBlockType == 'TrackerDataBlock':
		self.TrackerDataBlock.DroidVolume = UUID(self.TrackerDataBlock.DroidVolume)
		self.TrackerDataBlock.DroidFile = UUID(self.TrackerDataBlock.DroidFile)
		self.TrackerDataBlock.DroidBirthVolume = UUID(self.TrackerDataBlock.DroidBirthVolume)
		self.TrackerDataBlock.DroidBirthFile = UUID(self.TrackerDataBlock.DroidBirthFile)
	    #elif windowsvsita...
	    #elif shindataBLock

            elif dataBlockType == 'EnvironmentVariableDataBlock':
       	      self.EnvironmentVariableDataBlock.TargetUnicode =  UnicodeBuff(self.EnvironmentVariableDataBlock.TargetUnicode)
	    elif dataBlockType == 'IconEnvironmentDataBlock':
       	      self.IconEnvironmentDataBlock.Environment.TargetUnicode = UnicodeBuff(self.IconEnvironmentDataBlock.Environment.TargetUnicode)
	    elif dataBlockType == 'DarwinDataBlock':
	      self.DarwinDataBlock.DataUnicode = UnicodeBuff(self.DarwinDataBlock.DataUnicode)
	    elif dataBlockType == 'KnownFolderDataBlock':
	      self.KnownFolderDataBlock.ID = UUID(self.KnownFolderDataBlock.ID)
	    elif dataBlockType == 'PropertyStoreDataBlock':
	      serializedPropertyHeader = Header(SerializedPropertyHeader)
	      self.PropertyStoreSerializedAttr = {}
	      while len(data) >= 32: 
	        self.PropertyStoreDataBlock.Property.FormatID = UUID(self.PropertyStoreDataBlock.Property.FormatID)
	        if self.PropertyStoreDataBlock.Property.StorageSize and len(data) > 40:
	          if self.PropertyStoreDataBlock.Property.FormatID != "D5CDD505-2E9C-101B-9397-08002B2CF9AE":
		    serializedPropertyData = data[32:]
		    IntegerName = Struct(serializedPropertyHeader, self.vfile, serializedPropertyHeader.IntegerName, serializedPropertyData)
		    try:
		      value = 'Undef Type'	 
		      value = PropertyType[IntegerName.TypedValue.Type]
   		      value = PropertyTypeConverter[value](serializedPropertyData[13:])
		    except KeyError:
		      pass
	            self.PropertyStoreSerializedAttr[str(IntegerName.Id)] = (value, str)
		    data = data[self.PropertyStoreDataBlock.Property.StorageSize:]
		    if len(data) >= 32: 
	              setattr(self, dataBlockType, Struct(dataBlockHeader, self.vfile, getattr(dataBlockHeader, dataBlockType), data))
		    else:
		      break
	          else:
		    #StringType
		    break
                else:
		  break

	  except AttributeError, e:
	    break #avoid infinite loop, possibly skip decodable data block
	
	except KeyError, e:
	  if (dataBlockHeader.DataBlockStandard.ssize == 0) or (standard.BlockSize == 0):
	    break


  def readStringData(self, dataName):
     if (dataName, str) in self.shellLink.LinkFlags:
	size = unpack("H", self.vfile.read(2))[0]
	if size:
	 Name = dataName.replace('Has', '') 
	 if ("IsUnicode", str) in self.shellLink.LinkFlags:
	   data = unicode(self.vfile.read(size*2).decode('UTF-16'))
	 else:
	   data = self.vfile.read(size)
	 setattr(self, Name, data) 
	 if Name == "RelativePath":
	   n = VFS.Get().GetNode(self.node.parent().absolute() + '/' + data.encode('UTF-8').replace('\\', '/')) 
	   if n:
	     #This create a subnode with a link
	     #vl = VLink(n, self.node)
	     #vl.thisown = False
	     setattr(self, "RelativePathLink", n)

  def attributesMap(self):
   try:
     return ResolveAttributesMap(self, LnkAttributesMap)	
   except:
     pass

class LNKHandler(AttributesHandler, ModuleProcessusHandler):
  def __init__(self):
    AttributesHandler.__init__(self, "lnk")
    ModuleProcessusHandler.__init__(self, "lnk")
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

class LNK(Script):
  def __init__(self):
   Script.__init__(self, "lnk")
   self.handler = LNKHandler()

  def start(self, args):
    try:
      node = args['file'].value()
      p = LNKParser(node)
      arg = p.attributesMap()
      self.handler.setAttributes(node, arg)
      node.registerAttributes(self.handler)
    except (KeyError, Exception):
      pass

class lnk(Module): 
  """This module generates metadata for lnk files as attributes"""
  def __init__(self):
    Module.__init__(self, "lnk", LNK)
    self.conf.addArgument({"name": "file",
                           "description": "Extract metadata from this file",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addConstant({"name": "mime-type", 
 	                   "type": typeId.String,
 	                   "description": "compatible extension",
 	                   "values": ["windows/shortcut"]})
    self.flags = ["single"] 
    self.tags = "Metadata"
    self.icon = ":lnk"
