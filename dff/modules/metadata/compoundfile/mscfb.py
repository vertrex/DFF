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

from struct import unpack

from dff.api.vfs.libvfs import Node
from dff.api.types.libtypes import Variant, VMap, VList, Argument, typeId, MS64DateTime 

from dff.modules.structparser import Struct, Header, ResolveAttributesMap, AttributesVMap
from dff.modules.lnk.lnkitem import UUID

OLEHeader = ({ "info" : { "os":"None", "arch":"None", "name":"OLE2"},
		"descr" : {
			     "CompoundDocumentHeader" : ((512),
			     {
			       "OleSignature" : (8, 0),
			       "CLSID" : (16, 8),
			       "MinorVersion" : (2, 24),
			       "MajorVersion" : (2, 26),
			       "ByteOrder" : (2, 28),
			       "SectorShift" : (2, 30),
			       "MiniSectorShift" : (2, 32),
			       "Reserved1"	:  (6, 34),
			       "NumberOfDirSect": (4, 40),
			       "NumberOfFatSect": (4, 44),
			       "FirstDirSectLocation"	: (4, 48),
			       "TransactionSignNumber" : (4, 52),
			       "MiniStreamCutoffSize" : (4, 56),
			       "FirstMiniFatSectLocation" : (4, 60),
			       "NumberOfMiniFatSectors" : (4, 64), 
			       "FirstDIFATSectLocation" : (4, 68),	
			       "NumberOfDIFATSector" : (4, 72),
			     }),
			     "DirectoryEntry" : ((128),
			     {
			       "objectName" : (64, 0),
			       "nameLen" : (2, 64),
			       "objectType" : (1, 66),
			       "colorFlag" : (1, 67),	
			       "leftSiblingID" : (4, 68),
			       "rightSiblingID" : (4, 72),
			       "childID" : (4, 76),
			       "CLSID" : (16, 80),
			       "stateBits" : (4, 96),
			       "creationTime" : (8, 100),
			       "modifiedTime" : (8, 108),
			       "startingSectorLocation" : (4, 116),
			       "streamSize" : (8, 120),
			     }),
			}
		})


class DIFAT(object):
  def __init__(self, node, numberOfSector, firstSectLocation, sectorSize):
     self.numberSector = numberOfSector
     self.firstSectLocation = firstSectLocation
     self.sectorSize = sectorSize
     self.node = node

     vfile = self.node.open()
     try :
       vfile.seek(76)    
       self.table = vfile.read(436)
       sector = self.firstSectLocation
       previousSector = None
       while sector < 0xFFFFFFFA:
        if previousSector == sector: 
          raise Exception("Error infinite loop in DIFAT")
	if vfile.seek(512 + (sector * self.sectorSize)) != 512 + (sector * self.sectorSize):
          raise Exception("Error can't seek in DIFAT")
        self.table += vfile.read(self.sectorSize)
        previousSector = sector
 	sector = self.readSector(sector)
     except :
	vfile.close()
	raise 
     vfile.close()

  def readSector(self, fatsector):
     vfile = self.node.open()
     try :
       currentfattableid = fatsector / (self.sectorSize / 4)
       currentfatsector = unpack('I', self.table[currentfattableid*4:(currentfattableid*4)+4])[0]
       if vfile.seek(512 + (currentfatsector * self.sectorSize)) != 512 + (currentfatsector * self.sectorSize):
         raise Exception("DIFAT readsector error can't seek")
       fattable = unpack((self.sectorSize/4)*'I', vfile.read(self.sectorSize))
     except :
	error()
	vfile.close()
	raise	
     vfile.close()
     return fattable[fatsector - ((self.sectorSize/4)* currentfattableid)]

class FAT(object):
   def __init__(self, node, difat, numberOfSector, sectorSize):
     self.difat = difat
     self.node = node
     self.numberOfSector = numberOfSector
     self.sectorSize = sectorSize

     vfile = self.node.open()
     try:
       self.table = "" 
       for index in range(0, self.numberOfSector):
        sector = unpack('I', self.difat.table[index*4:(index*4)+4])[0]
        if vfile.seek(512 + (sector * self.sectorSize)) != (512 + (sector * self.sectorSize)):
          raise Exception("Compound FAT can't seek")
        data = vfile.read(self.sectorSize)
        self.table += data
     except :
	pass #Sometime file try to read at an invalid sector
     vfile.close()  

   def readSector(self, sector):
      parsedIndex = set() 	
      data = ""
      vfile = self.node.open()
      try: 
        while (sector < 0xFFFFFFFA) and (sector not in parsedIndex):
	  parsedIndex.add(sector) 
          if vfile.seek(512 + ((sector) * self.sectorSize)) != (512 + ((sector) * self.sectorSize)):
            raise Exception("Compound FAT readSector can't seek")
          data += vfile.read(self.sectorSize)
	  sector = unpack('I', self.table[sector*4:(sector*4)+4])[0]
      except :
	vfile.close()
	raise	
      vfile.close()
      return data

   def offsetsSector(self, sector):
      parsedIndex = set()
      offsets = []
      while (sector < 0xFFFFFFFA) and (sector not in parsedIndex):
	parsedIndex.add(sector)
        pos = 512 + ((sector) * self.sectorSize)
        off = (pos, self.sectorSize, self.node)
	offsets.append(off)
        sector = unpack('I', self.table[sector*4:(sector*4)+4])[0]
      return offsets

class MiniFAT(object):
  def __init__(self, fat, firstSector, numberOfSector, cutoffSize, sectorSize):
     self.fat = fat
     self.numberOfSector = numberOfSector
     self.sectorSize = sectorSize
     self.cutoffSize = cutoffSize
     self.table = self.fat.readSector(firstSector)
     self.node = None

  def setRootStorageObject(self, root):
     self.node = root 

  def offsetsRoot(self, dataSector):
     return self.fat.offsetsSector(dataSector)

  def offsetsSector(self, index):
     parsedIndex = set()
     offsets = []

     while (index < 0xFFFFFFFA) and (index not in parsedIndex):
	parsedIndex.add(index)
        offsets.append(((index * 64), 64, self.node))
        index = unpack('I', self.table[index*4:(index*4)+4])[0]
     return offsets

class CompoundDocumentHeader(Struct):
  CompoundDocumentAttributesMap = {
      "Minor version" : ("MinorVersion" ,int),
      "Major version" : ("MajorVersion" ,int),
      "Byte order" : ("ByteOrder" ,int),
      "Sector shift" : ("SectorShift" ,int),
      "MiniSectorShift" : ("MiniSectorShift" ,int),
      "Number of directory sector" : ("NumberOfDirSect" ,int),
      "Number of FAT sector" : ("NumberOfFatSect" ,int),
      "First directory sector location" : ("FirstDirSectLocation" ,int),
      "Mini stream cutoff size" : ("MiniStreamCutoffSize" ,int),
      "First mini fat sector location" : ("FirstMiniFatSectLocation" ,int),
      "Number of mini fat sectors" : ("NumberOfMiniFatSectors" ,int),
      "First DIFAT sector location" : ("FirstDIFATSectLocation" ,int),
      "Number of DIFAT sector" : ("NumberOfDIFATSector", int),
      }
  OLEHeaderSignature = unpack('Q', "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")[0]
  def __init__(self, node, mfsobj):
     self.header = Header(OLEHeader)
     self.node = node
     self.mfsobj = mfsobj
     self.vfile = node.open()
     try :
       self.vfile.seek(0)
       data = self.vfile.read(self.header.CompoundDocumentHeader.ssize)
     except :
	self.vfile.close()
	raise	
     self.vfile.close()
     Struct.__init__(self, self.header, None, self.header.CompoundDocumentHeader, data)
     if self.OLEHeaderSignature != self.OleSignature:
        raise Exception('OLE Header is not valid.')
     if self.SectorShift == 0x9:
	self.SectorSize = 512 
     elif self.SectorShift == 0xc:
	self.SectorSize = 4096
     self.CLSID = UUID(self.CLSID)

     self.entries = []

  def parseDocument(self, register):
     difat = DIFAT(self.node, self.NumberOfDIFATSector, self.FirstDIFATSectLocation, self.SectorSize)
     fat = FAT(self.node, difat, self.NumberOfFatSect, self.SectorSize)
     minifat = MiniFAT(fat, self.FirstMiniFatSectLocation, self.NumberOfMiniFatSectors, self.MiniStreamCutoffSize, self.SectorSize)
     self.entries = DirectoryEntries(fat, minifat, self.FirstDirSectLocation, self.header, self.node, self.mfsobj, register)
     
  def streams(self):
     entries = self.entries.entries()
     sortedEntries = []
     for entry in entries:
       if entry.objectName == "DocumentSummaryInformation": #special case it will be parsed first so we could used code page to decode properly other entry
         sortedEntries.insert(0, entry)
       else:
         sortedEntries.append(entry) 
     return sortedEntries 

  def _attributes(self):
     try:
        return AttributesVMap(ResolveAttributesMap(self, self.CompoundDocumentAttributesMap))
     except:
        pass

class DirectoryEntries(object):
  def __init__(self, fat, minifat, sectorLocation, header, parent, mfsobj, register = True):
     data = fat.readSector(sectorLocation)
     self.__entries = []
     self.__addedEntriesID = []
     size = 0
     root = None
     node = parent
     while size < len(data):
      try:
	entry = DirectoryEntry(header, data[size:size+128], fat, minifat, node, mfsobj)
        size += 128
        if len(entry.objectName) == 0 or entry.objectType == 'TypeUnknown':
	  continue 
        if entry.objectType == 'RootStorageObject' and root == None:
	  root = entry
          self.__entries.append(entry)
        elif entry.objectType != 'RootStorageObject':
          self.__entries.append(entry)
      except :
        self.__entries.append(None)
	size += 128
	error()	
     if root: 
       self.parseChild(root)
       self.__addedEntriesID.append(0)
     orphaned = self.parseOrphan(root, mfsobj)
     if register and root:
       mfsobj.registerTree(parent, root) 
     elif register and orphaned:
       mfsobj.registerTree(parent, orphaned)

  def addChild(self, root, entry, entryID):
     if entryID not in self.__addedEntriesID:
       root.addChild(entry)
       self.__addedEntriesID.append(entryID)

  def parseOrphan(self, root, mfsobj):
     orphaned = None
     if len(self.__entries) != len(self.__addedEntriesID):
       orphaned = Node('Orphaned', 0, root, mfsobj)
       orphaned.__disown__()
       for eid in xrange(0, len(self.__entries)):
	  if eid not in self.__addedEntriesID:
	    try:
              if self.__entries[eid]:
  	        orphaned.addChild(self.__entries[eid])	
            except KeyError:
	       pass
     return orphaned

  def parseChild(self, root):
     if root.childID != 0xffffffff:
       try:
         entry = self.__entries[root.childID]
         self.addChild(root, entry, root.childID)
         self.parseLeft(root, entry)
         self.parseRight(root, entry)
         self.parseChild(entry)
       except KeyError:
	 pass

  def parseLeft(self, root, entry):
     if entry.leftSiblingID != 0xffffffff:
       try:
         leftSibling = self.__entries[entry.leftSiblingID]
         self.addChild(root, leftSibling, entry.leftSiblingID)
         self.parseLeft(root, leftSibling)
         self.parseRight(root, leftSibling)
         if leftSibling.childID != 0xffffffff:
	   self.parseChild(leftSibling)
       except KeyError:
	 pass

  def parseRight(self, root, entry):
     if entry.rightSiblingID != 0xffffffff:
       try:
         rightSibling = self.__entries[entry.rightSiblingID]
         self.addChild(root, rightSibling, entry.rightSiblingID)
         self.parseRight(root, rightSibling)
         self.parseLeft(root, rightSibling)
         if rightSibling.childID != 0xffffffff:
	   self.parseChild(rightSibling)
       except KeyError:
	 pass

  def entries(self):
     return self.__entries
 

#invalidNameCounter = 0

class DirectoryEntry(Node, Struct):
  Type = {
   	   0x0 : "TypeUnknown",
	   0x1 : "StorageObject",
           0x2 : "StreamObject",
           0x5 : "RootStorageObject"
   	 }
  AttributesMap = {
   "Object type" : ("objectType", str),
   "CLSID" : ("CLSID", str),
   "Creation time" : ("creationTime", MS64DateTime),
   "Modified time" : ("modifiedTime", MS64DateTime),
   "Starting sector" : ("startingSectorLocation", int),
   "Child ID" : ("childID", int),
   "Right Sibling ID" : ("rightSiblingID", int),
   "Left Sibling ID" : ("leftSiblingID", int),
  }
  def __init__(self, header, data, fat, minifat, parent, mfsobj):
     self.extraAttr = None
     Struct.__init__(self,header, None, header.DirectoryEntry, data)
     self.fat = fat
     self.minifat = minifat
     invalidNameCounter = 1
     try:
     #if self.objectName[1] == "\x00": #Some compound file like MSI as invalid name this is an ugly way to test
       self.objectName = unicode(self.objectName[:self.nameLen - 2], 'UTF-16').encode('UTF-8')
     except:
     #else:
       #global invalidNameCounter
       #invalidNameCounter += 1
       self.objectName = str("Unknown-" + str(invalidNameCounter)).encode('UTF-8')
     try:
       self.objectType = self.Type[ord(self.objectType)]
     except KeyError:
       self.objectType = self.Type[0x0]

     if len(self.objectName) == 0 or self.objectType == 'TypeUnknown':
	return
     self.CLSID = UUID(self.CLSID)

     if len(self.objectName) and mfsobj:
       realSize = self.offsetsSize()
       if self.streamSize > realSize:
	 streamSize = realSize
       else:
	 streamSize = self.streamSize 
       if self.objectName[0] <= "\x05":
         self.objectName = self.objectName[1:]
       Node.__init__(self, self.objectName, streamSize, None, mfsobj)
       self.__disown__()
     if self.objectType == "RootStorageObject":
       self.minifat.setRootStorageObject(self)

  def offsets(self):
    offsets = None
    try:
      if self.objectType == "StreamObject" and self.streamSize >= self.minifat.cutoffSize:
       offsets = self.fat.offsetsSector(self.startingSectorLocation)
      elif self.objectType == "StreamObject" and self.streamSize < self.minifat.cutoffSize:
	offsets = self.minifat.offsetsSector(self.startingSectorLocation)
      elif self.objectType == "RootStorageObject":
	offsets = self.minifat.offsetsRoot(self.startingSectorLocation)
    except:
	pass
	#error()
    return offsets

  def offsetsSize(self):
     offsets = self.offsets()
     sizes = 0
     if offsets:
       for offset, size, node in offsets:
  	  sizes += size
     return sizes

  def fileMapping(self, fm):
     offsets = self.offsets()
     if offsets:
       curoffset = 0
       for offset, size, node in offsets:
         if curoffset + size > self.streamSize:
	   size = self.streamSize - curoffset
         fm.push(curoffset, size, node, offset)
         curoffset += size
         if curoffset >= self.streamSize:
	   break

  def setExtraAttributes(self, extraAttr):
     self.extraAttr = extraAttr

  def _attributes(self):
    try:
      attr = AttributesVMap(ResolveAttributesMap(self, self.AttributesMap))
      if self.extraAttr:
	(name, vmap) = self.extraAttr
	attr[name] = vmap
      return attr
    except :
      attr = VMap()
      return attr
