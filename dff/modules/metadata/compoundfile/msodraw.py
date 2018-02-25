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

from dff.api.types.libtypes import VMap
from dff.api.vfs.libvfs import Node

class OfficeArtDggContainer(object):
  def __init__(self, vfile, delay = None):
     self.rh = OfficeArtRecordHeader(vfile)
     self.drawingGroup = OfficeArtFDGGBlock(vfile)
     self.blipStore = OfficeArtBStoreContainer(vfile, delay)

#MS-ODRAW page 49 
class OfficeArtFDGGBlock(object):
  def __init__(self, vfile):
     self.rh = OfficeArtRecordHeader(vfile)
     vfile.seek(self.rh.recLen, 1)


class OfficeArtBStoreDelay(object):
  def __init__(self, vfile):
    self.blips = []
    rgfb = OfficeArtRecordHeader(vfile)
    while vfile.tell() < vfile.node().size():
      if rgfb.recType == 0xF007:
        oafbse = OfficeArtFBSE(vfile)
        if oafbse.blip.offset != None:
     	  self.blips.append(oafbse.blip)
      elif rgfb.recType >= 0xF018 and rgfb.recType <= 0xF117: 
         blip = OfficeArtBlip(rgfb, vfile.tell())
         self.blips.append(blip)
      try:
        if rgfb.recLen == 0:
	  break
        vfile.seek(rgfb.recLen , 1)
        rgfb = OfficeArtRecordHeader(vfile)
      except :
  	break	

class OfficeArtBStoreContainer(object):
  def __init__(self, vfile, delay = None):
     self.blips = []
     self.rh = OfficeArtRecordHeader(vfile)
     rgfb = OfficeArtRecordHeader(vfile)
     fpos = self.rh.recLen + vfile.tell()

     while vfile.tell() < fpos: 
       if rgfb.recType == 0xF007:
         oafbse = OfficeArtFBSE(vfile, delay)
	 if oafbse.blip.offset != None:
   	   self.blips.append(oafbse.blip)
       elif rgfb.recType >= 0xF018 and rgfb.recType <= 0xF117: 
         vfile.seek(rgfb.recLen, 1) 
         #blip = OfficeArtBlip(rgfb, vfile.tell())
         #self.blips.append(blip)
       else:
	 if rgfb.recLen != 0:
  	   vfile.seek(rgfb.recLen , 1)
	 else:
	   break
       rgfb = OfficeArtRecordHeader(vfile)
 
#MS_ODRAW page 55
class OfficeArtInlineSpContainer(object):
  def __init__(self, vfile):
     self.shape = OfficeArtSpContainer(vfile)
     vfile.seek(self.shape.rh.recLen ,1)
     self.rgfb = OfficeArtRecordHeader(vfile) 
     self.blip = None
#loop ? like BSToreContainer ?
     if self.rgfb.recType == 0xF007:
	oafbse = OfficeArtFBSE(vfile)
        self.blip = oafbse.blip
     elif self.rgfb.recType >= 0xF018 and self.rgfb.recType <= 0xF117:
	self.blip = OfficeArtBlip(self.rgfb, vfile.tell()) 
     else:
	if self.rgfb.recLen != 0:
	  vfile.seek(self.rgfb.recLen, 1)
        

class OfficeArtFBSE(object):
  def __init__(self, vfile, delay = None):
     self.blip = None
     self.rh = OfficeArtRecordHeader(vfile)
     vfile.seek(12, 1)
     self.size, self.cRef, self.foDelay, u1, cbName, u2, u3 = unpack('IIIBBBB', vfile.read(16))
     if (cbName > 0) and (cbName < 0xff):
       self.nameData = vfile.read(cbName)
     if delay == None:
       self.bliprh = OfficeArtRecordHeader(vfile)
       self.blip = OfficeArtBlip(self.bliprh, vfile.tell())
     else:
       fdelay = delay.open()
       try:
         if fdelay.seek(self.foDelay) != self.foDelay:
           raise Exception("Can't seek to foDelay in OfficeArtFBSE")
         self.bliprh = OfficeArtRecordHeader(fdelay)
         self.blip = OfficeArtBlip(self.bliprh, fdelay.tell())	
       except :
	 fdelay.close()
	 raise
       fdelay.close() 
 
class OfficeArtBlip(object):
  Type = {
    0xF01A : "EMF",
    0xF01B : "WMF",
    0xF01C : "PICT", 
    0xF01D : "JPEG",
    0xF01E : "PNG",
    0xF01F : "DIB",
    0xF029 : "TIFF",
    0xF02A : "JPEG",
  }
  TypeOffset = {
    "JPEG" : [(0x46A, 17), (0x6E2, 17), (0x46B, 33), (0x6E3, 33)] ,
    "PNG"  : [(0x6E0, 17), (0x6E1, 33)],
    "EMF"  : [(0x3D4, 50), (0x3D5, 66)],
    "WMF"  : [(0x216, 50), (0x217, 66)],
    "PICT" : [(0x542, 50), (0x543, 66)],
    "DIB"  : [(0x7A8, 17), (0x7A9, 33)],
    "TIFF" : [(0x6E4, 17), (0x6E5, 33)],
  }
  def __init__(self, rh, voffset):
     self.rh = rh
     self.offset = None
     self.size = None
     try :
       offsets = self.TypeOffset[self.Type[self.rh.recType]]
     except KeyError, e:
       return  

     for (instance, shift) in offsets:
        if self.rh.recInstance == instance:
	  self.offset = voffset + shift
          self.size = self.rh.recLen - shift
	  break

class OfficeArtSpContainer(object):
  ['fGroup', 'fChild', 'fPatriarch', 'fDeleted', 'fOleShape', 'fHaveMaster', 'fFlipH', 'fFlipV', 'fConnector', 'fHaveAnchor',
   'fBackground', 'fHaveSpt']
  def __init__(self, vfile):
     self.rh = OfficeArtRecordHeader(vfile)
     #offset = vfile.tell()
     #vfile.seek(24) #self.shapeGroup
     #self.shapeProp = OfficeArtFSP(vfile)
     #vfile.seek(offset)
     #self.shapeProp = 
     #self.deletedShape = 
     #self.shaprePrimaryOptions1 = 
     #self.shapeSecondaryOptions1 = 
     #self.shapeTertiaryOptions1 = 
     #self.childAnchor = 
     #self.clientAnchor = 
     #self.clientData = 
     #self.clientTextbox
     #self.shapeSecondaryOptions2 = 
     #self.shapeSecondaryOptions2 = 
     #self.shapeTertiaryOptions2 = 
    
class OfficeArtFSP(object):
  def __init__(self, vfile):
     self.rh = OfficeArtRecordHeader(vfile)
     spid = unpack('HH', vfile.read(4))[0]
     spid = bin(spid).replace('0b', '')
 
class OfficeArtRecordHeader(object):
  def __init__(self, vfile):
      recVerInstance, self.recType, self.recLen = unpack('<HHI', vfile.read(8))
      self.recVer = recVerInstance  & 0x000f
      self.recInstance = recVerInstance >> 4

class PictureNode(Node):
  def __init__(self, parent, offset, size, count):
     self.parent = parent
     self.offset = offset
     Node.__init__(self, 'Picture' + str(count), size, self.parent, self.parent.fsobj())
     self.__disown__()

  def fileMapping(self, fm):
     fm.push(0, self.size(), self.parent, self.offset)

  def _attributes(self):
     v = VMap()
     return v 


