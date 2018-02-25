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

import sys, traceback
from struct import unpack

from dff.api.vfs.libvfs import Node
from dff.api.types.libtypes import Variant, VMap, VList, Argument, typeId

from dff.modules.structparser import Struct, Header, ResolveAttributesMap, AttributesVMap

from dff.modules.compoundfile.msdocheader import MSDocHeader
from dff.modules.compoundfile.msodraw import OfficeArtInlineSpContainer, OfficeArtDggContainer, PictureNode 

class WordDocument(Struct):
  cbRgFcLcbSizeFibVersion  = { 
     744 : 4,
     864 : 3,
    1088 : 2,
    1312 : 1,
    1464 : 0,
  }
  VersionList = ["FibRgFcLcb2007", "FibRgFcLcb2003", "FibRgFcLcb2002", "FibRgFcLcb2000", "FibRgFcLcb97"]
  BitField1 = ["fDot", "fGlsy", "fComplex", "fHasPic", "cQuickSaves", "fEncrypted", "fWhichTblStm", "fReadOnlyRecommended",
  "fWriteReservation", "fExtChar", "fLoadOverride", "fFatEast", "fObfuscated"]
  def __init__(self, node):
    header = Header(MSDocHeader)
    self.node = node
    vfile = self.node.open()
    try :
      data = vfile.read(154)
      Struct.__init__(self, header, None, header.Fib, data)
      if self.FibBase.wIdent != 0xA5EC:
	vfile.close()
        raise RuntimeError("Header wIdent is invalid on stream " + str(self.node.absolute()))
      self.readFib(vfile, header)
      self.readFibRgCsNew(vfile, header)
    except :
	vfile.close()
	raise	
    vfile.close()

    self.initBitField() 
    self.setTableAndDataStream()

  def initBitField(self):
     b = bin(self.FibBase.bitfield1).replace('0b', '')[::-1]
     b += (16 - len(b))*'0'
     for i in xrange(0, 4):
       setattr(self.FibBase, self.BitField1[i], int(b[i]))
     setattr(self.FibBase, self.BitField1[4], int(b[4:8], 2))
     for i in xrange(8, 16):
       setattr(self.FibBase, self.BitField1[i-3], int(b[i]))

#find nFib version according to cbRgFcLcb as nFib is always set a '97'
#then loop and set each Fib structure to self to ease access
  def readFib(self, vfile, header):
    try:
      fibRgFcLcbVersion = self.VersionList[self.cbRgFcLcbSizeFibVersion[self.cbRgFcLcb*8]] 
    except KeyError:
      raise Exception("No valid nFib/version")

    fibRgFcLcbVersionHeader = getattr(header, fibRgFcLcbVersion)
    data = vfile.read(fibRgFcLcbVersionHeader.ssize)
    currentc = Struct(header, None, fibRgFcLcbVersionHeader, data)
    setattr(self, fibRgFcLcbVersion, currentc)

    #After have reading so much MS header I started to write code as cryptic as them
    for x in range(self.cbRgFcLcbSizeFibVersion[self.cbRgFcLcb*8] + 1, 5):
       currentc = getattr(currentc, self.VersionList[x])
       setattr(self, self.VersionList[x], currentc)

  def readFibRgCsNew(self, vfile, header):
    #getting right nFib
    self.cswNew = unpack('H', vfile.read(2))[0]
    self.FibRgCswNew = None
    data = vfile.read(self.cswNew * 2)
    if self.cswNew == 0:
      self.nFib = self.FibBase.nFib
    elif self.cswNew * 2 == 4: 
       self.FibRgCswNew = Struct(header, None, header.FibRgCswNewData2000, data)
       self.nFib = self.FibRgCswNew.nFibNew
    elif self.cswNew * 2 == 10:
       self.FibRgCswNew = Struct(header, None, header.FibRgCswNewData2007, data)
       self.nFib = self.FibRgCswNew.nFibNew
 
  def setTableAndDataStream(self):
    if self.FibBase.fWhichTblStm == 0:
      tableName = '0Table'
    else:
      tableName = '1Table'
    children = self.node.parent().children() 
    for node in children:
       if node.name() == tableName:
         self.tableStream = node
       if node.name() == 'Data':
	 self.dataStream = node 

  #wAlgo retrieve text from MS-DOC this give us the PlPcd /acp /aPcd table who permit to find text offset
  def text(self):
      #print hex(self.FibBase.fcMin) #start of text block / non-offical
      #print hex(self.FibBase.fcMac)  # end of last text block
      offset = self.FibRgFcLcb97.fcClx #offset of a Clx in the table stream
      size = self.FibRgFcLcb97.lcbClx
      pcdt = Pcdt(self.tableStream, offset, size) #pLCpCD
      #now get the text from main document who CP is always 0
      maindocument = (self.fibRgLw97.ccpText, pcdt.cpOffset(0)) 
      #footnote = (self.fibRgLw97.ccpFtn, pcdt.cpOffset(1)) 
      #headers = (self.fibRgLw97.ccpHdd, pcdt.cpOffset(2))
      #comments = (self.fibRgLw97.ccpAtn, pcdt.cpOffset(3))
      #endnotes = (self.fibRgLw97.ccpEdn, pcdt.cpOffset(4))
      #textboxes = (self.fibRgLw97.ccpTxbx, pcdt.cpOffset(5))
      #headertextboxes = (self.fibRgLw97.ccpHdrTxbx, pcdt.cpOffset(6))
      offsets = [maindocument] #, footnote, headers, comments, endnotes, textboxes, headertextboxes] #, last
      return offsets 

  def pictures(self):
      pictures = []
      try:
        pictures += self.dataStreamPictures() 
      except:
	pass        
      try:
        pictures += self.worddocumentPictures()
      except :
	pass
      return pictures
  
  def worddocumentPictures(self):
     pictures = []
     if self.FibRgFcLcb97.lcbDggInfo == 0:
       return pictures
     offset = self.FibRgFcLcb97.fcDggInfo
     size = self.FibRgFcLcb97.lcbDggInfo
     oac = OfficeArtContent(self.tableStream, offset, size, self.node)
     for blip in oac.pictures.blipStore.blips:
	pictures.append((blip.offset, blip.size, self.node))
     return pictures
 
  def dataStreamPictures(self):
      pictures = []
      offset = self.FibRgFcLcb97.fcPlcfBteChpx
      size = self.FibRgFcLcb97.lcbPlcfBteChpx
      plcBteChpx = PlcBteChpx(self.tableStream, offset, size)
      stChpxFKPs = ChpxFKPs(plcBteChpx, self.node)
      worddocument = self.node.open()
      try:
       for chpxFKPidx in xrange(0, len(stChpxFKPs.CHPXFKP)):
         for chpx in stChpxFKPs.CHPXFKP[chpxFKPidx].Chpxs:
	   for grpprl in chpx.grpprl:
	     if grpprl.sprm.sgc == 2 and grpprl.sprm.ispmd == 3 and grpprl.sprm.fSpec == 1:
 	         offset = unpack('I', grpprl.operand)[0]
		 chpxfkp = stChpxFKPs.CHPXFKP[chpxFKPidx]
		 runstart = chpxfkp.RGFCs[chpx.rfc] 
		 runend = chpxfkp.RGFCs[chpx.rfc + 1]
		 if worddocument.seek(runstart) != runstart:
                   raise Exception("Can't seek to data stream")
		 run = worddocument.read(runend +1 -runstart)
		 if run.find('\x01') != -1:
		   data = 0
		   for grpprldata in chpx.grpprl:	
		      if grpprldata.sprm.sgc == 2 and grpprldata.sprm.ispmd == 6:
			data = unpack('B', grpprldata.operand)[0]
			break	
		   if data == 0:
		     try:
		       paoad = PICFAndOfficeArtData(self.dataStream, offset)
		       if paoad.picture.blip:
		         pictures.append((paoad.picture.blip.offset, paoad.picture.blip.size, self.dataStream))
		     except :
			pass
      except :
	pass
      worddocument.close()
      return pictures

  def createPictureNodes(self):
     offsets = self.pictures()
     count = 1
     for offset, size, node in offsets:
        PictureNode(node, offset, size, count)
        count += 1

  def createTextNodes(self):
      offsets = self.text()
      ssize = 0
      for size, off in offsets:
        ssize += size
      WordTextNode(self.node, offsets, ssize)
 
class WordTextNode(Node):
  def __init__(self, worddocument, offsets, size):
     self.offsets = offsets
     self.worddocument = worddocument
#nom du document
     Node.__init__(self, 'Text', size, self.worddocument, self.worddocument.fsobj())
     self.__disown__()

  def fileMapping(self, fm):
     cursize = 0
     for size, offset in self.offsets:
       if size:
         fm.push(cursize, size, self.worddocument, offset)
         cursize += size

  def _attributes(self):
     v = VMap()
     return v


#MS-DOC page 420
class PICFAndOfficeArtData(object):
  def __init__(self, datastream, offset):
     vfile = datastream.open()
     try:
       if vfile.seek(offset) != offset:
         raise Exception("Can't seek in PICAndOfficeArtData")
       data = vfile.read(68)
       picf = PICF(data)	
       if picf.mm == 0x66:
	 nameSize =  unpack('B', vfile.read(1))[0]
	 self.name = vfile.read(nameSize)
	 self.name += '\x00'
       else:
         self.name = None 
       self.picture = OfficeArtInlineSpContainer(vfile) 
     except :
	vfile.close()
	raise
     vfile.close()       


#MS-DOC Page 404
class OfficeArtContent(object):
  def __init__(self, tablestream, offset, size, delay = None):
     vfile = tablestream.open()
     try:
       if vfile.seek(offset) != offset:
         raise Exception("Can't seek to OfficeArtContent")
       self.pictures = OfficeArtDggContainer(vfile, delay)
     except :
	vfile.close()
	raise
     vfile.close()
class PICF(object):
  mmType = {
    0x64 : "MM_SHAPE",
    0x66 : "MM_SHAPEFILE"
  }
  def __init__(self, data):
     self.lcb = unpack('I', data[0:4])[0]
     self.cbHeader = unpack('H', data[4:6])[0]
     self.mm = unpack('H', data[6:8])[0]	
     

class PlcBteChpx(object):
   def __init__(self, worddocument, offset, size):  
     self.worddocument = worddocument
     self.offset = offset
     self.size = size
     self.nPNFKPCHPX = (self.size - 4) / (4 + 4)     
     self.naFC = 1 + self.nPNFKPCHPX 
     
     vfile = self.worddocument.open()
     try:
       if vfile.seek(self.offset) != self.offset:
         raise Exception("Can't seek to PlcBteChpx")
       data = vfile.read((self.naFC * 4))
       self.aFC = unpack('I'*self.naFC, data)
       data = vfile.read(self.nPNFKPCHPX * 4)
       #must be 22 bits :
       self.PNFKPCHPX = unpack('I'*self.nPNFKPCHPX, data)
     except :
      vfile.close()
      raise
     vfile.close()

   def KPCHPXoffset(self, n):
      return (self.PNFKPCHPX[n]) * 512

#MS-DOC Page 551
class ChpxFKPs(object):
  def __init__(self, plcBteChpx, worddocument):
     self.CHPXFKP = []
     vfile = worddocument.open()
     try:
       for x in xrange(0, plcBteChpx.nPNFKPCHPX):
         offset = plcBteChpx.KPCHPXoffset(x)
         if vfile.seek(offset) != offset:
           raise "Can't seek to ChpxFKPs"
         data = vfile.read(512)
         self.CHPXFKP.append(ChpxFKP(data))
     except :
       vfile.close()
       raise
     vfile.close()

#MS-DOC page 235
class ChpxFKP(object): 
  def __init__(self, data):
     crun = unpack('B' ,data[511:512])[0]
     crun = unpack('B' ,data[-1])[0]
     nRGFC = crun + 1
     nRGB =  crun
     self.RGFCs = unpack(nRGFC*'I', data[:nRGFC*4])
     RGBs = unpack(nRGB*'B', data[nRGFC*4:nRGFC*4+nRGB])
     self.Chpxs = []
     rgbskip = []
     rfccounter = 0
     for rgb in RGBs:
        if rgb != 0 and (rgb not in rgbskip):
	  rgbskip.append(rgb)
	  self.Chpxs.append(Chpx(data[rgb*2:], rfccounter))
	rfccounter += 1

class Chpx(object):
  def __init__(self, data, rfc):
     cb = unpack('B', data[0])[0]
     data = data[1:cb+1]
     self.grpprl = []
     self.rfc = rfc
     count = 0
     while count < cb:
        prl = PRL(data)
        self.grpprl.append(prl)  
        data = data[len(prl):]
	count += len(prl)

#MS-Doc page 31 / 414
class PRL(object):
  def __init__(self, data):
     self.sprm = SPRM(data[0:2])
     operandSize =  self.sprm.spraTable[self.sprm.spra]
     if operandSize == 0:
	if (self.sprm.ispmd == 0x8 and self.sprm.sgc == 5): #TDefOperandTable 
	  sz = unpack('H', data[2:4])[0]
	  r = 2
        elif (self.sprm.ispmd == 0x1 and self.sprm.sgc == 0x15): #sprmPchgTabs
  	  sz = unpack('B', data[2:3])[0]
	  r = 1
          if sz == 255:
	     delctabs = unpack('B', data[3:4])[0]
	     r += 1
	     deladdtabs = unpack('B', data[4+delctabs:4+delctabs+1])[0]	
	     sz = (4 * delctabs) + (3 * deladdtabs) 
	     r += 1
        else:
  	  sz = unpack('B', data[2:3])[0]
	  r = 1
	operandSize = r + sz
     self.size = 2 + operandSize
     self.operand = data[2:operandSize+2]

  def __len__(self):
     return self.size

#MS-Doc page 30
class SPRM(object):
  sgcTable = {
	       1 : "Paragraph",
	       2 : "Character",
	       3 : "Picture",
	       4 : "Section",
	       5 : "Table", 
	     }
  spraTable = {
		0 : 1,
		1 : 1,
		2 : 2,
		3 : 4,
		4 : 2,
		5 : 2,
		6 : 0, #Variable if sprmTDefTable or sprmPChTabs
		7 : 3,
	      }
  def __init__(self, data):
     c = unpack('H', data)[0]
     c = bin(c).replace('0b', '')[::-1]
     c += (16-len(c))*'0'
     self.ispmd = int(c[0:9][::-1], 2)
     self.fSpec = int(c[9], 2)
     self.sgc = int(c[10:13][::-1], 2)
     self.spra = int(c[13:16][::-1], 2)

class Pcdt(object):
  def __init__(self, table, offset, size):
     vfile = table.open() 
     try:
       if vfile.seek(offset) != offset:
         raise Exception("Can't seek to Pcdt offset")
       data = vfile.read(size)
     except :
       vfile.close()
       raise
     vfile.close()
     
     self.cltx = unpack('c', data[0])[0]
     data = data[1:]
     if self.cltx == 0x1:
       self.cbGrppl = unpack('I', data[0:4])[0]
       data = data[4:]
       self.GrpPrl = unpack('I'*self.cbGrppl, data[:self.cbGrppl])
       data = data[:self.cbGrppl]
     #else cltx == 0x2:
     self.lcb = unpack('I', data[0:4])[0]
     data = data[4:]
     plcdData = data[:self.lcb]
     naPcd = (self.lcb-4)/(4+8)
     naCP = naPcd + 1 
     self.aCP = unpack('I'*naCP, plcdData[0:naCP*4])
     plcdData = plcdData[naCP*4:]
     self.aPcd = []
     for x in range(0, naPcd):
        data = plcdData[x*8:(x*8)+8]
        self.aPcd.append(PCD(data))

  def cpOffset(self,cp):
     i = cp
     if self.aPcd[cp].fCompressed == 0:
	#16 Bit unicode
       return self.aPcd[cp].fc# + (2*(cp - self.aCP[i]))
     else:
       return (self.aPcd[cp].fc/2) #+ (cp- self.aCP[i])

class PCD(object):
  def __init__(self, data):
   fcstruct = unpack('<HBBBBH', data)[1:5]   
   binfcstruct = ''
   for i in fcstruct:
      c = bin(int(i)).replace('0b', '')[::-1]
      c += (8-len(c))*'0'
      binfcstruct += c

   self.fc =  binfcstruct[0:30][::-1]
   self.fc = int(self.fc, 2)
   self.fCompressed = int(binfcstruct[30:31])
