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
from dff.api.types.libtypes import Variant, VMap, VList, Argument, typeId, MS64DateTime 

from dff.modules.structparser import Struct, Header, ResolveAttributesMap, AttributesVMap
from dff.modules.lnk.lnkheader import PropertyType

OfficeDocumentSectionCLSID = {
"F29F85E0-4FF9-1068-AB91-08002B27B3D9" : ("SummaryInformation",
     {
	1:  "Code page",
	2:  "Title", 
	3:  "Subject", 
	4:  "Author",
	5:  "Keywords",
	6:  "Comments",
	7:  "Template",
	8:  "Last author", 
	9:  "Revision number", 
	10: "Total editing time", #MSVariant is filetime but it's an absolute time
	11: "Last Printed", 
	12: "Created time", 
	13: "Last saved time", 
	14: "Number of pages", 
	15: "Number of words",  
	16: "Number of characters",
	17: "Thumbnail",
	18: "Application name", 
	19: "Security",
    }),
"D5CDD502-2E9C-101B-9397-08002B2CF9AE" : ("DocumentSummaryInformation",
   {
	0: "Dictionary",
        1 : "Code page",
        2 : "Category",
        3 : "Presentation format",
        4 : "Estimated size",
	5 : "Number of lines",
	6 : "Number of paragraphs",
	7 : "Number of slides",
	8 : "Number of notes",
	9 : "Number of hidden slides",
	10 : "Number of multimedia clips",
	11 : "Scale crop",
	12 : "Heading pairs",
	13 : "Titles of parts",
	14 : "Manager",
	15 : "Company",
	16 : "Links dirty",
	17 : "Number of characters",
	19 : "Application version",
	26 : "Content type", 
	27 : "Content status",
   }),
}

class MSVariant(object):
  def __init__(self, vfile):
    try:
      self.Type = PropertyType[unpack('I', vfile.read(4))[0]]
      self.Value = MSVariantConverter[self.Type](vfile)
    except :
      self.Value = None

class VT_CF(Node):
  ClipboardFormat = {
  -1 : "CFTAG_WINDOWS",
  -2 : "CTAG_MACINTOSH",
  -3 : "CFTAG_FMTID",
   0 : "CFTAG_NODATA",
  }
  ClipboardDataFormat = {
   3 : "CF_METAFILEPICT",
   8 : "CF_DIB",
   14: "CF_ENHMETAFILE",
    2: "CF_BITMAP",
  }
  def __init__(self, vfile):
    #XXX WMF and other type 
     self.parent = vfile.node()
     self.Size = unpack('I', vfile.read(4))[0]
     self.cbFormat = self.ClipboardFormat[unpack('i', vfile.read(4))[0]]
     self.cbDataFormat = self.ClipboardDataFormat[unpack('I', vfile.read(4))[0]]
     if self.cbDataFormat == "CF_METAFILEPICT":
       (mappingMode, x) = unpack('II', vfile.read(8))
       self.Size -=  8
     self.Size -= 4
     self.pos = vfile.tell()
     Node.__init__(self, 'Thumbnail', self.Size, self.parent, vfile.node().fsobj())
     self.__disown__()

  def fileMapping(self, fm):
     fm.push(0, self.size(), self.parent, self.pos)

  def _attributes(self):
     vmap = VMap()
     v = Variant(self.cbFormat)
     vmap['Clibboard Format'] = v
     v = Variant(self.cbDataFormat)
     vmap['Clibboard Data Format'] = v
     return vmap

#Could be done automatically 
class VT_VECTOR_LPSTR(VList):
  def __init__(self, vfile):
    vsize = unpack('I', vfile.read(4))[0]
    VList.__init__(self)
    count = 0
    while count < vsize:
      try:
	v = VT_LPSTR(vfile)
	self.push_back(v)
      except :
	pass
      count += 1

class VT_VECTOR_VARIANT(VList):
  def __init__(self, vfile):
    vsize = unpack('I', vfile.read(4))[0]
    VList.__init__(self)
    count = 0 
    while count < vsize:
      try:
        msv = MSVariant(vfile)
        v = msv.Value
        self.push_back(v)	
      except :
        pass
      count += 1

class VT_LPWSTR(Variant): #untested
  def __init__(self, vfile):
    size = unpack('I', vfile.read(4))[0]
    data = vfile.read(size)
    data = unicode(data, 'UTF-16').encode('UTF-8')
    Variant.__init__(self, data)

class VT_LPSTR(Variant):
  def __init__(self, vfile):
     size = unpack('I', vfile.read(4))[0]
     data = vfile.read(size)
     if len(data) > 1:
        Variant.__init__(self, str(data))
     else:
	Variant.__init__(self, None)

class VT_FILETIME(Variant):
  def __init__(self, vfile):
     data = unpack('Q', vfile.read(8))[0]
     #MS didn't differentiate absolute and relative time (time/datetime) 
     #so use ugly trick heare
     if data >= 116444736000000000: #a date time should be superior than the lep between unix & ms epoch
       vt = MS64DateTime(data)
       vt.thisown = False
       Variant.__init__(self, vt) 
     else:
       Variant.__init__(self, data)
     
class VT_BOOL(Variant):
  def __init__(self, vfile):
     Variant.__init__(self, bool(unpack('H', vfile.read(2))[0]))
     
class VT_I4(Variant):
  def __init__(self, vfile):
    Variant.__init__(self, unpack('I', vfile.read(4))[0])

class VT_I2(Variant):
  def __init__(self, vfile):
    Variant.__init__(self, unpack('H', vfile.read(2))[0])

MSVariantConverter = { 
  "VT_LPSTR" : VT_LPSTR,
  "VT_FILETIME" : VT_FILETIME,
  "VT_I4" : VT_I2,
  "VT_I2" : VT_I2,
  "VT_BOOL" : VT_BOOL,
  "VT_CF" : VT_CF,
  "VT_VECTOR_LPSTR" : VT_VECTOR_LPSTR,
  "VT_VECTOR_VARIANT" : VT_VECTOR_VARIANT,
}
