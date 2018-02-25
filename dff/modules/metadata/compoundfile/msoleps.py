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

from dff.modules.structparser import Struct, Header, ResolveAttributesMap, AttributesVMap
from dff.modules.lnk.lnkitem import UUID

from dff.modules.compoundfile.msoshared import MSVariant

PropertySetStreamHeader = ({ "info" : { "os":"None", "arch":"None", "name":"PropertySetStream"},
		"descr" : {
			     "PropertySetStream" : ((28),
			     {
			        "magic" : (2, 0),
				"void"  : (2, 2),
				"OSVersion" : (2, 4),
				"OSType" : (2, 6),
				"CLSID" : (16, 8),
				"SectionCount" : (4, 24),
			     }),
			     "SectionList" : ((20),
			     {
				"CLSID" :  (16, 0),
				"Offset" : (4, 16)
			     }),
			     "Section" : ((8),
			     {
				"Length" : (4, 0),
				"PropertyCount" : (4, 4),
			     }),
			     "PropertyList" : ((8),
			     {
				"PropertyID" : (4, 0),
				"Offset" : (4, 4)
			     }),

			  }	
		})

class PropertyList(list):
  def __init__(self):
     list.__init__(self)

  def propertyID(self, ID):
     for Property in self:
	if Property.PropertyID == ID:
	  return Property 
     return []

class PropertySetStream(Struct):
  OSID = { 0x0 : "Windows 16", 0x1 : "Macintosh", 0x2 : "Windows 32"}
  def __init__(self, stream, matchingSectionCLSID = None): #add some sectionCLSID to match to avoid parsing all section
     self.sectionList = []
     vfile = stream.open()    
     try:
       magic = vfile.read(2)
       if magic != "\xfe\xff":
	 vfile.close()
	 raise RuntimeError('Not a property stream')
       vfile.seek(0) 
       data = vfile.read(28)
       self.header = Header(PropertySetStreamHeader)
       Struct.__init__(self, self.header, None, self.header.PropertySetStream, data)
       self.CLSID = UUID(self.CLSID)
       try :
	os = self.OSID[self.OSType]
	self.OSVersion = os + ' - ' + str(self.OSVersion & 0x00ff) + '.' + str(self.OSVersion >> 8)
       except KeyError:
	self.OSVersion = "Unknown"
       count = 0
       if vfile.seek(28) != 28:
         raise Exception("Can't seek in property stream")
       while count < self.SectionCount:
	  sectionListData = vfile.read(20)
	  sectionHeader = Struct(self.header, None, self.header.SectionList, sectionListData)
	  sectionHeader.CLSID = UUID(sectionHeader.CLSID)
	  currentSectionListOffset = vfile.tell()
          if not matchingSectionCLSID or (sectionHeader.CLSID in matchingSectionCLSID):
            if vfile.seek(sectionHeader.Offset) != sectionHeader.Offset:
              raise Exception("Can't seek to sectionHeader.Offset in PropertySetStream")
	    data = vfile.read(8)
	    sectionHeader.Section = Struct(self.header, None, self.header.Section, data) 
	    sectionHeader.Section.PropertyList = PropertyList() 
	    maxReadSize = stream.size() - vfile.tell()
	    if maxReadSize <= 0:
	      break
	    if sectionHeader.Section.Length < maxReadSize: 
  	      readSize = sectionHeader.Section.Length
            else:
  	      readSize = maxReadSize
	    data = vfile.read(readSize) 
	    propertyCount = 0
	    while propertyCount < sectionHeader.Section.PropertyCount:
              propert = Struct(self.header, None, self.header.PropertyList, data[propertyCount*8:(propertyCount*8)+8])	
	      sectionHeader.Section.PropertyList.append(propert)
              propertyCount += 1		
	      if vfile.seek(sectionHeader.Offset + propert.Offset) != sectionHeader.Offset + propert.Offset:
                raise Exception("Can't seek to sectionHeader.Offset + propert.Offset in propertyStream")
              propert.Variant = MSVariant(vfile)
	      self.sectionList.append(sectionHeader)
	  if vfile.seek(currentSectionListOffset) != currentSectionListOffset:
            raise Exception("Can't seek to currentSectionListOffset in PropertySetStream") 
	  count += 1
     except :
	vfile.close()
        raise
     vfile.close()

  def sectionCLSID(self, sectionCLSID):
     for section in self.sectionList:
        if section.CLSID == sectionCLSID:
	  return section.Section
     return None

  def show_sections(self):
     print self.magic, self.void, self.OSVersion, self.CLSID, self.SectionCount 
     for section in self.sectionList:
	print section.CLSID, section.Section
	for propert in section.Section.PropertyList:
	  print propert
	  print propert.Variant.Type
	  print propert.Variant.Value
