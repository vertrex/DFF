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

from dff.api.types.libtypes import MS64DateTime, DosDateTime 

from dff.modules.structparser import FlagsList

from lnkheader import FileAttributesFlags

ItemType = {
        0x1F: "GUID",
        0x23: "Drive",
        0x25: "Drive",
        0x29: "Drive",
        0x2E: "Shell Extension",
        0x2F: "Drive",
        0x30: "Directory",
        0x31: "Directory",
        0x32: "File",
        0x34: "File Unicode",
        0x35: "File Unicode",
	0x36: "File Unicode",
        0x41: "Workgroup",
        0x42: "Computer",
        0x46: "Net Provider",
        0x47: "Whole Network",
        0x4C: "Web Folder",
        0x61: "MSITStore",
        0x70: "Printer/RAS Connection",
        0xB1: "History/Favorite",
        0xC3: "Network Share",
}

def UnicodeBuff(buff):
   pos =  buff.find('\x00\x00')
   while pos != -1:
      if pos % 2:
	  pos = buff.find('\x00\x00',pos+1)
      else:
	  return unicode(buff[:pos], 'UTF-16')
   return None 	

def ShortSizeString(data, isUnicode = True):
   size = unpack("H", data[0:2])[0]
   if isUnicode:
     return (unicode(data[2:(size*2 + 2)], 'UTF-16'), size*2 + 4)
   else:
     return (data[2:size+1], size + 3)

def ItemFileUnicode(data, isUnicode = True):
   directoryMap = {}
   #directoryMap["ID type"] = (IDtype, int)
   size = unpack("I", data[2:6])[0]
   if size:
     directoryMap["size"] = (size, int)
   time, date = unpack("HH", data[6:10])
   directoryMap["modified time"] = ((date, time,), DosDateTime)
   directoryMap["File attributes"] = (FlagsList(unpack("H", data[10:12])[0], FileAttributesFlags), list)

   data = data[12:]
   pos = data.find('\x03\x00\x04\x00') #Serves as end of string marker ? 
   if pos:
     name = unicode(data[:pos-2], 'UTF-16')
     directoryMap["name"] = (name, str)
     data = data[pos-2:]

   if isUnicode:
     if len(data) % 2:
   	data = data[1:]
     raw_bytes = unpack("6B", data[2:8]) #ENF OF UNICODE STR ??\03\00\04\00
     time, date = unpack("HH", data[8:12])
     directoryMap["creation time"] = ((date, time,), DosDateTime)
     time, date = unpack("HH", data[12:16])
     directoryMap["access time"] = ((date, time,), DosDateTime)
     length_next = unpack("H", data[18:20])[0]
     unicode_name = UnicodeBuff(data[20:])
     directoryMap["unicode name"] = (unicode_name, str)
     data = data[20+len(unicode_name)*2+2:]
     if length_next:
       pos = data.find('\x00')
       localized_name = data[:pos] ##XXX May have 2 or more strings ?
       directoryMap["localized name"] = (localized_name, str)
   else:
     if len(data) > 1:
       pos = data.find('\x00')
       directoryMap["short name"] = (data[:pos], str)
   return (directoryMap, dict)

def ItemDirectory(data, isUnicode = True):
   directoryMap = {}
   size = unpack("I", data[2:6])[0]
   if size:
     directoryMap["size"] = (size, int)
   time, date = unpack("HH", data[6:10])
   directoryMap["modified time"] = ((date, time,), DosDateTime) #XXX modified time ? 
   directoryMap["File attributes"] = (FlagsList(unpack("H", data[10:12])[0], FileAttributesFlags), list)

   pos =  data[12:].find('\x00')
   if pos != -1:
     name = data[12:12+pos]
     data = data[12+pos+1:]
     directoryMap["name"] = (name, str)

   if isUnicode:
     if len(data) % 2:
   	data = data[1:]
     raw_bytes = unpack("6B", data[2:8]) #ENF OF UNICODE STR ??\03\00\04\00
     time, date = unpack("HH", data[8:12])
     directoryMap["creation time"] = ((date, time,), DosDateTime)
     time, date = unpack("HH", data[12:16])
     directoryMap["access time"] = ((date, time,), DosDateTime)
     length_next = unpack("H", data[18:20])[0]
     unicode_name = UnicodeBuff(data[20:])
     directoryMap["unicode name"] = (unicode_name, str)
     data = data[20+len(unicode_name)*2+2:]
     if length_next:
       pos = data.find('\x00')
       localized_name = data[:pos] ##XXX May have 2 or more strings ?
       directoryMap["localized name"] = (localized_name, str)
   else:
       if len(data) > 1:
         pos = data.find('\x00')
         directoryMap["short name"] = (data[:pos], str)
   return (directoryMap, dict)

def ItemDrive(data, isUnicode = True):
   #if isUnicode:
     #return (unicode(data[1:]), str)
   #else:
     pos = data[1:].find('\x00')
     if pos != -1:
       return (data[1:], str)	
     return ('', str)
    

def ItemWebFolder(data, isUnicode = True):
   idmap = {}	    
   data = data[6:]
   tm = unpack("<Q", data[:8])[0]
   idmap["modified"] = (tm, MS64DateTime)
   data = data[20:]
   (name, size) = ShortSizeString(data, isUnicode) 
   idmap["name"] = (name, str)
   data = data[size:]
   if name:
      idmap["address"]= (ShortSizeString(data, isUnicode)[0], str)
   #if len(idmap):
   return (idmap, dict)

def ItemNetworkShare(data, isUnicode = True):
    idmap = {}
    data = data[3:] 
    pos =  data.find('\x00')
    if pos != -1:
      idmap["name"] = (data[:pos], str)
      data = data[pos+1:]
    pos =  data.find('\x00')
    if pos != -1:
      idmap["protocol"] = (data[:pos], str)
      data = data[pos+1:]
    pos =  data.find('\x00')
    if pos != -1:
      idmap["description"] = (data[:pos], str)
    #if len(idmap):   
    return (idmap, dict) 

def UUID(uuid):
   buff1 = uuid[0:4]
   buff2 = uuid[4:6]
   buff3 = uuid[6:8]
   buff4 = uuid[8:16]
   uuid = buff1[::-1] + buff2[::-1] + buff3[::-1] + buff4 
   buff = ''
   for i in xrange(0, len(uuid)):
      buff += "%.2X" % ord(uuid[i])
      if i in (3, 5, 7, 9):
        buff += '-' 
   return buff

def ItemGUID(data, isUnicode = True):
   dummy = data[1:2]
   return (UUID(data[2:18]), str)

def ItemNetwork(data, isUnicode = True):
   idmap = {}
   data = data[3:] 
   pos =  data.find('\x00')
   if pos != -1:
     idmap["name"] = (data[:pos], str)
     data = data[pos+1:]
   pos =  data.find('\x00')
   if pos != -1:
     idmap["protocol"] = (data[:pos], str)
   #if len(idmap):    
   return (idmap, dict)

def ItemWholeNetwork(data, isUnicode = True):
   data = data[3:]
   pos = data.find('\x00')
   if pos != -1:
     return (data[:pos], str)
   return ('', str)

def ItemMSITStore(data, isUnicode = True):
   data = data[6:]
   return (UnicodeBuff(data) , str)

ItemTypeConverter = {
"GUID" : ItemGUID,
"Printer/RAS Connection" : ItemGUID,
"Shell Extension" : ItemGUID,
"Workgroup" : ItemNetwork,
"Computer" :  ItemNetwork,
"Net Provider" : ItemNetwork,
"Whole Network" : ItemWholeNetwork,
"MSITStore" : ItemMSITStore, 
"Network Share" : ItemNetworkShare, 
"Web Folder" : ItemWebFolder,
"Drive" : ItemDrive,
"File Unicode" : ItemFileUnicode,
"Directory" : ItemDirectory,
"File" : ItemDirectory,
"History/Favorite" : ItemDirectory,
}



