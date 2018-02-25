# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2011 ArxSys
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
#  Jeremy Mounier <jmo@digital-forensic.org>
# 

from decoder import *

import re
from urlparse import urlparse

REDR_LOCATION_OFFSET = 0x10

URL_SIGNATURE = "URL "

MSIECF_URL = {"signature" : [0x0, 0x4, STRING_T],
              "blocks" : [0x4, 0x4, UINT32_T],
              "secFiletime" : [0x8, 0x8, UINT64_T],
              "primFiletime" : [0x10, 0x8, UINT64_T],
              "expirDatetime" : [0x18, 0x4, UINT32_T],
              "cachedFilesize" : [0x20, 0x4, UINT32_T],
              "upCachedFilesize" : [0x24, 0x4, UINT32_T],
              "nonReleasableTimedelta" : [0x2C, 0x4, UINT32_T],
              "locationOffset" : [0x34, 0x4, UINT32_T],
              "cacheDirIndex" : [0x38, 0x1, UINT8_T],
              "filenameOffset" : [0x3C, 0x4, UINT32_T],
              "cacheEntryFlags" : [0x40, 0x4, UINT32_T],
              "dataOffset" : [0x44, 0x4, UINT32_T],
              "dataSize" : [0x48, 0x4, UINT32_T],
              "lastCheckedDatetime" : [0x50, 0x4, UINT32_T],
              "hits" : [0x54, 0x4, UINT32_T]
              }

MSIECF_REDR = {"signature" : [0x0, 0x4, STRING_T],
               "blocks" : [0x4, 0x4, UINT32_T],
               "uk1" : [0x8, 0x4, UINT32_T],
               "uk2" : [0xC, 0x4, UINT32_T]
              }

MSIECF_LEAK = {"signature" : [0x0, 0x4, STRING_T],
               "blocks" : [0x4, 0x4, UINT32_T],
               "cachedFilesize" : [0x20, 0x4, UINT32_T],
               "cacheDirIndex" : [0x38, 0x1, UINT8_T],
               "filenameOffset" : [0x3C, 0x4, UINT32_T]
               }

URL_DATA_ENTRY_HEADER_SIZE = 0x4

URL_DATA_ENTRY = {"entrySize" : [0x0, 0x2, UINT16_T],
                  "entryType" : [0x2, 0x1, UINT8_T],
                  "valueType" : [0x3, 0x1, UINT8_T]
                  } 

URL_DATA_ENTRY_VT_EMPTY = 0x0
URL_DATA_ENTRY_VT_MZ = 0x1
URL_DATA_ENTRY_VT_INT32 = 0x3
URL_DATA_ENTRY_VT_ASCII = 0x1e
URL_DATA_ENTRY_VT_UNICODE = 0x1f

ENTRY_TYPE = {0x0e : ["GUID", URL_DATA_ENTRY_VT_ASCII],
              0x10 : ["Page title", URL_DATA_ENTRY_VT_UNICODE],
              0x15 : ["Favicon URI", URL_DATA_ENTRY_VT_ASCII],
              0x16 : ["File URI", URL_DATA_ENTRY_VT_UNICODE]}


class HashRecord(decoder):
    def __init__(self, node, offset, template):
	self.node = node
	vfile = node.open()
        decoder.__init__(self, vfile, offset, template)
	vfile.close()

    def readStringField(self, off):
	readsize = (self.blocks * 0x80) - off
        ret = ""
        try:
	    vfile = self.node.open()
            vfile.seek(self.offset + off)
            buff = vfile.read(readsize)
	    vfile.close()
            for b in buff:
                if b != '\0':
                    ret += b
                else:
                    break
            return ret
        except:
            pass

class UrlDataEntry(decoder):
    def __init__(self, node, offset, template=URL_DATA_ENTRY):
	vfile = node.open()
	vfile.seek(offset)
        decoder.__init__(self, node, offset, template=URL_DATA_ENTRY)
        vfile.close()	
        self.dataSize = self.entrySize - URL_DATA_ENTRY_HEADER_SIZE
        self.dataOffset = self.offset + URL_DATA_ENTRY_HEADER_SIZE

    def data(self):
        if self.dataOffset > 0:
	    vfile = node.open()
            vfile.seek(self.dataOffset)
            data = self.vfile.read(self.dataSize)
	    vfile.close()
            return self.formatData(data)

    def name(self):
        if self.entryType in ENTRY_TYPE:
            return ENTRY_TYPE[self.entryType][0]
        else:
            return "Unknown"

    def formatData(self, buff):
        if self.valueType in (URL_DATA_ENTRY_VT_MZ, URL_DATA_ENTRY_VT_UNICODE):
            return buff.decode('utf-16', 'replace')
        elif self.valueType == URL_DATA_ENTRY_VT_ASCII:
            return buff.decode('ascii', 'replace')
        elif self.valueType == URL_DATA_ENTRY_VT_EMPTY:
            return None
        else:
            return buff

class Url(HashRecord):
    def __init__(self, node, offset, cachetab, template=MSIECF_URL):
        HashRecord.__init__(self, node, offset, template=MSIECF_URL)
        self.cachetable = cachetab

    def filename(self):
        """ Return filename"""
        if self.filenameOffset != 0:
            return self.readStringField(self.filenameOffset)
        else:
            return None

    def location(self):
        """ Return record location string"""
        if self.locationOffset != 0:
            return self.readStringField(self.locationOffset)
        else:
            return None

    def dataEntries(self):
        """ Return data entry List """
        entries = []
        if self.dataOffset != 0:
            rsize = 0
            while rsize < self.dataSize:
                dentry = UrlDataEntry(self.node, self.offset + self.dataOffset + rsize)
                if dentry.entrySize > 0:
                    rsize += dentry.entrySize
                    entries.append(dentry)
                else:
                    break
            return entries            

    def data(self):
        """ Return simple data field (String)"""
        if self.dataOffset != 0:
            return self.readStringField(self.dataOffset)
        else:
            return None

    def cacheDirectory(self):
        try:
            if self.cachetable:
                entries = self.cachetable.entries()
                return entries[self.cacheDirIndex].name
            else:
                return None
        except KeyError:
            return None


class Redr(HashRecord):
    def __init__(self, node, offset, cachetab, template=MSIECF_REDR):
        HashRecord.__init__(self, node, offset, template=MSIECF_REDR)

        self.cachetable = cachetab

    def location(self):
        return self.readStringField(REDR_LOCATION_OFFSET)


class Leak(HashRecord):
    def __init__(self, node, offset, template=MSIECF_LEAK):
        HashRecord.__init__(self, node, offset, template=MSIECF_LEAK)

    def filename(self):
        if self.filenameOffset != 0:
            return self.readStringField(self.filenameOffset)
        else:
            return None
