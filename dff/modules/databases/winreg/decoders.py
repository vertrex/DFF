# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2013 ArxSys
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
#
import string
from struct import unpack

from dff.api.types.libtypes import Argument, typeId, DateTime, MS64DateTime

#class DateDecoder():
#    def __init__(self, data, keyname):
#        self.data = None
#        if str(keyname) == 'InstallDate':
#        self.data = str(DateTime(data, TIME_UNIX))
#        else:
#         self.data = data

#    def decode(self):
#        return self.data

class DateDecoder():
    def __init__(self, data):
        self.data = data
        if type(data) == bytearray:
            self.data = str(MS64DateTime(unpack('Q', str(data))[0]))
        else:
            self.data = str(DateTime(data))

    def decode(self):
        return self.data

class Rot13decoder():
    def __init__(self, data):
        self.data = data

    def decode(self):
        buff = unicode()
        for c in self.data:
            if c in string.ascii_uppercase:
                buff += chr((((ord(c) - 0x41)+13)%26) + 0x41)
            elif c in string.ascii_lowercase:
                buff += chr((((ord(c) - 0x61)+13)%26) + 0x61)
            else:
                buff += c
        return buff.encode('UTF-8').decode('UTF-8')

class UTF16LEDecoder():
    def __init__(self, data):
        self.data = data

    def decode(self):
        buff = unicode()
        return self.data.decode('UTF-16LE').encode("UTF8")

class UTF16BEDecoder():
    def __init__(self, data):
        self.data = data

    def decode(self):
        buff = unicode()
        return self.data.decode('UTF-16BE').encode("UTF8")

class UserAssistDecoder():
    def __init__(self, data, keyname):
        self.count = 0
        self.lastUpdate = "N/A"
        self.id = 0 
        if len(data) <= 16:
            try:
                self.id = unpack("<I", str(data[0:4]))[0]
                self.count = unpack("<I", str(data[4:8]))[0]
                if self.count > 5:
                    self.count -= 5
                else:
                    self.count = 0
                self.lastUpdate = MS64DateTime(unpack("<Q", str(data[8:16]))[0])
            except :
                pass
        elif len(data) == 72:
            try:
                self.count = unpack("<I", str(data[4:8]))[0]
                self.lastUpdate = MS64DateTime(unpack("<Q", str(data[60:68]))[0])
            except :
                pass
 
    def decode(self):
        buff = "Id :" + str(self.id) + " count : " + str(self.count) + " last update : " + str(self.lastUpdate)
        return buff 
