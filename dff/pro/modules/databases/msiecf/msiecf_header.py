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

HEADER_OFFSET = 0
HEADER_SIZE = 0x4C # Contains cache dir entries

HEADER_SIGNATURE = {0: "Client",
                    1: "UrlCache",
                    2: "MMF",
                    3: "Ver"}

HEADER_SIGNATURE_VERSION = 4

MSIECF_HEADER = {"signature" : [0x0, 0x1C, STRING_T],
                 "filesize" : [0x1C, 0x4, UINT32_T],
                 "rootHashTableOffset" : [0x20, 0x4, UINT32_T],
                 "totalBlocks" : [0x24, 0x4, UINT32_T],
                 "allocatedBlocks" : [0x28, 0x4, UINT32_T],
                 "quotaCacheSize" : [0x30, 0x4, UINT32_T],
                 "cacheSize" : [0x38, 0x4, UINT32_T],
                 "nonReleasableCacheSize" : [0x40, 0x4, UINT32_T],
                 "cacheDirEntries" : [0x48, 0x4, UINT32_T]
                 }

class Header(decoder):
    def __init__(self, node, offset=HEADER_OFFSET, template=MSIECF_HEADER):
	vfile = node.open()
        decoder.__init__(self, vfile, offset=0, template=MSIECF_HEADER)
	vfile.close()
        self.__validity = 0

    def isValid(self):
        sig = self.signature.split()
        if sig[0] == HEADER_SIGNATURE[0]:
            self.__validity += 25
        if sig[1] == HEADER_SIGNATURE[1]:
            self.__validity += 25
        if sig[2] == HEADER_SIGNATURE[2]:
            self.__validity += 25
        if sig[3] == HEADER_SIGNATURE[3]:
            self.__validity += 25
        if self.__validity >= 75:
            return True
        return False

    def validity(self):
        return self.__validity

    def version(self):
        sig = self.signature.split()
        return sig[HEADER_SIGNATURE_VERSION]
                
