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

CACHE_DIR_TABLE_OFFSET = 0x4C
CACHE_ENTRY_SIZE = 0xC

#Junk just after cache table (unused)
#JUNK_OFFSET = 0x1D0
#JUNK_SIZE = 0x80

MSIECF_CACHE_ENTRY = {"files" : [0x0, 0x4, UINT32_T],
                      "name" : [0x4, 0x8, STRING_T]
                      }

class CacheTable:
    def __init__(self, node, dirEntries):
        self.node = node
        # Represents the number of entries
        self.dirEntries = dirEntries
        # CacheEntry objects
        self.__entries = {}

        self.allocate()

    def allocate(self):
        curoffset = CACHE_DIR_TABLE_OFFSET
        cp = 0
	vfile = self.node.open()
        while cp < self.dirEntries:
	    vfile.seek(curoffset)
            e = decoder(vfile, curoffset, template=MSIECF_CACHE_ENTRY)
            self.__entries[cp] = e
            curoffset += CACHE_ENTRY_SIZE
            cp += 1
        vfile.close()

    def entries(self):
        if len(self.__entries) > 0:
            return self.__entries
        else:
            return None




        
