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

from hash_records import *

BLOCK_SIZE = 0x80

HASH_HEADER_SIZE = 0x10
HASH_ENTRY_SIZE = 0x8
HASH_UNALLOCATED_ENTRY = 0xDEADBEEF

HASH_SIGNATURE = "HASH"

MSIECF_HASH_TABLE = {"signature" : [0x0, 0x4, STRING_T],
                     "blocks" : [0x4, 0x4, UINT32_T],
                     "next" : [0x8, 0x4, UINT32_T],
                     "sequence" : [0xC, 0x4, UINT32_T]
                            }

MSIECF_HASH_ENTRY = {"recordID" : [0x0, 0x4, UINT32_T],
                     "recordOffset" : [0x4, 0x4, UINT32_T]
                     }


RECORD_FLAG_VALID = [0x0, 0x8]
# 0x8 : Add STICKY_CACHE_ENTRY flag into URL header ??
RECORD_FLAG_INVALID = [0x1]
RECORD_FLAG_UNUSED = [0x3]
RECORD_FLAG_REDR = [0x5]
RECORD_FLAG_UNINIT = [0xF]

class HashTableManager:
    def __init__(self, node, rootaboffset, cachetable):
        self.__tables = []
        self.cachetable = cachetable
        self.node = node
	self.vfile = node.open()
        
        if self.isValidTab(rootaboffset):
            self.rootaboffset = rootaboffset
            self.parseTables()
        self.vfile.close()

    def isValid(self):
        if len(self.__tables) > 0:
            return True
        return False

    def isValidTab(self, taboffset):
        self.vfile.seek(taboffset)
        buff = self.vfile.read(MSIECF_HASH_TABLE["signature"][TEMP_SIZE])
        if buff == HASH_SIGNATURE:
            return True
        return False

    def parseTables(self):
        curroffset = self.rootaboffset
        while curroffset != 0:
            tab = HashTable(self.node, curroffset, self.cachetable)
            self.__tables.append(tab)
            curroffset = tab.next

    def getRecords(self, recordtype):
        ret = []
        for table in self.__tables:
            if recordtype == "REDIRECT":
                recs = table.redirectRecords
            elif recordtype == "VALID":
                recs = table.validRecords
            elif recordtype == "INVALID":
                recs = table.invalidRecords
            else:
                recs = table.unknownRecords
            if recs:
                for rec in recs:
                    ret.append(rec)
        return ret

    def unusedEntries(self):
        ret = []
        for table in self.__tables:
            recs = table.unusedEntries
            if recs:
                for rec in recs:
                    ret.append(rec)
        return ret

    def uninitEntries(self):
        ret = []
        for table in self.__tables:
            recs = table.uninitEntries
            if recs:
                for rec in recs:
                    ret.append(rec)
        return ret


class HashTable(decoder):
    def __init__(self, node, offset, cachetable, template=MSIECF_HASH_TABLE):
	self.node = node
	self.vfile = node.open()
        decoder.__init__(self, self.vfile, offset, template=MSIECF_HASH_TABLE)
        self.entries_area_size = (self.blocks * BLOCK_SIZE) - HASH_HEADER_SIZE
        self.root_entry_offset = self.offset + HASH_HEADER_SIZE
        self.entries_count = self.entries_area_size / HASH_ENTRY_SIZE

        self.cachetab = cachetable
        # Records
        self.validRecords = []
        self.redirectRecords = []
        self.invalidRecords = []
        self.unknownRecords = []
        self.uninitEntries = []
        self.unusedEntries = []

        self.parseRecords()
	self.vfile.close()

    def parseRecords(self):
        curentry = 0
        curoffset = self.root_entry_offset
        tempinvalid = []
        while curentry < self.entries_count:
            e = HashEntry(self.vfile, curoffset)
            if e.getRecordID() in RECORD_FLAG_VALID:
                self.validRecords.append(Url(self.node, 
                                             e.recordOffset, 
                                             self.cachetab))
            elif e.getRecordID() in RECORD_FLAG_REDR:
                self.redirectRecords.append(Redr(self.node,
                                              e.recordOffset,
                                              self.cachetab))
            elif e.getRecordID() in RECORD_FLAG_INVALID:
                tempinvalid.append(e)
            elif e.getRecordID() in RECORD_FLAG_UNINIT:
                self.uninitEntries.append(e)
            elif e.getRecordID() in RECORD_FLAG_UNUSED:
                self.unusedEntries.append(e)
            else:
                self.unknownRecords.append(e)

            curoffset += HASH_ENTRY_SIZE
            curentry += 1
        # Process invalid records
        for irec in tempinvalid:
            if self.isValidRecord(irec.recordOffset):
                self.validRecords.append(Url(self.node,
                                             irec.recordOffset,
                                             self.cachetab))
            else:
                self.invalidRecords.append(irec)

    def isValidRecord(self, recoffset):
        self.vfile.seek(recoffset)
        buff = self.vfile.read(MSIECF_URL["signature"][TEMP_SIZE])
        if buff == URL_SIGNATURE:
            return True
        return False

class HashEntry(decoder):
    def __init__(self, vfile, offset, template=MSIECF_HASH_ENTRY):
        decoder.__init__(self, vfile, offset, template=MSIECF_HASH_ENTRY)

    def getRecordID(self):
        return self.recordID & 0xf






        
