# DFF -- An Open Source Digital Forensics Framework
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
#  Jeremy MOUNIER < jmo@arxsys.fr>
#

from msiecf_header import *
from cache_table import *
from hash_table import *
from hash_records import *
from msiecf_carver import *

from dff.api.exceptions.libexceptions import *
from dff.api.types.libtypes import Variant, VMap
from dff.api.vfs.libvfs import *

# Index type : default = TEMP
# Global history uses dataEntries
INDEX_TYPE = { "GLOBAL_HISTORY" : '^Visited:',
               "HISTORY" : '^:[0-9]{16}:',
               "COOKIE" : '^Cookie:',
               "PRIVACIE" : '^PrivacIE:',
               "IECOMPAT" : '^iecompat:',
               "IETLD" : '^ietld:',
               "FEEDS" : '^feedplat:',
               "USERDATA" : '^userdata:',
               "DOMSTORE" : '^DOMStore:'}

class MSIEIndex:
    """ Master class which parse Microsoft Internet Explorer (MSIE) cache format  """
    def __init__(self, indexnode):
        self.indexnode = indexnode
        self.__records = {}

        head = self.readHeader()
        if head:
            self.header = head
            self.cachetable = self.readCacheTable()
            self.hashTables = self.readHashTables(self.cachetable)
        self.carver = None
### READ Operations ###

    def readHeader(self):
        """ Check for MSIECF header and create it"""
        head = Header(self.indexnode)
        if head.isValid():
            return head
        else:
            return None

    def readCacheTable(self):
        """ Read and create MSIECF cache table if exists """
        if self.header.cacheDirEntries > 0:
            return CacheTable(self.indexnode, self.header.cacheDirEntries)
        else:
            return None
        
    def readHashTables(self, cachetable):
        """ Check for MSIECF header and create it """
        if self.header.rootHashTableOffset > 0:
            return HashTableManager(self.indexnode, self.header.rootHashTableOffset, cachetable)
        else:
            return None

    def version(self):
        """ Get MSIE cache file version"""
        return self.header.version()

    def carveRecords(self):
        self.carver = MSIECFCarver(self.indexnode)
        self.carver.process()

    def ValidDeletedRecords(self):
        deletedRecords = []
        if not self.carver:
            self.carveRecords()
        carvedRecords = self.carver.urls()
        tablesRecords = self.hashTables.validRecords()
        for crecord in carvedRecords:
            deleted = True
            for trecord in tablesRecords:
                if trecord.offset == crecord.offset:
                    deleted = False
            if deleted:
                deletedRecords.append(crecord)
        return deletedRecords

    def RedirectDeletedRecords(self):
        deletedRecords = []
        if not self.carver:
            self.carveRecords()
        carvedRecords = self.carver.redr()
        for crecord in carvedRecords:
            deleted = True
            for trecord in tablesRecords:
                if trecord.offset == crecord.offset:
                    deleted = False
            if deleted:
                deletedRecords.append(crecord)
        return deletedRecords

    def getUnallocatedBlocks(self):
        # Parse regular Records
        # Carve regular Records and get deleted from parsed
        # get all blocks from all records
        # from this list deduce unallocated blocks
        pass

    def mount(self, mfso):
        if self.hashTables:
            records = self.hashTables.getRecords("VALID")
            if records:
                self.rootnode = Node("MSIECF", 0, None, mfso)
                for record in records:
                    name = record.location()
                    if name:
                        node = MSIECFNode(mfso, self.rootnode, record, self.indexnode)
                mfso.registerTree(self.indexnode, self.rootnode) 

class MSIECFNode(Node):
  def __init__(self, mfso, parent, record, rnode):
      Node.__init__(self, record.location(), len(record.location()), parent, mfso)
      self.record = record
      self.rnode = rnode
      self.pnode = parent
      self.__disown__()
      self.setFile()

  def fileMapping(self, fm):
      fm.push(0, self.record.templateSize(), self.rnode, self.record.offset)
