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

import binascii
import struct

from dff.api.exceptions.libexceptions import *
from dff.api.types.libtypes import Variant, VMap, DateTime 
from dff.api.vfs.libvfs import *

from dff.modules.firefoxcache.decoder import *
from dff.modules.firefoxcache.commons import *
from dff.modules.firefoxcache.cache_record import *

# http://mxr.mozilla.org/mozilla2.0/source/netwerk/cache/nsDiskCacheMap.h

class CacheMapHeader(decoder):
    def __init__(self, vfile, offset, template=FIREFOX_MAP_HEADER):
        decoder.__init__(self, vfile, offset, template=FIREFOX_MAP_HEADER)
        self.setIndianess(BIG)
        self.decode()

    def isValid(self):
        if self.isDirty == 0 or self.isDirty == 1:
            return True
        else:
            return False

    def evictionRank(self):
        """
        Return an eviction rank table
        """
        try:
            self.vfile.seek(self.templateSize())
            buff = self.vfile.read(BUCKETS * 4)
            if len(buff) == BUCKETS * 4:
                res = struct.unpack('>32I', buff)
                return res
        except:
            print "Read eviction rank Error"


    def bucketUsages(self):
        """
        Return a bucketUsage table of size 32
        """
        try:
            self.vfile.seek(self.templateSize() + BUCKETS * 4)
            buff = self.vfile.read(BUCKETS * 4)
            if len(buff) == BUCKETS * 4:
                res = struct.unpack('>32I', buff)
                return res
        except:
            print "Read eviction rank Error"

class CacheMap:
    def __init__(self, header, cachenodes, mfso):
        self.cachenodes = cachenodes
        self.header = header
        self.mfso = mfso

        self._recordsList = []
        self._records = {}

        if self.isValid():
            self.listRecords()

    def isValid(self):
        # Check if header is dirty
        if self.header.isDirty == 1:
        # Check records modulo
            totalrecords = (self.header.vfile.node().size() - HEADER_SIZE) / 16
            if totalrecords % 4 == 0:
                return True
        return False

    def listRecords(self):
        """
        Create a list of valid records 
        """
        offset = HEADER_SIZE
        count = 0
        # Open cache map file
        while count < totalrecords:
            record = MapRecord(self.header.vfile, offset, self.cachenodes)
            if record.hash != 0:
                self._recordsList.append(record) 
            offset += record.templateSize()
            count += 1

    def mapRecords(self):
        """
        Take a list of records, generate node or retrieve it from the vfs and create a map of type : {record : node}
        """

        self.rootnode = Node("files", 0, None, self.mfso)
        for record in self._recordsList:
            entry = record.metadata()
            if record.datainfo.file != 0:
                node = CacheNode(self.mfso, self.rootnode, record.metadata().filename(), entry.dataSize, record, self.cachenodes[record.datainfo.file])

            else:
                node = recod.getVfsNode()
            self._records[record] = node

        self.mfso.registerTree(self.cachenodes[0].node(), self.rootnode)

    def getRecordList(self):
        if len(self._recordsList) > 0:
            return self._recordsList
        else:
            return None

    def getRecords(self):
        return self._records

class CacheNode(Node):
    def __init__(self, mfso, parent, name, size, record, vfile):
        Node.__init__(self, name.encode('utf-8', 'replace'), size, parent, mfso)
        self.rsize = size
        self.record =  record
        self.vfile = vfile
        self.__disown__()

    def getTime(self, timestamp):
        vt = DateTime(timestamp)
        vt.thisown = False
        v = Variant(vt)
        return v

    def fileMapping(self, fm):
        bs = (self.record.datainfo.bitmapSize / 32) * 4
        off = bs + self.record.datainfo.blockSize * self.record.datainfo.startBlock
        fm.push(0, self.rsize, self.vfile.node(), off)

    def CVariant(self, data):
        d = Variant(data)
        return d
    
    def _attributes(self):
        attr = VMap()
        
        attr["Last modified"] = self.getTime(self.record.metadata().lastModifiedDateTime())
        attr["Last fetched"] = self.getTime(self.record.metadata().lastFetchedDateTime())
        attr["Expiration"] = self.getTime(self.record.metadata().expirationDateTime())

        return attr


        




