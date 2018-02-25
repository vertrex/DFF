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

from dff.api.exceptions.libexceptions import *
from dff.api.types.libtypes import Variant, VMap
from dff.api.vfs.libvfs import *

from dff.modules.firefoxcache.decoder import *
from dff.modules.firefoxcache.commons import *
from dff.modules.firefoxcache.dtime import *
from dff.modules.firefoxcache.cache_map import *

# http://mxr.mozilla.org/mozilla2.0/source/netwerk/cache/nsDiskCacheMap.h

class XData:
    def __init__(self, xdata):
        if xdata:
            self.xdata = xdata
            setattr(self, "init", bool(self.xdata & LocationInitializedMask))
            setattr(self, "file",  (self.xdata & LocationSelectorMask) >> LocationSelectorOffset)
            setattr(self, "blockCount", ((self.xdata & ExtraBlocksMask) >> ExtraBlocksOffset) + 1)
            setattr(self, "startBlock", (self.xdata & BlockNumberMask))
            setattr(self, "blockSize", self.getBlockSize((self.xdata & LocationSelectorMask) >> LocationSelectorOffset))
            setattr(self, "bitmapSize", self.getBitmapSize((self.xdata & LocationSelectorMask) >> LocationSelectorOffset))
            setattr(self, "fileSize", (self.xdata & FileSizeMask) >> FileSizeOffset)
            setattr(self, "fileGeneration", self.xdata & FileGenerationMask)
            setattr(self, "reserved", self.xdata & ReservedMask)
            
    def getBlockSize(self, index):
        if index:
            return (256 << (2 * ((index) - 1)))
        return 0

    def getBitmapSize(self, index):
        if index:
            return (131072 >> (2 * ((index) - 1)))
        return 0

class MapRecord(decoder):
    def __init__(self, vfile, offset, cachenodes, template=FIREFOX_MAP_RECORD):
        decoder.__init__(self, vfile, offset, template=FIREFOX_MAP_RECORD)
        self.setIndianess(BIG)
        self.decode()


        self.cachenodes = cachenodes

        self.metainfo = None
        self.datainfo = None

        if self.hash != 0:
            self.setXDataInfo()

    def setXDataInfo(self):
        if self.dataLocation:
            self.datainfo = XData(self.dataLocation)
        if self.metaLocation:
            self.metainfo = XData(self.metaLocation)

    def metadata(self):
        """
        Returns the metadata Entry of the record
        """
        if self.metainfo and self.metainfo.init:
            if self.metainfo.file >= 0 or self.metainfo.file < 4:
                vfile = self.cachenodes[self.metainfo.file]
                bs = (self.metainfo.bitmapSize / 32) * 4
                off = bs + self.metainfo.blockSize * self.metainfo.startBlock
                return MetaEntry(vfile, off)
            else:
                return None
        else:
            return None

    def data(self):
        if self.datainfo and self.datainfo.init:
            if self.datainfo.file >= 0 or self.datainfo.file < 4:
                vfile = self.cachenodes[self.datainfo.file]
                bs = (self.datainfo.bitmapSize / 32) * 4
                off = bs + self.datainfo.blockSize * self.datainfo.startBlock
                try:
                    metadata = self.metadata()
                    vfile.seek(off)
                    buff = vfile.read(metadata.dataSize)
                    return buff
                except:
                    print "Error while getting data"
                    return None
            else:
                return None
        else:
            return None
        
    def hexhash(self):
        h = hex(self.hash)
        if len(h[2:]) == 8:
            return h[2:]
        return None

    def localHashPath(self):
        if self.datainfo.file == 0:
            h = self.hexhash()
            if h:
                path = "" + h[0:1] + "/" + h[1:3] + "/" + h[3:8] + "d01"
                rootpath = self.cachenodes[0].node().parent().absolute()
                if rootpath:
                    return rootpath + "/" + path
                else:
                    return None
            else:
                return None
        else:
            return None

    def getVfsNode(self):
        from api.vfs.vfs import vfs
        vfs = vfs()
        node = vfs.getnode(self.localHashPath())
        if node:
            return node
        return None


class MetaEntry(decoder):
    def __init__(self, vfile, offset, template=FIREFOX_META_ENTRY):
        decoder.__init__(self, vfile, offset, template=FIREFOX_META_ENTRY)
        self.setIndianess(BIG)
        self.decode()

    def key(self):
        try:
            self.vfile.seek(self.offset + self.templateSize())
            buff = self.vfile.read(self.keySize)
            return unicode(buff)
        except:
            print "Error while getting metadata"
            return None

    def filename(self):
        k = self.key()
        if k:
            try:
                skey = k.split('/')
                fn = skey[len(skey) - 1]
                return unicode(fn)
            except:
                print "Error while getting filename"
                return None

    def request(self):
        try:
            self.vfile.seek(self.offset + self.templateSize() + self.keySize)
            buff = self.vfile.read(self.metaDataSize)
            return unicode(buff)
        except:
            print "Error while getting metadata"
            return None

    def lastFetchedDateTime(self):
        return DTime(self.lastFetched).toDatetime()

    def lastModifiedDateTime(self):
        return DTime(self.lastModified).toDatetime()

    def expirationDateTime(self):
        return DTime(self.expirationTime).toDatetime()
        




