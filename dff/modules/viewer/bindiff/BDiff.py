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
#  Jeremy Mounier <jmo@digital-forensic.org>
# 
import binascii
import struct
import string

from PyQt4.QtGui import *
from PyQt4.QtCore import *

from dff.api.vfs import *
from dff.api.vfs.libvfs import *
from dff.api.exceptions.libexceptions import *

from dff.modules.bindiff.hexView import *
from dff.modules.bindiff.lfscrollbar import *

class BDiff(QWidget):
    def __init__(self, parent):
        super(BDiff,  self).__init__(parent)
        self.mainWindow = parent
        self.vfs = vfs.vfs()
        
    def init(self, node1, node2):
        self.node1 = node1
        self.node2 = node2

        self.vfile1 = node1.open()
        self.vfile2 = node2.open()

        self.initInfos()
        #Init view and scene
        self.initShape()
        #First Read and Sector Shape Creation
        try:
            self.vfile1.seek(0)
            self.vfile2.seek(0)
            buffer1 = self.vfile1.read(self.pageSize)    
            buffer2 = self.vfile2.read(self.pageSize)
            self.updateCurrents(0)
            self.whex.updateItems(0, buffer1)
            self.whex2.updateItems(0, buffer2)

            self.processPageDiff(buffer1, buffer2)

            self.whex.hexitem.initStartBlank()
            self.whex.asciitem.initStartBlank()
            self.whex2.hexitem.initStartBlank()
            self.whex2.asciitem.initStartBlank()

        except vfsError,  e:
            print e.error

    def initInfos(self):
        #Files Size
        self.file1size = self.node1.size()
        self.file2size = self.node2.size()
        #Set Master file 
        if self.file1size > self.file2size:
            self.masterFile =  self.vfile1
            self.masterFileSize =  self.file1size
        else:
            self.masterFile =  self.vfile2
            self.masterFileSize = self.file2size
        #Offset
        self.currentOffset = 0
        # Offset Base : 0:HEX 1:DEC 2:BIN
        self.opt_offsetBase = 0
        #Pages
        self.currentPage = 0
        self.pageSize = 256
        self.pageHead = 0
        self.pageSpare = 0
        self.pagesPerBlock = 32
        self.bytesPerLine = 16
        self.groupBytes = 1

    def initShape(self):
        #General Layout : Header + View + Footer
        self.vlayout = QVBoxLayout()
        self.vlayout.setSpacing(0)

        self.hlayout = QHBoxLayout()
        self.hlayout.setSpacing(0)

        self.whex = wHex(self)
        self.whex2 = wHex(self)

        self.whex.view.setSyncView(self.whex2.view)
        self.whex2.view.setSyncView(self.whex.view)
                
        self.hexcontainer = QWidget()
        self.vlayout.addWidget(self.whex)
        self.vlayout.addWidget(self.whex2)
        self.hexcontainer.setLayout(self.vlayout)

        self.hlayout.addWidget(self.hexcontainer)

        self.scrollbar = LFScrollBar(self)
        self.hlayout.addWidget(self.scrollbar)

        self.setLayout(self.hlayout)


    def processDiffList(self, difflist):
        cp = 0
        tmplen = 0

        tmpoffset = difflist[0]
        diffinfos = {}        

        while cp <= len(difflist):
            if (cp  +  1) < len(difflist):
                if difflist[cp + 1] == difflist[cp] + 1:
                    tmplen = tmplen + 1
                    cp = cp + 1
                else:
                    cp = cp + 1
                    diffinfos[tmpoffset] = tmplen + 1
                    tmpoffset = difflist[cp]
                    tmplen = 0
            else:
                diffinfos[tmpoffset] = tmplen + 1
                cp = cp + 1
                
        return diffinfos



    def processPageDiff(self, buff1, buff2):
        difflist = self.diffBuffers(buff1, buff2)
        if len(difflist) > 0:
            diffinfos = self.processDiffList(difflist)
            self.whex.hexitem.colorizeDiff(diffinfos)
            self.whex.asciitem.colorizeDiff(diffinfos)
            self.whex2.hexitem.colorizeDiff(diffinfos)
            self.whex2.asciitem.colorizeDiff(diffinfos)
        

    def diffBuffers(self, buff1, buff2):
        cp = 0
        difflist = []

        buff1len = len(buff1)
        buff2len = len(buff2)

        if buff1len != buff2len:
            if buff1len > buff2len:
                masterlen = buff1len
                minorlen = buff2len
            else:
                masterlen = buff2len
                minorlen = buff1len
        else:
            minorlen = buff1len
            masterlen = buff1len

        while cp < minorlen:
            if buff1[cp] != buff2[cp]:
                difflist.append(cp)
            cp = cp + 1

        rangelen = masterlen - minorlen
        l = 0
        while l < rangelen:
            difflist.append(cp)
            cp = cp + 1
            l = l + 1

        return difflist

    def updateCurrents(self, offset):
#        print "update offset : ", offset
        self.currentOffset = offset
        self.currentPage = offset / self.pageSize
        self.currentBlock = offset / (self.pageSize * self.pagesPerBlock)

##########################################
#             READ OPERATIONS            #
##########################################

    def readOffset(self, offset):
        #Transform offset to start of its line
        line = offset / self.bytesPerLine
        readoff = line * self.bytesPerLine

        buffer1 = ""
        if readoff >= 0:
            if readoff < self.file1size:
                try:
                    self.vfile1.seek(readoff)
                    buffer1 = self.vfile1.read(self.pageSize)
                    self.whex.updateItems(offset, buffer1)
                except vfsError,  e:
                    print "Read Offset: I/O error"
            else:
                self.whex.hexitem.dumpEOF()

            buffer2 = ""
            if readoff < self.file2size:
                try:
                    self.vfile2.seek(readoff)
                    buffer2 = self.vfile2.read(self.pageSize)
                    self.whex2.updateItems(offset, buffer2)
                except vfsError,  e:
                    print "Read Offset: I/O error"
            else:
                self.whex2.hexitem.dumpEOF()

            self.processPageDiff(buffer1, buffer2)
            self.updateCurrents(readoff)

