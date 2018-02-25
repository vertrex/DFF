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
import struct
import binascii

from PyQt4.QtGui import *
from PyQt4.QtCore import *

from dff.api.exceptions.libexceptions import *

class decodeValues(QWidget):
    def __init__(self,  parent):
        QWidget.__init__(self)
        self.heditor = parent
        self.selection = self.heditor.selection

        self.layout = QVBoxLayout()
        self.createShape()

        self.layout.addWidget(self.decodeTree)
        self.setLayout(self.layout)

    def createShape(self):
        self.createTreeWidget()
        self.setTreeTypes()

    def createTreeWidget(self):
        self.decodeTree = QTreeWidget()
        self.decodeTree.setColumnCount(2)
        
        headerLabels = [QApplication.translate("decodeValues", "Type", None, QApplication.UnicodeUTF8),
                       QApplication.translate("decodeValues", "Value", None, QApplication.UnicodeUTF8)]
        
        self.decodeTree.setHeaderLabels(headerLabels)
        self.decodeTree.setAlternatingRowColors(True)
        
    def setTreeTypes(self):
        self.byte = QTreeWidgetItem(self.decodeTree)
        self.byte.setText(0, "char8")
        self.ubyte = QTreeWidgetItem(self.decodeTree)
        self.ubyte.setText(0, "u_char8")
        self.short = QTreeWidgetItem(self.decodeTree)
        self.short.setText(0, "short16")
        self.ushort = QTreeWidgetItem(self.decodeTree)
        self.ushort.setText(0, "u_short16")
        self.int = QTreeWidgetItem(self.decodeTree)
        self.int.setText(0, "int32")
        self.uint = QTreeWidgetItem(self.decodeTree)
        self.uint.setText(0, "u_int32")

        self.long = QTreeWidgetItem(self.decodeTree)
        self.long.setText(0, "long64")
        self.ulong = QTreeWidgetItem(self.decodeTree)
        self.ulong.setText(0, "u_long64")

        self.binary = QTreeWidgetItem(self.decodeTree)
        self.binary.setText(0, "binary")
        self.hex = QTreeWidgetItem(self.decodeTree)
        self.hex.setText(0, "hexadecimal")

    def update(self):
        char = self.readConvers(1)
        short = self.readConvers(2)
        int = self.readConvers(4)
        long = self.readConvers(8)

        if char != -1:
            bchar = struct.unpack('b',  char)
            charedit = "%.0d" % bchar
            self.byte.setText(1, charedit)

            bchar = struct.unpack('B', char)
            charedit = "0x"
            charedit += "%.0X" % bchar
            self.ubyte.setText(1, charedit)
        
        if short != -1:
            bshort = struct.unpack('h',  short)
            shortedit = "%.0d" % bshort
            self.short.setText(1, shortedit)

            bshort = struct.unpack('H',  short)
            shortedit = "0x"
            shortedit += "%.0X" % bshort
            self.ushort.setText(1, shortedit)

        if int != -1:
            bint = struct.unpack('i',  int)
            intedit = "%.0d" % bint
            self.int.setText(1, intedit)

            bint = struct.unpack('I',  int)
            intedit = "0x"
            intedit += "%.0X" % bint
            self.uint.setText(1, intedit)

        if long != -1:
            blong = struct.unpack('q',  long)
            longedit = "%.0d" % blong
            self.long.setText(1, longedit)

            blong = struct.unpack('Q',  long)
            longedit = "0x"
            longedit += "%.0X" % blong
            self.ulong.setText(1, longedit)
                
        if char != -1:
            bin = self.byte_to_bits_string(bchar[0])
            hexa = "%.2X" % bchar[0]

            self.binary.setText(1, bin)
            self.hex.setText(1, hexa)

    def byte_to_bits_string(self, x):
      return "".join(map(lambda y:str((x>>y)&1), range(7, -1, -1)))

    def readConvers(self,  size):
        try:
            offset = self.selection.offset
            if offset + size < self.heditor.filesize:
                self.heditor.file.seek(offset)
                buff = self.heditor.file.read(size)
                return buff
            else:
                return -1
        except vfsError,  e:
            print "error Conversion read"
