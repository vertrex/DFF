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
import time

from PyQt4.QtCore import QString, Qt
from PyQt4.QtGui import QTextEdit, QFont, QTextDocument, QBrush, QColor, QTextCharFormat, QTextTable, QTextTableFormat

from cursor import *

#TODO

#Pour la visualisation et son organisation: |offset = widget| hexview = QTextEdit | Ascii QTextEdit ou QGraphics ou Gimp view



class textItem(QTextEdit):
    def __init__(self, parent):
        QTextEdit.__init__(self)
        self.initValues(parent)
        self.initFont()
#        self.initColors()
#        self.initTab()


    def initTab(self):
        cursor = self.textCursor()
#        self.tableformat = QTextTableFormat()
        self.table = cursor.insertTable(1, 3)
        self.printOffset(0)

#        print self.table.rows()


    def initValues(self, parent):
        self.heditor = parent
        #Buffer
        self.buffer = []
        self.bufferLines = 0 
        #Line
        self.currentLine = 0
        #Offset
        self.startOffset = 0

        self.row = {}
        self.line = []

#        self.setAcceptsHoverEvents(True)

        self.document = QTextDocument()
        self.setDocument(self.document)

        self.cursor = self.textCursor()
#        self.setTextCursor(self.cursor)


    def initFont(self):
        #Font
        self.font = QFont("Courier")
        self.font.setFixedPitch(1)
        self.font.setBold(False)
        self.font.setPixelSize(14)
        self.setCurrentFont(self.font)
        #Cursor

    #Just after new read
    def formatBuffer(self, buff, offset):
        t = time.time()
        self.startOffset = offset

        del self.buffer
        pos = str(len(buff)) + 'B'
        self.buffer = struct.unpack(pos, buff)        
        self.bufferLines = len(self.buffer) / 16
#        for index in block:
#            byte = "%.2x" % index
#            if count < 15:
#                byte += " "
#                count += 1
#            else:
#                byte += "\n"
#                count = 0
#            self.buffer.append(byte)
        print time.time() - t

    def printLine(self, line, offset):
        count = 0
        start = line * 16
        dline = self.buffer[start:start+16]
        #Print Offset
        self.setTextColor(Qt.black)

        cell = self.table.cellAt(0,1)
        cellCursor = cell.firstCursorPosition()

        cellCursor.insertText(" | ")
        for byte in dline:            
            if count % 2 == 0:
                self.setTextColor(Qt.black)
                cellCursor.insertText("%.2x" % byte)
            else:
                self.setTextColor(Qt.blue)
                cellCursor.insertText("%.2x" % byte)
            cellCursor.insertText(" ")
            count += 1
#            print count
        self.setTextColor(Qt.black)
        cellCursor.insertText("| ")
        #self.printAscii(dline)

        cellCursor.insertText("\n")

#        print self.buffer
#        self.setPlainText(self.buffer)
#        self.colorizeText()

    def printOffset(self, offset):
        self.setCurrentFont(self.font)
        self.setTextColor(Qt.red)
        cell = self.table.cellAt(0,0)
        cellCursor = cell.firstCursorPosition()
#        cursor = self.table.cellAt(0, 0).firstCursorPosition()
        cellCursor.insertText("%.10d" % offset)

    def printAscii(self, line):
        for char in line:
            if str(char) in string.printable:
                self.insertPlainText(str(char))
            else:
                self.insertPlainText(".")

    def printBuffer(self):
        t = time.time()
        #Clean text
        self.moveCursor(QTextCursor.Start)
        self.moveCursor(QTextCursor.End, QTextCursor.KeepAnchor)

        self.setCurrentFont(self.font)

        offset = self.startOffset
#        self.printOffset(offset)

        l = self.currentLine
        while l < self.bufferLines:
            self.printLine(l, offset)
            l += 1
            offset += 16
        
        print "E"
        self.moveCursor(QTextCursor.Start)
        print time.time() - t


    def initColors(self):
        #Blue Color
        self.blue = QBrush(QColor(Qt.blue))
        self.blueFormat = QTextCharFormat()
        self.blueFormat.setFont(self.font)
        self.blueFormat.setForeground(self.blue)

    def colorizeText(self):
        self.size = self.buffer.size()
        cur = self.textCursor()
        pos = cur.position()
#        self.moveCursor(QTextCursor.Start)
        while pos < self.size:
            self.moveCursor(QTextCursor.NextWord)
            self.moveCursor(QTextCursor.EndOfWord, QTextCursor.KeepAnchor)
        
            cur = self.textCursor()
#            self.setTextColor(QColor(Qt.blue))
            cur.setCharFormat(self.blueFormat)

            self.moveCursor(QTextCursor.NextWord)

            cur = self.textCursor()
            pos = cur.position()
#            print pos

        self.moveCursor(QTextCursor.Start)
#
#            self.moveCursor(QTextCursor.NextWord)
#            self.moveCursor(QTextCursor.EndOfWord, QTextCursor.KeepAnchor)
#            self.setTextColor(QColor(Qt.blue))

#        print self.cursor.position()
#        self.setCurrentCharFormat(self.blueFormat)
        
            
            

        
