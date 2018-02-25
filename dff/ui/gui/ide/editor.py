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
#  Jeremy Mounier <jmo@digital-forensic.org>
# 
from PyQt4.QtGui import QPlainTextEdit, QTextEdit, QColor, QTextFormat, QPainter,  QWidget, QFont, QTextCursor
from PyQt4.QtCore import Qt, SIGNAL, QRect, QChar, QString, QSize

from dff.ui.gui.ide.highlighter import pythonHighlighter

class codeEditor(QPlainTextEdit):
    def __init__(self, buff=None, parent=None):
        super(codeEditor, self).__init__(parent)

        self.setTabStopWidth(20)
        self.lineNumberArea = LineNumberArea(self)
        self.configureFont()
        self.connect(self, SIGNAL("blockCountChanged(int)"), self.updateLineNumberAreaWidth)
        self.connect(self, SIGNAL("updateRequest(const QRect, int)"), self.updateLineNumberArea)
        self.connect(self, SIGNAL("cursorPositionChanged()"), self.highlightCurrentLine)
        self.updateLineNumberAreaWidth(0)

        self.highlighter = pythonHighlighter(self.document())

        self.selectionStart = 0
        self.selectionEnd = 0

        self.highlightCurrentLine()

        self.__name = QString("")
        self.__scriptPath = QString("") 

        if buff != None:
            self.setPlainText(buff)

    def configureFont(self):
        font = QFont()
        font.setFamily('Helvetica')
        font.setFixedPitch(True)
        font.setPointSize(11)
        self.setFont(font)


    def lineNumberAreaWidth(self):
        digits = 1
        mmax = max(1, self.blockCount())
        while (mmax >= 10):
            mmax /= 10
            digits += 1
        space = 3 + self.fontMetrics().width(QChar('9')) * digits
        return space

    def updateLineNumberAreaWidth(self, blockCount):
        self.setViewportMargins(self.lineNumberAreaWidth(), 0, 0, 0)

    def updateLineNumberArea(self, rect, dy):
        if (dy):
            self.lineNumberArea.scroll(0, dy)
        else:
            self.lineNumberArea.update(0, rect.y(), self.lineNumberArea.width(), rect.height())
        if rect.contains(self.viewport().rect()): 
            self.updateLineNumberAreaWidth(0)

    def resizeEvent(self, event):
        QPlainTextEdit.resizeEvent(self, event)
        cr = self.contentsRect()
        self.lineNumberArea.setGeometry(QRect(cr.left(), cr.top(), self.lineNumberAreaWidth(), cr.height()))

    def highlightCurrentLine(self):
        selections = []
        if (not self.isReadOnly()):
            selection = QTextEdit.ExtraSelection()

        lineColor = QColor(240,240,240)
        selection.format.setBackground(lineColor)
        selection.format.setProperty(QTextFormat.FullWidthSelection, True)
        selection.cursor = self.textCursor()
        selection.cursor.clearSelection()
        selections.append(selection)
        self.setExtraSelections(selections)

    def lineNumberAreaPaintEvent(self, event):
        painter = QPainter(self.lineNumberArea)
        painter.fillRect(event.rect(), Qt.lightGray)

        block = self.firstVisibleBlock()
        blockNumber = block.blockNumber()
        top =  self.blockBoundingGeometry(block).translated(self.contentOffset()).top()
        bottom = top +  self.blockBoundingRect(block).height()

        while (block.isValid() and top <= event.rect().bottom()):
            if (block.isVisible() and bottom >= event.rect().top()):
                number = QString.number(blockNumber + 1)
                painter.setPen(Qt.black)
                painter.drawText(0, top, self.lineNumberArea.width(), self.fontMetrics().height(),
                                 Qt.AlignRight, number)

            block = block.next()
            top = bottom
            bottom = top + self.blockBoundingRect(block).height()
            blockNumber += 1

    def setName(self,  name):
        self.__name = name
        
    def getName(self):
        if self.__name:
            return self.__name
        else:
            return None

    def setScriptPath(self,  path):
        self.__scriptPath = path
        
    def getScriptPath(self):
        if self.__scriptPath:
            return self.__scriptPath
        else:
            return "error"

    def comment(self):
        cursor = self.textCursor()
        start = min([cursor.selectionStart(), cursor.selectionEnd()])
        end = max([cursor.selectionStart(), cursor.selectionEnd()])
        cursor.beginEditBlock()
        cursor.setPosition(start)
        while cursor.position() <= end:
            cursor.movePosition(QTextCursor.StartOfLine)
            cursor.setPosition(cursor.position() + 1, QTextCursor.KeepAnchor)
            if cursor.selectedText() != "#":
                cursor.movePosition(QTextCursor.StartOfLine)
                cursor.insertText("#")
            if not cursor.movePosition(QTextCursor.NextBlock):
                cursor.movePosition(QTextCursor.EndOfLine)
                break
        cursor.endEditBlock()

    def uncomment(self):
        cursor = self.textCursor()
        start = min([cursor.selectionStart(), cursor.selectionEnd()])
        end = max([cursor.selectionStart(), cursor.selectionEnd()])
        cursor.beginEditBlock()
        cursor.setPosition(start)
        while cursor.position() <= end:
            cursor.movePosition(QTextCursor.StartOfLine)
            cursor.setPosition(cursor.position() + 1, QTextCursor.KeepAnchor)
            if cursor.selectedText() == "#":
                cursor.removeSelectedText()
            if not cursor.movePosition(QTextCursor.NextBlock):
                cursor.movePosition(QTextCursor.EndOfLine)
                break
        cursor.endEditBlock()


class LineNumberArea(QWidget):
    def __init__(self, codeEditor):
        super(LineNumberArea, self).__init__(codeEditor)
        self.codeEditor = codeEditor

    def sizeHint(self):
        return QSize(self.codeEditor.lineNumberAreaWidth(), 0)

    def paintEvent(self, event):
        self.codeEditor.lineNumberAreaPaintEvent(event)


