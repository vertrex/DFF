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
#  Frederic B. <fba@digital-forensic.org>
import string
import time

from PyQt4.QtGui import QWidget, QGroupBox, QGridLayout, QLabel, QComboBox, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem, QIcon, QMessageBox, QHBoxLayout, QCheckBox
from PyQt4.Qt import SIGNAL

from dff.modules.carver.utils import QSpinBox

from process import CarvingProcess

class PatternsTable(QWidget):
    def __init__(self):
        QWidget.__init__(self)
        self.grid = QGridLayout()
        self.setLayout(self.grid)
        self.patternArea()
        self.patternTable()

    def createPattern(self, name, x):
        label = name.lower() + "Label"
        type = name.lower() + "Type"
        entry = name.lower() + "Entry"
        setattr(self, label, QLabel(name))
        setattr(self, entry, QLineEdit())
        setattr(self, type, QComboBox())
        labelobj = getattr(self, label)
        typeobj = getattr(self, type)
        entryobj = getattr(self, entry)
        typeobj.addItem("Hexadecimal")
        typeobj.addItem("String")
        self.grid.addWidget(labelobj, x, 0)
        self.grid.addWidget(entryobj, x, 1)
        self.grid.addWidget(typeobj, x, 2)


    def patternArea(self):
        self.filetypeLabel = QLabel("File type")
        self.filetype = QLineEdit()
        self.alignedLabel = QLabel("block aligned")
        self.aligned = QCheckBox()
        self.windowLabel = QLabel("Window size")
        self.window = QSpinBox()
        self.window.setSuffix(" bytes")
        self.window.setRange(0, 2500000)
        self.window.setSingleStep(100)
        self.addEntry = QPushButton("add")
        self.connect(self.addEntry, SIGNAL("clicked()"), self.insertPattern)
        self.grid.addWidget(self.filetypeLabel, 0, 0)
        self.grid.addWidget(self.filetype, 0, 1, 1, 2)
        self.createPattern("Header", 2)
        self.createPattern("Footer", 3)
        self.grid.addWidget(self.windowLabel, 4, 0)
        self.grid.addWidget(self.window, 4, 1)
        self.grid.addWidget(self.alignedLabel, 5, 0)
        self.grid.addWidget(self.aligned, 5, 1)
        self.grid.addWidget(self.addEntry, 6, 1)


    def patternTable(self):
        self.patterns = QTableWidget()
        self.patterns.setShowGrid(False)
        self.patterns.setColumnCount(5)
        self.patterns.setHorizontalHeaderLabels(["Filetype", "Header", "Footer", "Window", "Block aligned"])
        self.patterns.horizontalHeader().setStretchLastSection(True)
        self.connect(self.patterns.verticalHeader(), SIGNAL("sectionClicked(int)"), self.patterns.removeRow)
        self.grid.addWidget(self.patterns, 7, 0, 1, 3)
        

    def warning(self, msg):
        msgBox = QMessageBox(self)
        msgBox.setText(msg)
        msgBox.setIcon(QMessageBox.Warning)
        msgBox.exec_()

    def validate(self, **kwargs):
        msg = ""

        if len(kwargs["type"]) == 0:
            msg = "Type must be defined"
        else:
            for i in kwargs["type"]:
                if i not in string.letters:
                    msg = "Type's characters must be in the following set\n\n" + string.letters
                    break
            rowCount = self.patterns.rowCount()
            for row in range(0, rowCount):
                if str(self.patterns.item(row, 0).text()) == kwargs["type"]:
                    msg = "Type <" + kwargs["type"] + " > already defined"
        if msg != "":
            self.warning(msg)
            return False

        if kwargs["headerType"] == "Hexadecimal" and not self.isHex(kwargs["header"]):
            msg = "Header must be an even number of chars"
            self.warning(msg)
            return False
        
        if len(kwargs["header"]) == 0:
            msg = "Header must be provided"
            self.warning(msg)
            return False

        if kwargs["footerType"] == "Hexadecimal" and not self.isHex(kwargs["footer"]):
            msg = "Footer must be an even number of chars"
            self.warning(msg)
            return False

        if kwargs["window"] <= 0:
            msg = "Window size must be greater than 0"
            self.warning(msg)
            return False

        return True


    def insertPattern(self):
        filetype = str(self.filetype.text())
        header = str(self.headerEntry.text())
        headerType = str(self.headerType.currentText())
        footer = str(self.footerEntry.text())
        footerType = str(self.footerType.currentText())
        window = self.window.text()
        aligned = self.aligned.isChecked()

        #Validate most of provided items
        kwargs = {"type": filetype, "header": header, "headerType": headerType, 
                  "footer": footer, "footerType": footerType, "window": int(window.replace(" bytes", ""))}
        if not self.validate(**kwargs):
            return

        filetypeItem = QTableWidgetItem(filetype)
        headerItem = QTableWidgetItem(header + " (" + headerType[0:3] + ")")
        footerItem = QTableWidgetItem(footer + " (" + footerType[0:3] + ")")
        windowItem = QTableWidgetItem(window)
        alignedItem = QTableWidgetItem(str(aligned))
        self.patterns.insertRow(self.patterns.rowCount())
        vertHeader = QTableWidgetItem(QIcon(":closetab.png"), "")
        row = self.patterns.rowCount() - 1
        self.patterns.setVerticalHeaderItem(row, vertHeader)
        self.patterns.setItem(row, 0, filetypeItem)
        self.patterns.setItem(row, 1, headerItem)
        self.patterns.setItem(row, 2, footerItem)
        self.patterns.setItem(row, 3, windowItem)
        self.patterns.setItem(row, 4, alignedItem)
        self.patterns.resizeRowToContents(row)

        
    def isHex(self, hstr):
        HEXCHAR = "0123456789abcdefABCDEF"
        if len(hstr) % 2 != 0:
            return False
        even = False
        for i in range(len(hstr)):
            if hstr[i] not in HEXCHAR:
                return False
        return True
    

    def toHex(self, str):
        HEXCHAR = "0123456789abcdefABCDEF"
        hexStr = ""
        evenhex = ""
        for i in range(len(str)):
            if str[i] in HEXCHAR:
                if len(evenhex) == 1:
                    hexStr += chr(int(evenhex+str[i], 16))
                    evenhex = ""
                else:
                    evenhex = str[i]
            else:
                raise ValueError, "argument 'str' contains not valid characters"
        if len(evenhex) != 0:
            raise ValueError, "argument 'str' must be an even number of char"
        return hexStr


    def textToPattern(self, text):
        idx = text.find("(")
        pattern = ""
        if idx != -1:
            type = text[idx+1:idx+4]
            pattern = text[0:idx-1]
            if type == "Hex":
                pattern = self.toHex(pattern)
        return pattern


    def selectedItems(self):
        selected = {}
        rowCount = self.patterns.rowCount()
        for row in range(0, rowCount):
            filetype = str(self.patterns.item(row, 0).text())
            selected[filetype] = []
            pattern = []
            pattern.append(self.textToPattern(str(self.patterns.item(row, 1).text())))
            pattern.append(self.textToPattern(str(self.patterns.item(row, 2).text())))
            pattern.append(int(self.patterns.item(row, 3).text().replace(" bytes", "")))
            selected[filetype].append([pattern])
            if self.patterns.item(row, 4).text() == "True":
                selected[filetype].append(True)
            else:
                selected[filetype].append(False)
        return selected


class UserPatterns(QWidget):
    def __init__(self, vnode):
        QWidget.__init__(self)
        self.baseLayout = QHBoxLayout(self)
        self.table = PatternsTable()
        self.cprocess = CarvingProcess(self.table, vnode)
        self.baseLayout.addWidget(self.table)
        self.baseLayout.addWidget(self.cprocess)
