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

from PyQt4.QtGui import *
from PyQt4.QtCore import *

class informations(QWidget):
    def __init__(self, parent):
        QWidget.__init__(self)
        self.init(parent)
        self.initFont()
        self.initShape()

    def init(self, parent):
        self.heditor = parent

    def initFont(self):
        self.font = QFont("Gothic")
        self.font.setFixedPitch(1)
        self.font.setBold(False)
        self.font.setPixelSize(14)

    def initShape(self):
        self.viewLabel = QHBoxLayout()
        self.viewLabel.setContentsMargins(0, 0, 0, 0)
#        self.viewLabel.setSpacing(150)
        self.viewLabel.setAlignment(Qt.AlignLeft)

        self.createOffsetLabel(self.heditor.selection.offset)
        self.createPageLabel(self.heditor.currentPage)
        self.createBlockLabel(self.heditor.currentBlock)
        self.createSelectionLabel()
        self.setLayout(self.viewLabel)

    def createOffsetLabel(self, offset):
        # Offset
        labeltext = "Offset: "
        if self.heditor.decimalview:
            toint = "%.10d"% offset
        else:
            toint = "%.10x"% offset
        labeltext += toint

        self.offsetlabel = QLabel(labeltext)
        self.offsetlabel.setFont(self.font)
        self.viewLabel.addWidget(self.offsetlabel)

    def createPageLabel(self, page):
        #Sector Label
        labeltext = "| Page: "
        if self.heditor.decimalview:
            toint = "%d" % page
        else:
            toint = "%x" % page
        labeltext += toint

        self.pagelabel = QLabel(labeltext)
        self.pagelabel.setFont(self.font)        
        self.viewLabel.addWidget(self.pagelabel)


    def createBlockLabel(self, block):
        #Sector Label
        labeltext = "| Block: "
        if self.heditor.decimalview:
            toint = "%d" % block
        else:
            toint = "%x" % block
        labeltext += toint

        self.blocklabel = QLabel(labeltext)
        self.blocklabel.setFont(self.font)        
        self.viewLabel.addWidget(self.blocklabel)

    def createSelectionLabel(self):
        labeltext = "| Selection: -"
        self.selectlabel = QLabel(labeltext)
        self.selectlabel.setFont(self.font)
        self.viewLabel.addWidget(self.selectlabel)

    def update(self):
        #Update offset
        labeltext = "Offset: "
        if self.heditor.decimalview:
            toint = "%.10d"% self.heditor.selection.offset
        else:
            toint = "0x"
            toint += "%.10x"% self.heditor.selection.offset
        labeltext += toint
        self.offsetlabel.setText(labeltext)

        labeltext = "| Page: "
        if self.heditor.decimalview:
            toint = "%d" % self.heditor.currentPage
        else:
            toint = "0x"
            toint += "%x" % self.heditor.currentPage
        labeltext += toint
        self.pagelabel.setText(labeltext)

        labeltext = "| Block: "
        if self.heditor.decimalview:
            toint = "%d" % self.heditor.currentBlock
        else:
            toint = "0x"
            toint += "%x" % self.heditor.currentBlock
        labeltext += toint

        self.blocklabel.setText(labeltext)

        labeltext = "| Selection: "
        if self.heditor.decimalview:
            toint = "%d" % self.heditor.selection.length
        else:
            toint = "0x"
            toint += "%x" % self.heditor.selection.length
        labeltext += toint
        self.selectlabel.setText(labeltext)
