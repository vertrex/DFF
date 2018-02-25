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
from PyQt4.QtCore import QString, Qt, SIGNAL, QLineF
from PyQt4.QtGui import QWidget, QHBoxLayout, QVBoxLayout, QGroupBox, QGridLayout, QLabel, QLineEdit, QComboBox, QPushButton, QSlider, QTabWidget, QMatrix, QSpinBox

from dff.modules.hexedit.utils import *

class options(QWidget):
    def __init__(self, parent):
        QWidget.__init__(self)
        self.init(parent)
        self.initShape()

    def init(self, parent):
        self.heditor = parent        

    def initShape(self):
        self.vbox = QVBoxLayout()
        self.optab = QTabWidget()

        self.fill = QWidget()

        self.createHexOptions()
#        self.createPageOptions()
        self.createPixelOptions()
        self.vbox.addWidget(self.optab)

        self.createButtons()
        self.vbox.addWidget(self.fill)

        self.setLayout(self.vbox)
        
    def createPageOptions(self):
        self.pagegrid = QGridLayout()
        self.pagegroup = QWidget()
        
        pagelabel = QLabel("Page size : ")
        self.sizeEdit = QFFSpinBox(self)
        self.sizeEdit.setMaximum(self.heditor.filesize)
        self.sizeEdit.setValue(self.heditor.pageSize)
#        psize = QString("%.2d" % self.heditor.pageSize)
#        self.sizeEdit.insert(psize)

        headerlabel = QLabel("Header size : ")
        self.headEdit = QFFSpinBox(self)
        self.headEdit.setMaximum(self.heditor.filesize)
        self.headEdit.setValue(self.heditor.pageHead)
#        phead = QString("%.2d" % self.heditor.pageHead)
#        self.headEdit.insert(phead)

        sparelabel = QLabel("Spare size : ")
        self.spareEdit = QFFSpinBox(self)
        self.spareEdit.setMaximum(self.heditor.filesize)
        self.spareEdit.setValue(self.heditor.pageSpare)
#        pspare = QString("%.2d" % self.heditor.pageSpare)
#        self.spareEdit.insert(pspare)
        
        ppb = QLabel("Pages per block:")
        self.pagesperblock = QComboBox()
        self.pagesperblock.addItem("8")
        self.pagesperblock.addItem("16")
        self.pagesperblock.addItem("32")
        self.pagesperblock.addItem("64")
        self.pagesperblock.addItem("128")
        self.pagesperblock.addItem("256")
        self.pagesperblock.addItem("512")
        self.pagesperblock.setCurrentIndex(2)

        lview = QLabel("Left indication: ")
        self.indic = QComboBox()
        self.indic.addItem("Offset")
        self.indic.addItem("Block")

#        self.pagesperlineEdit = QLineEdit()
#        ppl = QString("%.2d" % self.heditor.pagesPerBlock)
#        self.pagesperlineEdit.insert(ppl)

        self.pagegrid.addWidget(pagelabel, 0, 0)
        self.pagegrid.addWidget(self.sizeEdit, 0, 1)

        self.pagegrid.addWidget(headerlabel, 1, 0)
        self.pagegrid.addWidget(self.headEdit, 1, 1)

        self.pagegrid.addWidget(sparelabel, 2, 0)
        self.pagegrid.addWidget(self.spareEdit, 2, 1)

        self.pagegrid.addWidget(ppb, 3 ,0)
        self.pagegrid.addWidget(self.pagesperblock, 3, 1)

        self.pagegrid.addWidget(lview, 4, 0)
        self.pagegrid.addWidget(self.indic, 4, 1)

        self.pagegrid.addWidget(self.fill, 5, 0)
        self.pagegrid.setRowStretch(5, 1)
#        self.pagegrid.addWidget(self.fill, 6, 0)

#        self.pagegrid.addWidget(pagesperline, 6, 0)
#        self.pagegrid.addWidget(self.pagesperlineEdit, 7, 0)

        self.pagegroup.setLayout(self.pagegrid)
        self.vvbox.addWidget(self.pagegroup)

#        self.optab.insertTab(1, self.pagegroup, "Pages" )

#        self.vbox.addWidget(self.pagegroup)

    def createHexOptions(self):
        self.vvbox = QVBoxLayout()
        self.vcontainer = QWidget()

        self.hexgroup = QWidget()

        self.hexgrid = QGridLayout()

        groupebylabel = QLabel("Groupe by:")
        self.groupeby = QComboBox()
        self.groupeby.addItem("1")
        self.groupeby.addItem("2")
        self.groupeby.addItem("4")

        offsetlabel = QLabel("Offset as")
        self.offsetas = QComboBox()
        self.offsetas.addItem("Hexadecimal")
        self.offsetas.addItem("Decimal")


#        self.hexgrid.addWidget(groupebylabel, 0, 0)
#        self.hexgrid.addWidget(self.groupeby, 1, 0)
        self.hexgrid.addWidget(offsetlabel, 0, 0)
        self.hexgrid.addWidget(self.offsetas, 0, 1)
#        self.hexgrid.addWidget(self.fill, 2, 0)
#        self.hexgrid.setRowStretch(2, 1)

        self.hexgroup.setLayout(self.hexgrid)
        
        self.vvbox.addWidget(self.hexgroup)

        self.createPageOptions()

        self.vcontainer.setLayout(self.vvbox)

        self.optab.insertTab(0, self.vcontainer, "General")

#        self.vbox.addWidget(self.hexgroup)

        #Offset as decimal / hexadecimal

    def createPixelOptions(self):
        self.pixgroup = QWidget()

        self.pixgrid = QGridLayout()

        formatlabel = QLabel("Format :")
        self.format = QComboBox()
        self.format.addItem("RGB")
        self.format.addItem("Alpha RGB")
        self.format.addItem("Indexed 8bit")
        self.format.addItem("Mono")
        self.connect(self.format, SIGNAL("currentIndexChanged(const QString)"), self.formatChanged)

        colorlabel = QLabel("Indexed Color :")
        self.icolor = QComboBox()
        self.icolor.addItem("Green")
        self.icolor.addItem("Red")
        self.icolor.addItem("Blue")
        self.icolor.addItem("Ascii")
        self.icolor.addItem("256")
        self.icolor.setEnabled(False)


        slidelabel = QLabel("Resolution : ")

        self.sliderspin = QSpinBox(self)
        self.sliderspin.setMinimum(64)
        self.sliderspin.setMaximum(1024)
        self.sliderspin.setValue(self.heditor.wpixel.view.w)
        self.connect(self.sliderspin, SIGNAL("valueChanged(int)"), self.slidermoved)

        self.slider = QSlider(Qt.Horizontal)
        self.slider.setMinimum(64)
        self.slider.setMaximum(1024)
        self.slider.setValue(self.heditor.wpixel.view.w)
        self.slider.setSingleStep(1)

        self.zoomlabel = QLabel("Scale factor : 1")
        self.zoom = QSlider(Qt.Horizontal)
        self.zoom.setMinimum(1)
        self.zoom.setMaximum(5)
        self.zoom.setValue(1)
        self.zoom.setSingleStep(1)
        self.zoom.setTickInterval(1)
        self.zoom.setTickPosition(QSlider.TicksBelow)

        self.connect(self.slider, SIGNAL("sliderMoved(int)"), self.slidermoved)
        self.connect(self.zoom, SIGNAL("sliderMoved(int)"), self.scale)

        self.pixgrid.addWidget(formatlabel, 0, 0)
        self.pixgrid.addWidget(self.format, 0, 1)
        self.pixgrid.addWidget(colorlabel, 1, 0)
        self.pixgrid.addWidget(self.icolor, 1, 1)

        self.pixgrid.addWidget(slidelabel, 2, 0)
        self.pixgrid.addWidget(self.sliderspin, 2, 1, Qt.AlignLeft)

        self.pixgrid.addWidget(self.slider, 3, 0)
        self.pixgrid.addWidget(self.zoomlabel, 4, 0, Qt.AlignLeft)
        self.pixgrid.addWidget(self.zoom, 5, 0)

        self.pixgrid.addWidget(self.fill, 6, 0)
        self.pixgrid.setRowStretch(6, 1)

        self.pixgroup.setLayout(self.pixgrid)

        self.optab.insertTab(1, self.pixgroup, "Pixel")

    def setSliderLabel(self, value):
        cvalue = QString()
        cvalue = "%2.d" % value
        self.sliderlabel.setText(cvalue)
    
    def setZoomLabel(self, value):
        zvalue = QString("Scale factor : ")
        zvalue += "%2.d" % value
        self.zoomlabel.setText(zvalue)


    def createButtons(self):
        self.applyB = QPushButton("Apply")
        self.connect(self.applyB, SIGNAL('clicked()'), self.apply)



        self.vbox.addWidget(self.applyB)

    def checkValue(self, value):
        try:
            n = int(value)
            return n
        except ValueError:
            return -1

    def apply(self):
        #PAGE CHECK
        pagesize = self.sizeEdit.value()
        headsize = self.headEdit.value()
        sparesize = self.spareEdit.value()
        pagesperblock = self.checkValue(self.pagesperblock.currentText())

        if (pagesize < 0) or (headsize < 0) or (sparesize < 0) or (pagesperblock < 0):
            print "Wrong values"
        else:
            offas = self.offsetas.currentText()
            if offas == "Decimal":
                self.heditor.decimalview = True
            elif offas == "Hexadecimal":
                self.heditor.decimalview = False
            #Hexview refresh
            self.heditor.readOffset(self.heditor.currentOffset)
            #Pageview refresh
            if self.indic.currentText() == "Offset":
                self.heditor.pageOffView = True
            else:
                self.heditor.pageOffView = False

            self.heditor.refreshPageValues(headsize, pagesize, sparesize, pagesperblock)
            if self.heditor.wpage.scroll:
                self.heditor.wpage.scroll.refreshValues(self.heditor.pagesPerBlock, self.heditor.pageSize)
            self.heditor.wpage.view.refreshAllContent()
            #PageView scrollbar refres
            #Pixel View refresh
            format = self.format.currentText()
            if format == "Indexed 8bit":
                self.heditor.wpixel.view.format = 0
            elif format == "Mono":
                self.heditor.wpixel.view.format = 1
            elif format == "RGB":
                self.heditor.wpixel.view.format = 2
            elif format == "Alpha RGB":
                self.heditor.wpixel.view.format = 3

            if self.heditor.wpixel.scroll:
                self.heditor.wpixel.scroll.refreshValues()
            #Color
            icolor = self.icolor.currentText()
            if icolor == "Red":
                self.heditor.wpixel.view.icolor = 0
            elif icolor == "Green":
                self.heditor.wpixel.view.icolor = 1
            elif icolor == "Blue":
                self.heditor.wpixel.view.icolor = 2
            elif icolor == "Ascii":
                self.heditor.wpixel.view.icolor = 3
            elif icolor == "256":
                self.heditor.wpixel.view.icolor = 4

            pixoffset = self.heditor.wpixel.view.currentOffset
            self.heditor.wpixel.view.read_image(pixoffset)

    def slidermoved(self, value):       
        pixoffset = self.heditor.wpixel.view.currentOffset
        self.heditor.wpixel.view.w = value
        self.sliderspin.setValue(value)
#        self.setSliderLabel(value)
        self.heditor.wpixel.view.read_image(pixoffset)
        if self.heditor.wpixel.scroll:
            self.heditor.wpixel.scroll.refreshValues()
#        print value

    def scale(self, value):
        self.setZoomLabel(value)
        self.heditor.wpixel.view.scale = value
        pixoffset = self.heditor.wpixel.view.currentOffset
        self.heditor.wpixel.view.read_image(pixoffset)


    def formatChanged(self, format):
        if format == "Indexed 8bit":
            self.icolor.setEnabled(True)
        else:
            self.icolor.setEnabled(False)


    def keyPressEvent(self, kEvent):
        key = kEvent.key()
        if key == Qt.Key_Return or key == Qt.Key_Enter:
            self.apply()

#            self.heditor.wpixel.view.format = 0
#        elif format == "Mono":
#            self.heditor.wpixel.view.format = 1
#        elif format == "RGB":
#            self.heditor.wpixel.view.format = 2
#        elif format == "Alpha RGB":
#            self.heditor.wpixel.view.format = 3
