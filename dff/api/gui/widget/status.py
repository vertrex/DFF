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
#  Frederic Baguelin <fba@digital-forensic.org>

from dff.api.gui.widget.linklabel import LinkLabel
from dff.api.vfs.libvfs import ABSOLUTE_ATTR_NAME

from PyQt4 import QtGui
from PyQt4.QtGui import QWidget, QSizePolicy, QLayout, QHBoxLayout, QSplitter, QLabel, QFrame
from PyQt4.QtCore import Qt, SIGNAL, QString


class StatusLabel(QLabel):
    def __init__(self, parent, model):
        super(QLabel, self).__init__(parent)
        self.__model = model
        self.setTextInteractionFlags(Qt.LinksAccessibleByMouse|Qt.TextSelectableByMouse)
        self.connect(self.__model, SIGNAL("updateStatus"), self.updateLabel)
        sizePolicy = QSizePolicy(QSizePolicy.Minimum, QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        self.setSizePolicy(sizePolicy)
        self.setTextFormat(Qt.RichText)

    def updateLabel(self):
        fmt = self.__model.format()
        styles = self.__model.styles()
        data = self.__model.data()
        fmtdata = {}
        head = "<style>"
        for style in styles.iterkeys():
            head += str(style) + "{" + str(styles[style]) + "}"
        head += "</style>"
        for key in data.iterkeys():
            value = data[key]
            if styles.has_key(key):
                fmtdata[key] = "<" + key + ">" + str(value) + "</" + key + ">"
            else:
                fmtdata[key] = value
        self.setText(head + fmt.format(**fmtdata))


class StatusWidget(QWidget):
    def __init__(self, parent=None):
        super(QWidget, self).__init__(parent)
        sizePolicy = QSizePolicy(QSizePolicy.Minimum, QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(1)
        sizePolicy.setVerticalStretch(0)
        self.setSizePolicy(sizePolicy)
        self.__hlayout = QHBoxLayout(self)
        self.__hlayout.setSpacing(6)
        self.__hlayout.setSizeConstraint(QLayout.SetMinimumSize)
        self.__hlayout.setMargin(0)
        self.__hlayout.setAlignment(Qt.AlignLeft)
        self.__labels = []
        self.__model = None

    def setStatusModel(self, model):
        self.__model = model
        for idx in xrange(0, model.count()):
            label = StatusLabel(self, model.status(idx))
            self.__hlayout.addWidget(label)
            if idx < model.count()-1:
                line = QFrame(self)
                line.setFrameShape(QFrame.VLine)
                line.setFrameShadow(QFrame.Sunken)
                self.__hlayout.addWidget(line)
            self.__labels.append(label)


class StatusBarWidget(QWidget):
    SplitterHandleStyle = """QSplitter::handle:horizontal {background: 
    qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #eee, stop:1 #ccc);
    border: 1px solid #777; width: 14px; margin-right: 4px; margin-left: 4px;}"""
    def __init__(self, parent = None):
        super(QWidget, self).__init__(parent)
        sizePolicy = QSizePolicy(QSizePolicy.Minimum, QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(1)
        sizePolicy.setVerticalStretch(1)
        self.setSizePolicy(sizePolicy)
        self.__hlayout = QHBoxLayout(self)
        self.__hlayout.setSpacing(6)
        self.__hlayout.setSizeConstraint(QLayout.SetMinimumSize)
        self.__hlayout.setMargin(0)
        self.__splitter = QSplitter(Qt.Horizontal, parent)
        self.__splitter.setHandleWidth(12)
        self.__hlayout.addWidget(self.__splitter)

    def addStatusWidget(self, widget, stretch):
        self.__splitter.setStyleSheet(StatusBarWidget.SplitterHandleStyle)
        self.__splitter.addWidget(widget)
        idx = self.__splitter.indexOf(widget)
        self.__splitter.setStretchFactor(idx, stretch)
