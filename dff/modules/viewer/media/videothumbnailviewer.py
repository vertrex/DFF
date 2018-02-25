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
#  Solal Jacob <sja@digital-forensic.org>
# 

__dff_module_viewerimage_version__ = "1.0.0"

from PyQt4 import QtCore, QtGui
from PyQt4.QtCore import Qt, QSize, QString, SIGNAL, QThread, QSize, QRect
from PyQt4.QtGui import QPixmap, QImage, QPushButton, QLabel, QWidget, QHBoxLayout, QVBoxLayout, QScrollArea, QIcon, QMatrix, QToolBar, QAction, QSizePolicy, QTabWidget, QTableWidget, QTableWidgetItem, QAbstractItemView, QLineEdit, QIntValidator, QFormLayout, QApplication, QCursor, QMenu, QRubberBand

from dff.api.vfs import vfs 
from dff.api.module.module import Module 
from dff.api.module.script import Script
from dff.api.types.libtypes import Argument, typeId

from dff.api.gui.thumbnail import Thumbnailer

class CopyMenu(QMenu):
  def __init__(self, parent):
     QMenu.__init__(self, parent)
     action = self.addAction(self.tr("copy"))
     self.connect(action, SIGNAL("triggered()"), parent.copyPixmapToClipboard)

class CopySelectionMenu(QMenu):
  def __init__(self, parent):
     QMenu.__init__(self, parent)
     action = self.addAction(self.tr("copy selection"))
     self.connect(action, SIGNAL("triggered()"), parent.copySelectionToClipboard)
     action = self.addAction(self.tr("copy entire image"))
     self.connect(action, SIGNAL("triggered()"), parent.copyPixmapToClipboard)

class ThumbnailVideoView(QWidget, Script):
  IconSize = 256
  Frames = 10
  def __init__(self):
    Script.__init__(self, "thumbnailvideo")
    self.icon = None
    self.vfs = vfs.vfs()

  def start(self, args):
    try :
      self.preview = args["preview"].value()
    except IndexError:
      self.preview = False
    try:
      self.node = args["file"].value()
    except KeyError:
      pass

  def g_display(self):
    QWidget.__init__(self)
    self.copyMenu = CopyMenu(self)
    self.copySelectionMenu = CopySelectionMenu(self)
    self.rubberBand = None
    self.hlayout = QVBoxLayout()
    self.setLayout(self.hlayout)

    self.menuLayout = QHBoxLayout()
    self.hlayout.addLayout(self.menuLayout)

    self.frameLayout = QFormLayout()
    self.menuLayout.addLayout(self.frameLayout)
    self.frameNumberEdit = QLineEdit(str(self.Frames))
    self.frameNumberEdit.setFixedWidth(40)
    self.frameNumberEdit.setValidator(QIntValidator(0, 256))
    self.frameLayout.addRow("Number of frame: ", self.frameNumberEdit)
    self.connect(self.frameNumberEdit, SIGNAL("textChanged(QString)"), self.setFrameNumber)

    self.iconLayout = QFormLayout()
    self.menuLayout.addLayout(self.iconLayout)
    self.iconSizeEdit = QLineEdit(str(self.IconSize))
    self.iconSizeEdit.setFixedWidth(40)
    self.iconSizeEdit.setValidator(QIntValidator(0, 512))
    self.iconLayout.addRow("Size: ", self.iconSizeEdit)
    self.connect(self.iconSizeEdit, SIGNAL("textChanged(QString)"), self.setIconSize)

    self.refreshButton = QPushButton("Refresh")
    self.menuLayout.addWidget(self.refreshButton)
    self.connect(self.refreshButton, SIGNAL("clicked()"), self.generateThumbnail)

    self.scrollArea = QScrollArea()
    self.hlayout.addWidget(self.scrollArea)

    self.generateThumbnail()

  def mousePressEvent(self, event):
    self.dragPosition = event.pos()
    if not self.rubberBand:
      self.rubberBand = QRubberBand(QRubberBand.Rectangle, self)
    self.rubberBand.setGeometry(QRect(self.dragPosition, QSize()))
    self.rubberBand.show()

  def mouseMoveEvent(self, event):
    self.rubberBand.setGeometry(QRect(self.dragPosition, event.pos()).normalized())

  def mouseReleaseEvent(self, event):
     if not self.rubberBand.size().isEmpty():
       rect = QRect(self.rubberBand.pos(), self.rubberBand.size())
       rect.moveLeft(rect.left() - (self.width() - self.thumbLabel.pixmap().width()) / 2.0)
       rect.moveTop(rect.top() - (self.height() - self.thumbLabel.pixmap().height()) / 2.0)
       self.currentSelection = rect
       self.copySelectionMenu.popup(QCursor.pos())
     else:
       self.copyMenu.popup(QCursor.pos())
     self.rubberBand.hide()

  def copySelectionToClipboard(self):
     QApplication.clipboard().setPixmap(self.thumbLabel.pixmap().copy(self.currentSelection))
     
  def copyPixmapToClipboard(self):
     QApplication.clipboard().setPixmap(self.thumbLabel.pixmap())

  
  def setIconSize(self, size):
     ThumbnailVideoView.IconSize = int(size)

  def setFrameNumber(self, number):
     ThumbnailVideoView.Frames = int(number)

  def generateThumbnail(self):
    self.thumbnailer = Thumbnailer()
    self.connect(self.thumbnailer, SIGNAL("ThumbnailUpdate"), self.updateThumbnail)
    pixmap = self.thumbnailer.generate(self.node, iconSize = self.IconSize, frames = self.Frames)
    if pixmap:
	self.updateThumbnail(self.node, pixmap)

  def updateThumbnail(self, node, pixmap):
     if pixmap:
       self.thumbLabel = QLabel()
       self.thumbLabel.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
       self.thumbLabel.setWordWrap(True)
       self.thumbLabel.setPixmap(pixmap)
       self.scrollArea.setWidget(self.thumbLabel)
     else:
       self.thumbLabel.setText("Can't render, video is corrupted.")
       self.thumbLabel.setAlignment(Qt.AlignCenter)
     self.thumbnailer.unregister()

  def updateWidget(self):
     pass

class videothumbnailviewer(Module):
  """Creates thumbnail from video files."""
  def __init__(self):
    Module.__init__(self, "thumbnailvideo", ThumbnailVideoView)
    self.conf.addArgument({"name": "file",
                           "description": "Picture file to display",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addArgument({"name": "preview",
			   "description": "Preview mode",
			   "input": Argument.Empty})
    self.conf.addConstant({"name": "mime-type", 
 	                   "type": typeId.String,
 	                   "description": "managed mime type",
 	                   "values": ["video"]})
    self.tags = "Viewers"
    self.icon = ":movie"
