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
# 

__dff_module_viewerimage_version__ = "1.0.0"
import re

from PyQt4 import QtCore, QtGui
from PyQt4.QtCore import Qt, QSize, QString, SIGNAL, QRect, QSize
from PyQt4.QtGui import QPixmap, QImage, QPushButton, QLabel, QWidget, QHBoxLayout, QVBoxLayout, QScrollArea, QIcon, QMatrix, QToolBar, QAction, QSizePolicy, QTabWidget, QTableWidget, QTableWidgetItem, QAbstractItemView, QLineEdit, QRubberBand, QMenu, QCursor, QApplication

from dff.api.vfs import vfs 
from dff.api.module.module import Module 
from dff.api.module.script import Script
from dff.api.types.libtypes import Argument, typeId

from dff.modules.metaexif import EXIF

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

class LoadedImage(QLabel):
  def __init__(self, parent):
    QLabel.__init__(self)
    self.parent = parent
    self.copyMenu = CopyMenu(self)
    self.copySelectionMenu = CopySelectionMenu(self)
    self.baseImage = QImage()
    self.matrix = QMatrix()
    self.zoomer = 1
    self.maxsize = 1024*10*10*10*25
    self.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Ignored);
    self.setAlignment(Qt.AlignCenter)
    self.rubberBand = None

  def setParent(self, parent):
    self.parent = parent

  def load(self, node):
    self.matrix.reset()
    self.zoomer = 1
    if node.size() < self.maxsize:
       self.node = node
       file = self.node.open()
       buff = file.read()
       file.close()
       if self.baseImage.loadFromData(buff):
         self.emit(SIGNAL("available(bool)"), True)
       else:
         self.baseImage.load(":file_broken.png")
         self.emit(SIGNAL("available(bool)"), False)
    else:
      self.baseImage.loadFromData("")
      self.emit(SIGNAL("available(bool)"), False)
    self.adjust()


  def adjust(self):
    if self.zoomer == 1:
      if self.baseImage.width() < self.parent.width() - 10:
        self.curWidth = self.baseImage.width()
      else:
        self.curWidth = self.parent.width() - 10
      if self.baseImage.height() < self.parent.height() - 10:
        self.curHeight = self.baseImage.height()
      else:
        self.curHeight = self.parent.height() - 10
    self.updateTransforms()


  def updateTransforms(self):
    if not self.baseImage.isNull():
      self.currentImage = self.baseImage.transformed(self.matrix).scaled(QSize(self.curWidth, self.curHeight), Qt.KeepAspectRatio, Qt.FastTransformation)
      self.setPixmap(QPixmap.fromImage(self.currentImage))
    else:
      self.clear()
      self.setText("File is too big to be processed")
    self.adjustSize()


  def rotateLeft(self):
    self.matrix.rotate(-90)
    self.updateTransforms()


  def rotateRight(self):
    self.matrix.rotate(90)
    self.updateTransforms()


  def enlarge(self):
    self.zoomer *= 1.25
    self.curWidth *= 1.25
    self.curHeight *= 1.25
    self.updateTransforms()


  def shrink(self):
    self.zoomer *= 0.8
    self.curWidth *= 0.8
    self.curHeight *= 0.8
    self.updateTransforms()


  def fit(self):
    self.zoomer = 1
    self.adjust()

  def normal(self):
    self.curWidth = self.baseImage.width()
    self.curHeight = self.baseImage.height()
    self.updateTransforms()

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
       rect.moveLeft(rect.left() - (self.width() - self.pixmap().width()) / 2.0)
       rect.moveTop(rect.top() - (self.height() - self.pixmap().height()) / 2.0)
       self.currentSelection = rect
       self.copySelectionMenu.popup(QCursor.pos())
     else:
       self.copyMenu.popup(QCursor.pos())
     self.rubberBand.hide()

  def copySelectionToClipboard(self):
     QApplication.clipboard().setPixmap(self.pixmap().copy(self.currentSelection))
     
  def copyPixmapToClipboard(self):
     QApplication.clipboard().setPixmap(self.pixmap())

class Metadata(QWidget):
  def __init__(self):
    QWidget.__init__(self)
    self.tabs = QTabWidget()
    self.nometa = QLabel("No EXIF metadata found")
    self.nometa.setAlignment(Qt.AlignCenter)
    self.box = QHBoxLayout()
    self.setLayout(self.box)
    self.box.addWidget(self.tabs)
    self.box.addWidget(self.nometa)
    self.nometa.hide()
    self.tabs.show()
    self.tabs.setTabPosition(QTabWidget.East)


  def process(self, node):
    for idx in xrange(0, self.tabs.count()):
      widget = self.tabs.widget(idx)
      del widget
    self.tabs.clear()
    self.node = node
    file = self.node.open()
    tags = EXIF.process_file(file)
    if len(tags) == 0:
      self.nometa.setSizePolicy(self.tabs.sizePolicy())
      self.tabs.hide()
      self.nometa.show()
    else:
      self.tabs.show()
      self.nometa.hide()
      sortedTags = {}
      for tag in tags.keys():
        if tag not in ('JPEGThumbnail', 'TIFFThumbnail', 'Filename', 'EXIF MakerNote'):
          spaceidx = tag.find(" ")
          ifd = tag[:spaceidx].strip()
          if ifd == "Image":
            ifd = "IFD 0 (Image)"
          if ifd == "Thumbnail":
            ifd = "IFD 1 (Thumbnail)"
          key = tag[spaceidx:].strip()
          try:
            val = str(tags[tag])
          except:
            val = "cannot be decoded"
          if ifd not in sortedTags.keys():
            sortedTags[ifd] = []
          sortedTags[ifd].append((key, val))
      for ifd in sortedTags.keys():
        table = QTableWidget(len(sortedTags[ifd]), 2)
        table.setShowGrid(False)
        table.setAlternatingRowColors(True)
        table.verticalHeader().hide()
        table.horizontalHeader().setClickable(False)
        table.horizontalHeader().setStretchLastSection(True)
        table.setHorizontalHeaderLabels(["Tag", "Value"])
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tabs.addTab(table, ifd)
        row = 0
        for res in sortedTags[ifd]:
          key = QTableWidgetItem(res[0])
          key.setFlags(Qt.ItemIsSelectable|Qt.ItemIsEnabled)
          val = QTableWidgetItem(res[1])
          val.setFlags(Qt.ItemIsSelectable|Qt.ItemIsEnabled)
          table.setItem(row, 0, key)
          table.setItem(row, 1, val)
          row += 1
      if 'JPEGThumbnail' in tags.keys():
        label = QLabel()
        img = QImage()
        img.loadFromData(tags['JPEGThumbnail'])
        label.setPixmap(QPixmap.fromImage(img))
        label.setAlignment(Qt.AlignCenter)
        self.tabs.addTab(label, "Embedded Thumbnail")
      if 'TIFFThumbnail' in tags.keys():
        label = QLabel()
        img = QImage()
        img.loadFromData(tags['TIFFThumbnail'])
        label.setPixmap(QPixmap.fromImage(img))
        label.setAlignment(Qt.AlignCenter)
        self.tabs.addTab(label, "Embedded Thumbnail")
      file.close()	

class ImageView(QWidget, Script):
  def __init__(self):
    Script.__init__(self, "viewerimage")
    self.type = "imageview"
    self.icon = None
    self.vfs = vfs.vfs()
    self.reg_viewer = re.compile(".*(JPEG|JPG|jpg|jpeg|GIF|gif|bmp|png|PNG|pbm|PBM|pgm|PGM|ppm|PPM|xpm|XPM|xbm|XBM|TIFF|tiff).*", re.IGNORECASE)
    self.sceneWidth = 0

  def start(self, args):
    try :
      self.preview = args["preview"].value()
    except IndexError:
      self.preview = False
    try:
      self.node = args["file"].value()
      self.curIdx = self.node.at()
    except KeyError:
      pass

  def isImage(self, node):
    if node.size() != 0:
      try:
        _type = node.dataType()
      except (IndexError, AttributeError, IOError):
	return False
      if self.reg_viewer.search(_type):
        return True
    return False


  def next(self):
    listNodes = self.node.parent().children()
    newIdx = self.curIdx + 1
    if newIdx >= len(listNodes):
	newIdx = 0
    while newIdx != self.curIdx:
      if self.isImage(listNodes[newIdx]):
        break
      newIdx += 1
      if newIdx >= len(listNodes):
        newIdx = 0
    self.curIdx = newIdx 
    self.setImage(listNodes[self.curIdx])


  def previous(self):
    listNodes = self.node.parent().children()
    newIdx = self.curIdx - 1 
    if newIdx < 0:
      newIdx = len(listNodes) - 1
    while newIdx != self.curIdx:
       if self.isImage(listNodes[newIdx]):
	 break
       newIdx -=  1
       if newIdx < 0:
	 newIdx = len(listNodes) - 1
    self.curIdx = newIdx
    self.setImage(listNodes[self.curIdx])
      

  def createActions(self):
    self.actions = QToolBar()
    self.actions.setObjectName("Image viewer actions")
    self.nextButton = QAction(QIcon(":next.png"), "Display next image", self.actions)
    self.previousButton = QAction(QIcon(":previous.png"), "Display previous image", self.actions)
    self.rotlButton = QAction(QIcon(":rotate-left.png"), "Rotate the image 90 degrees to the left", self.actions)
    self.rotrButton = QAction(QIcon(":rotate-right.png"), "Rotate the image 90 degrees to the right", self.actions)
    self.enlargeButton = QAction(QIcon(":viewmag+"), "Enlarge the image", self.actions)
    self.shrinkButton = QAction(QIcon(":viewmag-"), "Shrink the image", self.actions)
    self.fitButton = QAction(QIcon(":viewmagfit"), "Fit the image to the window", self.actions)
    self.normalButton = QAction(QIcon(":viewmag1"), "Show the image at its normal size", self.actions)
    self.actions.addAction(self.previousButton)
    self.actions.addAction(self.nextButton)
    self.actions.addAction(self.rotlButton)
    self.actions.addAction(self.rotrButton)
    self.actions.addAction(self.enlargeButton)
    self.actions.addAction(self.shrinkButton)
    self.actions.addAction(self.fitButton)
    self.actions.addAction(self.normalButton)
    self.connect(self.loadedImage, SIGNAL("available(bool)"), self.enableActions)
    self.connect(self.previousButton, SIGNAL("triggered()"), self.previous)
    self.connect(self.nextButton, SIGNAL("triggered()"), self.next)
    self.connect(self.rotlButton, SIGNAL("triggered()"), self.loadedImage.rotateLeft)
    self.connect(self.rotrButton, SIGNAL("triggered()"), self.loadedImage.rotateRight)
    self.connect(self.enlargeButton, SIGNAL("triggered()"), self.loadedImage.enlarge)
    self.connect(self.shrinkButton, SIGNAL("triggered()"), self.loadedImage.shrink)
    self.connect(self.fitButton, SIGNAL("triggered()"), self.loadedImage.fit)
    self.connect(self.normalButton, SIGNAL("triggered()"), self.loadedImage.normal)


  def enableActions(self, cond):
    self.rotlButton.setEnabled(cond)
    self.rotrButton.setEnabled(cond)
    self.enlargeButton.setEnabled(cond)
    self.shrinkButton.setEnabled(cond)
    self.fitButton.setEnabled(cond)
    self.normalButton.setEnabled(cond)


  def setImage(self, node):
    if not self.preview:
      self.imagelabel.clear()
      self.imagelabel.insert(QString.fromUtf8(node.absolute()))
      self.metadata.process(node)
    self.loadedImage.load(node)


  def g_display(self):
    QWidget.__init__(self, None)
    self.factor = 1
    self.box = QHBoxLayout()
    self.setLayout(self.box)

    self.imagebox = QVBoxLayout()
    self.scrollArea = QScrollArea()
    self.loadedImage = LoadedImage(self.scrollArea)
    self.scrollArea.setWidget(self.loadedImage)
    self.scrollArea.setAlignment(Qt.AlignCenter)
    if not self.preview:
      self.createActions()
      self.imagelabelbox = QVBoxLayout()
      self.imagelabelbox.setSpacing(0)
      self.imagelabel = QLineEdit()
      self.imagelabelbox.addWidget(self.imagelabel)
      self.imagelabel.setReadOnly(True)    
      self.imagebox.addWidget(self.actions)
    self.imagebox.addWidget(self.scrollArea)
    if not self.preview:
      self.imagebox.setAlignment(self.actions, Qt.AlignCenter)
      self.imagebox.addLayout(self.imagelabelbox)
      self.databox = QVBoxLayout()
      self.metadata = Metadata()
      self.databox.addWidget(self.metadata)

      if len(self.node.parent().children()) < 2:
        self.nextButton.setEnabled(False)
        self.previousButton.setEnabled(False)

    self.box.addLayout(self.imagebox)
    if not self.preview:
      self.box.addLayout(self.databox)
	
    self.setImage(self.node.parent().children()[self.curIdx])


  def updateWidget(self):
    if not self.preview:
      self.metadata.setMaximumSize(self.width() / 4, self.height())
    self.loadedImage.adjust()


  def resizeEvent(self, e):
    if not self.preview:
      self.metadata.setMaximumSize(self.width() / 4, self.height())
    self.loadedImage.adjust()


class imageviewer(Module):
  """Displays content of graphic file"""
  def __init__(self):
    Module.__init__(self, "pictures", ImageView)
    self.conf.addArgument({"name": "file",
                           "description": "Picture file to display",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addArgument({"name": "preview",
			   "description": "Preview mode",
			   "input": Argument.Empty})
    self.conf.addConstant({"name": "mime-type", 
 	                   "type": typeId.String,
 	                   "description": "managed mime type",
 	                   "values": ["image/jpeg", "image/gif", "image/png", "image/bmp", "image/tiff", "PBM", "PGM", "PPM", "XBM", "XPM"]})
    self.tags = "Viewers"
    self.icon = ":lphoto"
