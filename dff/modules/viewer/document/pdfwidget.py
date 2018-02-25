# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2014 ArxSys
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

from popplerqt4 import Poppler

from PyQt4.QtCore import Qt, QPoint, QRectF, QRect, SIGNAL, QSize, QPointF, QString
from PyQt4.QtGui import  QWidget, QRubberBand, QMatrix, QPixmap, QPainter, QLabel, QScrollArea, QHBoxLayout, QVBoxLayout, QSpacerItem, QSizePolicy, QLineEdit, QComboBox, QPushButton, QSpinBox, QColor, QApplication, QClipboard, QMenu, QCursor, QIntValidator, QIcon

class PageLineEdit(QHBoxLayout):
  def __init__(self):
    QHBoxLayout.__init__(self)
    self.maximumPageNumber = 0
    self.currentPageNumber = 0

    pageLayout = QHBoxLayout()
    self.addLayout(pageLayout)
    pageLayout.setMargin(0)
    pageLayout.setSpacing(0)
    self.pageLabel = QLabel(self.tr("Page: "))
    self.pageLabel.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
    pageLayout.addWidget(self.pageLabel)
    self.currentNumberLineEdit = QLineEdit()
    self.pageLabel.setBuddy(self.currentNumberLineEdit)
    pageLayout.addWidget(self.currentNumberLineEdit)
    self.currentNumberLineEdit.setMaximumWidth(35)
    self.currentNumberLineEdit.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
    self.currentNumberLineEdit.setStyleSheet(
                                             "border-left-width: 2px;"
                                             "border-right-width: 0px;"
                                             "border-top-width: 2px;"
                                             "border-bottom-width: 2px;"
                                             "border-style: solid;"
                                             "border-color: gray;")
    self.maximumNumberLineEdit = QLineEdit()
    pageLayout.addWidget(self.maximumNumberLineEdit)
    self.maximumNumberLineEdit.setMaximumWidth(40)
    self.maximumNumberLineEdit.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
    self.maximumNumberLineEdit.setStyleSheet(
                                             "border-left-width: 0px;"
                                             "border-right-width: 2px;"
                                             "border-top-width: 2px;"
                                             "border-bottom-width: 2px;"
                                             "border-style: solid;"
                                             "border-color: gray;")
    self.maximumNumberLineEdit.setReadOnly(True)
    self.updateText()

    buttonLayout = QHBoxLayout()
    buttonLayout.setMargin(0)
    buttonLayout.setSpacing(0)
    self.connect(self.currentNumberLineEdit, SIGNAL("editingFinished()"), self.validateText)
    self.previousPageButton = QPushButton(QIcon(":top.png"),"")
    self.connect(self.previousPageButton, SIGNAL("clicked()"), self.previousPageButtonPressed)
    buttonLayout.addWidget(self.previousPageButton)
    self.nextPageButton = QPushButton(QIcon(":down.png"),"")
    self.connect(self.nextPageButton, SIGNAL("clicked()"), self.nextPageButtonPressed)
    buttonLayout.addWidget(self.nextPageButton)
    self.addLayout(buttonLayout)

  def nextPageButtonPressed(self):
    if self.currentPageNumber + 1 <= self.maximumPageNumber:
      self.currentPageNumber += 1
      self.emit(SIGNAL("valueChanged(int)"), self.currentPageNumber)
      self.updateText()

  def previousPageButtonPressed(self):
    if self.currentPageNumber - 1 > 0:
      self.currentPageNumber -= 1
      self.emit(SIGNAL("valueChanged(int)"), self.currentPageNumber)
      self.updateText()

  def setMaximumPageNumber(self, value):
     self.maximumPageNumber = value
     self.currentNumberLineEdit.setValidator(QIntValidator(1, value))
     self.updateText()

  def validateText(self):
    text = self.currentNumberLineEdit.text()
    if self.currentNumberLineEdit.hasAcceptableInput():
      self.currentPageNumber = int(text)
      self.emit(SIGNAL("valueChanged(int)"), self.currentPageNumber)
    self.updateText()

  def setPageNumberValue(self, value):
     self.currentPageNumber = value
     self.updateText()

  def updateText(self):
     self.currentNumberLineEdit.setText(str(self.currentPageNumber))
     self.maximumNumberLineEdit.setText("/ " + str(self.maximumPageNumber))

class PDFWidget(QWidget):
  scaleFactors =  [ 0.25,   0.5,  0.75,    1.0,   1.25,    1.5,    2.0]
  scalePercents = ["25%", "50%", "75%", "100%", "125%", "150%", "200%"]
  def __init__(self):
    QWidget.__init__(self)
    self.hboxLayout = QVBoxLayout()
    self.setLayout(self.hboxLayout)
    self.setMenu()
    self.setPDFLabelScrollArea()

    self.connect(self.pageLineEdit, SIGNAL("valueChanged(int)"), self.pdfLabel.setPage)
    self.connect(self.pdfLabel, SIGNAL("pageChanged"), self.pageLineEdit.setPageNumberValue)
    self.connect(self.pdfLabel, SIGNAL("pageChanged"), self.scrollToTop)

    self.connect(self.scaleComboBox, SIGNAL("currentIndexChanged(int)"), self.scaleDocument)

    self.connect(self.searchLineEdit, SIGNAL("returnPressed()"), self.searchDocument)
    self.connect(self.findButton, SIGNAL("clicked()"), self.searchDocument)
    self.connect(self.clearButton, SIGNAL("clicked()"), self.pdfLabel.setPage)
    self.connect(self.searchLineEdit, SIGNAL("textChanged(QString)"), self.checkSearchText)
    self.connect(self, SIGNAL("setDocument"), self.setDocument) 

  def setMenu(self):
    self.menuLayout = QHBoxLayout()
    self.hboxLayout.addLayout(self.menuLayout)
    self.pageLineEdit = PageLineEdit()
    self.pageLineEdit.setEnabled(False)
    self.menuLayout.addLayout(self.pageLineEdit)

    spacer = QSpacerItem(20, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
    self.menuLayout.addItem(spacer)

    self.searchLayout = QHBoxLayout()
    self.menuLayout.addLayout(self.searchLayout)    
    self.searchLabel = QLabel(self.tr("Search:"))
    self.searchLabel.setTextFormat(Qt.AutoText)
    self.searchLayout.addWidget(self.searchLabel)    
    self.searchLineEdit = QLineEdit()
    self.searchLineEdit.setEnabled(False)
    self.searchLabel.setBuddy(self.searchLineEdit)
    self.searchLayout.addWidget(self.searchLineEdit)
    self.searchComboBox = QComboBox()
    self.searchComboBox.setEnabled(False)
    self.searchComboBox.insertItems(0, ["Forwards", "Backwards"])
    self.searchLayout.addWidget(self.searchComboBox)
    self.findButton = QPushButton("Find")
    self.findButton.setEnabled(False)
    self.searchLayout.addWidget(self.findButton)
    self.clearButton = QPushButton("Clear")
    self.clearButton.setEnabled(False)
    self.searchLayout.addWidget(self.clearButton)

    spacer = QSpacerItem(20, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
    self.menuLayout.addItem(spacer)
    
    self.scaleLabel = QLabel("Scale:")
    self.menuLayout.addWidget(self.scaleLabel)
    self.scaleComboBox = QComboBox()
    self.scaleComboBox.setEnabled(False)
    self.scaleComboBox.insertItems(0, self.scalePercents) 
    self.scaleComboBox.setCurrentIndex(3)
    self.scaleLabel.setBuddy(self.scaleComboBox)
    self.menuLayout.addWidget(self.scaleComboBox)

  def setPDFLabelScrollArea(self): 
    self.pdfLabel = PDFLabel(self)
    self.scrollArea = QScrollArea()
    self.scrollArea.setWidgetResizable(True)
    self.scrollArea.setAlignment(Qt.AlignCenter)
    self.scrollArea.setWidget(self.pdfLabel)
    self.hboxLayout.addWidget(self.scrollArea)

  def scrollToTop(self, value):
    self.scrollArea.verticalScrollBar().setValue(0)

  def setDocument(self, data):
    if self.pdfLabel.setDocument(data):
      self.searchLineEdit.setEnabled(True)
      self.searchComboBox.setEnabled(True)
      self.findButton.setEnabled(True)
      self.clearButton.setEnabled(True)
      self.scaleComboBox.setEnabled(True)
      self.pageLineEdit.setEnabled(True)
      self.pageLineEdit.setPageNumberValue(1)
      self.pageLineEdit.setMaximumPageNumber(self.pdfLabel.document().numPages())

  def setError(self, errorMessage):
    self.pdfLabel.setError(errorMessage)

  def setMessage(self, message):
    self.pdfLabel.setText(message)

  def checkSearchText(self, text):
     if text == "":
       self.pdfLabel.setPage()

  def scaleDocument(self, index):
    self.pdfLabel.setScale(self.scaleFactors[index])

  def searchDocument(self):
    if self.searchComboBox.currentIndex() == 0:
      location = self.pdfLabel.searchForwards(self.searchLineEdit.text())
    else:
      location = self.pdfLabel.searchBackwards(self.searchLineEdit.text())

    target = self.pdfLabel.matrix().mapRect(location).center().toPoint();
    self.scrollArea.ensureVisible(target.x(), target.y())

class CopyMenu(QMenu):
  def __init__(self, parent):
     QMenu.__init__(self, parent)
     action = self.addAction(self.tr("copy entire page as image"))
     self.connect(action, SIGNAL("triggered()"), parent.copyPixmapToClipboard)

class CopySelectionMenu(QMenu):
  def __init__(self, parent):
     QMenu.__init__(self, parent)
     action = self.addAction(self.tr("copy selection as text"))
     self.connect(action, SIGNAL("triggered()"), parent.copyTextToClipboard)
     action = self.addAction(self.tr("copy selection as image"))
     self.connect(action, SIGNAL("triggered()"), parent.copySelectionToClipboard)
     action = self.addAction(self.tr("copy entire page as image"))
     self.connect(action, SIGNAL("triggered()"), parent.copyPixmapToClipboard)

class PDFLabel(QLabel):
  def __init__(self, parent = None):
    QLabel.__init__(self, parent)
    self.currentPage = -1 
    self.doc = None
    self.rubberBand = None
    self.scaleFactor = 1.0
    self.setAlignment(Qt.AlignCenter) 
    self.dragPosition = QPoint()
    self.searchLocation = QRectF() 
    self.copyMenu = CopyMenu(self)
    self.copySelectionMenu = CopySelectionMenu(self)

  def document(self):
    return self.doc

  def matrix(self):
    return QMatrix(self.scaleFactor * self.physicalDpiX() / 72.0, 0,
                   0, self.scaleFactor * self.physicalDpiY() / 72.0, 
                   0, 0);

  def mousePressEvent(self, event):
    if not self.doc:
      return
    self.dragPosition = event.pos()
    if not self.rubberBand:
      self.rubberBand = QRubberBand(QRubberBand.Rectangle, self)
    self.rubberBand.setGeometry(QRect(self.dragPosition, QSize()))
    self.rubberBand.show()

  def mouseMoveEvent(self, event):
    if not self.doc:
      return
    self.rubberBand.setGeometry(QRect(self.dragPosition, event.pos()).normalized())

  def mouseReleaseEvent(self, event):
     if not self.doc:
       return
     if not self.rubberBand.size().isEmpty():
       rect = QRect(self.rubberBand.pos(), self.rubberBand.size())
       rect.moveLeft(rect.left() - (self.width() - self.pixmap().width()) / 2.0)
       rect.moveTop(rect.top() - (self.height() - self.pixmap().height()) / 2.0)
       self.currentSelection = rect
       self.copySelectionMenu.popup(QCursor.pos())
       #self.selectedText(rect)
     else:
       self.copyMenu.popup(QCursor.pos())
     self.rubberBand.hide()

  def scale(self):
    return self.scaleFactor

  def showPage(self, page = -1):
    if (page != -1 and page != self.currentPage + 1):
      self.currentPage = page - 1 
      self.emit(SIGNAL("pageChanged"), page)

    image = self.doc.page(self.currentPage).renderToImage(self.scaleFactor * self.physicalDpiX(), 
                                                          self.scaleFactor * self.physicalDpiY())

    if not self.searchLocation.isEmpty():
       highlightRect = self.matrix().mapRect(self.searchLocation).toRect()
       highlightRect.adjust(-2, -2, 2, 2)
       highlight = image.copy(highlightRect)
       painter = QPainter()
       painter.begin(image)
       painter.fillRect(image.rect(), QColor(0, 0, 0, 128))
       painter.drawImage(highlightRect, highlight)
       painter.end()
    
    self.setPixmap(QPixmap.fromImage(image))

  def searchBackwards(self, text):
    oldLocation = self.searchLocation

    page = self.currentPage;
    if oldLocation.isNull():
        page -= 1

    while page > -1:
        locations = []
        self.searchLocation = QRectF();

        while self.doc.page(page).search(text, self.searchLocation,  Poppler.Page.NextResult, Poppler.Page.CaseInsensitive):
          if self.searchLocation != oldLocation:
            locations.append(self.searchLocation)
          else:
            break
       
        try:
          index = locations.index(oldLocation)
        except :
          index = -1
        if index == -1 and len(locations):
          self.searchLocation = locations[-1]
          self.showPage(page + 1)
          return self.searchLocation
        if index > 0:
          self.searchLocation = locations[index - 1]
          self.showPage(page + 1)
          return self.searchLocation

        oldLocation = QRectF()
        page -= 1

    if self.currentPage == self.doc.numPages() - 1:
      return QRectF()

    oldLocation = QRectF()
    page = self.doc.numPages() - 1

    while page > self.currentPage:
        locations = []
        self.searchLocation = QRectF()

        while self.doc.page(page).search(text, self.searchLocation, Poppler.Page.NextResult, Poppler.Page.CaseInsensitive):
          locations.append(self.searchLocation)

        if len(locations):
          self.searchLocation = locations[-1]
          self.showPage(page + 1)
          return self.searchLocation
        page -= 1

    return QRectF() 

  def searchForwards(self, text):
    page = self.currentPage
    while page < self.doc.numPages():
        if self.doc.page(page).search(text, self.searchLocation, Poppler.Page.NextResult, Poppler.Page.CaseInsensitive): 
            if not self.searchLocation.isNull(): 
                self.showPage(page + 1)
                return self.searchLocation
        page += 1
        self.searchLocation = QRectF()
    page = 0

    while page < self.currentPage:
        self.searchLocation = QRectF()
        if self.doc.page(page).search(text, self.searchLocation, Poppler.Page.NextResult, Poppler.Page.CaseInsensitive):
            if not self.searchLocation.isNull():
                self.showPage(page + 1)
                return self.searchLocation
        page += 1
    return QRectF()

  def copyTextToClipboard(self):
    selectedRect = self.matrix().inverted()[0].mapRect(self.currentSelection)
    r = (selectedRect.x(), selectedRect.y(), selectedRect.width(), selectedRect.height(),)
    text = self.doc.page(self.currentPage).text(QRectF(*r))
    #Remove space
    #hadSpace = False
    #center = QPointF()
    #text = QString()
    #for box in self.doc.page(self.currentPage).textList(): 
      #bounding = box.boundingBox()
      #r = (bounding.x(), bounding.y(), bounding.width(), bounding.height(),)
      #if selectedRect.intersects(QRect(*r)): 
        #if hadSpace:
          #text += " "
        #if not text.isEmpty() and box.boundingBox().top() > center.y():
          #text += "\n";
        #text += box.text();
        #hadSpace = box.hasSpaceAfter();
        #center = box.boundingBox().center();
    
    if not text.isEmpty():
      QApplication.clipboard().setText(text, QClipboard.Clipboard) 
      QApplication.clipboard().setText(text, QClipboard.Selection) 

  def copySelectionToClipboard(self):
     #pixmap =      self.currentSelection
     QApplication.clipboard().setPixmap(self.pixmap().copy(self.currentSelection))
     
  def copyPixmapToClipboard(self):
     QApplication.clipboard().setPixmap(self.pixmap())

  def setDocument(self, data):
    self.doc = Poppler.Document.loadFromData(data)
    if self.doc:
      #self.setVisible #change default behavior not visible if no document is set 
      self.doc.setRenderHint(Poppler.Document.Antialiasing)
      self.doc.setRenderHint(Poppler.Document.TextAntialiasing)
      self.searchLocation = QRectF()
      self.currentPage = -1
      self.setPage(1)
      return True
    return False

  def setError(self, errorMessage):
    self.setText(errorMessage)

  def setPage(self, page = -1):
    if page != self.currentPage + 1:
      self.searchLocation = QRectF()
      self.showPage(page)

  def setScale(self, scale):
    if self.scaleFactor != scale:
      self.scaleFactor = scale
      self.showPage()
