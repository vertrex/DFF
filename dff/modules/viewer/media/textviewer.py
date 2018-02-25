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
#  Jeremy MOUNIER <jmo@digital-forensic.org>

__dff_module_cat_version__ = "1.0.0"

import time

from PyQt4.QtCore import Qt, QString, SIGNAL, QTextCodec, QPropertyAnimation, QRect, QEasingCurve, QThread, QMutex, QObject, QSize, QMutexLocker
from PyQt4.QtGui import QWidget, QTextCursor, QPlainTextEdit, QTextOption, QScrollBar, QAbstractSlider, QHBoxLayout, QListWidget, QVBoxLayout, QSplitter, QSizePolicy, QMessageBox, QPushButton, QShortcut, QKeySequence, QLineEdit, QSizePolicy, QTextCharFormat, QTextDocument, QAbstractButton, QPainter, QStyle, QStyleOptionToolButton, QIcon, QCheckBox, QPalette, QPlainTextDocumentLayout, QLabel

from dff.api.vfs import vfs 
from dff.api.types.libtypes import Argument, typeId
from dff.api.module.module import Module 
from dff.api.module.script import Script


class FindBarButton(QAbstractButton):
    def __init__(self, parent):
        QAbstractButton.__init__(self, parent)
        self.setFocusPolicy(Qt.NoFocus)
  

    def sizeHint(self):
        self.ensurePolished()
        iconSize = self.style().pixelMetric(QStyle.PM_LargeIconSize, None, self)
        pm = self.icon().pixmap(iconSize)
        return QSize(pm.width(), pm.height())
  

    def enterEvent(self, event):
        if self.isEnabled():
            self.update()
        QAbstractButton.enterEvent(self, event)
  

    def leaveEvent(self, event):
        if self.isEnabled():
            self.update()
        QAbstractButton.leaveEvent(self, event)
  

    def paintEvent(self, _event):
        p = QPainter(self)
        opt = QStyleOptionToolButton()
        opt.init(self)
        opt.state |= QStyle.State_AutoRaise
        if self.isEnabled() and self.underMouse() and not self.isChecked() and not self.isDown():
            opt.state |= QStyle.State_Raised
        if self.isChecked():
            opt.state |= QStyle.State_On
        if self.isDown():
            opt.state |= QStyle.State_Sunken
        self.style().drawPrimitive(QStyle.PE_PanelButtonTool, opt, p, self)
        opt.icon = self.icon()
        opt.subControls = QStyle.SubControls()
        opt.activeSubControls = QStyle.SubControls()
        opt.features = QStyleOptionToolButton.None
        opt.arrowType = Qt.NoArrow
        size = self.style().pixelMetric(QStyle.PM_ButtonIconSize, None, self)
        opt.iconSize = QSize(size, size)
        self.style().drawComplexControl(QStyle.CC_ToolButton, opt, p, self)


class FindAndHighlight(QThread):
    def __init__(self, parent):
        QThread.__init__(self, parent)
        self._mutex = QMutex()
        self._stop = False


    def stop(self):
        self._mutex.lock()
        self._stop = True
        self._mutex.unlock()

      
    def unstop(self):
        self._mutex.lock()
        self._stop = False
        self._mutex.unlock()


    def setText(self, text):
        self._mutex.lock()
        self.__text = text
        self._mutex.unlock()

    
    def setNeedle(self, needle):
        self._mutex.lock()
        self.__needle = needle
        self._mutex.unlock()

    
    def run(self):
        matches = []
        text = self.__text
        needle = self.__needle
        document = QTextDocument(self.__text)
        fmt = QTextCharFormat()
        fmt.setBackground(Qt.green)
        nlen = needle.size()
        count = 0
        match = QTextCursor(document)
        match.setPosition(0)
        stop = False
        matched = True
        position = 0
        while matched:
            match = document.find(needle, match)
            position = match.position() - nlen
            if position >= 0:
                matches.append(position)
                match.setCharFormat(fmt)
            else:
                matched = False
            self._mutex.lock()
            stop = self._stop
            self._mutex.unlock()
            if stop:
                break
        if stop:
            self.emit(SIGNAL("matchesAvailable"), None, [])
        else:
            document.moveToThread(self.parent().thread())
            self.emit(SIGNAL("matchesAvailable"), document, matches)


class FindBar(QWidget):
    def __init__(self, parent):
        QWidget.__init__(self, parent)
        self.connect(parent, SIGNAL("matchChanged"), self.matchChanged)
        
        self.query = QLineEdit(self)
        self.query.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.connect(self.query, SIGNAL("textChanged(const QString &)"), self.queryChanged)

        self.matchLabel = QLabel("", self)
        
        self.caseCheckbox = QCheckBox("C&ase sensitive", self);
        self.caseCheckbox.setAutoFillBackground(True)
        self.caseCheckbox.setMinimumHeight(22)
        self.connect(self.caseCheckbox, SIGNAL("stateChanged(int)"), self.enableCaseSensitivity)
        
        self.previousButton = FindBarButton(self)
        self.previousButton.setIcon(self.style().standardIcon(QStyle.SP_ArrowUp, None, self))
        self.previousButton.setVisible(True)
        self.connect(self.previousButton, SIGNAL("clicked()"), self.previousClicked)
        
        self.nextButton = FindBarButton(self)
        self.nextButton.setIcon(self.style().standardIcon(QStyle.SP_ArrowDown, None, self))
        self.nextButton.setVisible(True)
        self.connect(self.nextButton, SIGNAL("clicked()"), self.nextClicked)
        
        self.closeButton = FindBarButton(self)
        self.closeButton.setIcon(QIcon(":/mail_delete"))
        self.closeButton.setVisible(True)
        self.connect(self.closeButton, SIGNAL("clicked()"), self.hideBar)
        
        hbox = QHBoxLayout(self)
        hbox.setSpacing(0)
        hbox.addWidget(self.query)
        hbox.addWidget(self.previousButton)
        hbox.addWidget(self.nextButton)
        hbox.addWidget(self.caseCheckbox)
        hbox.addWidget(self.closeButton)


    def resizeLabel(self):
        parentgeom = self.query.geometry()
        width = self.matchLabel.fontMetrics().width(self.matchLabel.text())
        self.matchLabel.setGeometry(parentgeom.width()-width, 0, width, 40)


    def resizeEvent(self, event):
        super(FindBar, self).resizeEvent(event)
        if self.geometry().height() != 0:
            self.resizeLabel()
            

    def matchChanged(self, current, total):
        palette = self.matchLabel.palette()
        if current == -1 and total == -1:
            self.matchLabel.setText("")
        elif current == 0 and total == 0:
            self.matchLabel.setText(str(0) + self.tr(" of ") +  str(0))
            palette.setColor(self.matchLabel.backgroundRole(), Qt.red)
            palette.setColor(self.matchLabel.foregroundRole(), Qt.red)
        else:
            self.matchLabel.setText(str(current) + self.tr(" of ") + str(total))
            palette.setColor(self.matchLabel.backgroundRole(), Qt.green)
            palette.setColor(self.matchLabel.foregroundRole(), Qt.green)
        self.matchLabel.setPalette(palette)
        self.resizeLabel()
        
        
    def enableCaseSensitivity(self, state):
        if state == Qt.Checked:
            self.emit(SIGNAL("caseSensitive"))
        else:
            self.emit(SIGNAL("caseUnsensitive"))


    def enableFocus(self):
        self.query.setFocus()
    

    def hideBar(self):
        self.setGeometry(0, 0, 0, 0)


    def previousClicked(self):
        self.emit(SIGNAL("previous"))


    def nextClicked(self):
        self.emit(SIGNAL("next"))


    def queryChanged(self):
        self.emit(SIGNAL("queryChanged"), self.query.text())


class TextHorizontalScrollBar(QScrollBar):
    def __init__(self, parent=None):
        super(TextHorizontalScrollBar, self).__init__(parent)


    def hideEvent(self, event):
        super(TextHorizontalScrollBar, self).hideEvent(event)
        self.emit(SIGNAL("hide(void)"))
        

    def showEvent(self, event):
        super(TextHorizontalScrollBar, self).showEvent(event)
        self.emit(SIGNAL("show(void)"))
        
        
class CAT(QSplitter, Script):
    def __init__(self):
        Script.__init__(self, "Textviewer")
        self.vfs = vfs.vfs()
        self.type = "Textviewer"
        self.icon = None
        self.currentCodec = "UTF-8"
        self._finder = None
        self._matches = []
        self._matchIdx = -1
        self._mutex = QMutex()


    def start(self, args):
        self.args = args
        try :
            self.preview = args["preview"].value()
        except IndexError:
            self.preview = False
        try:
            self.node = args["file"].value()
        except:
            pass


    def g_display(self):
        QSplitter.__init__(self)
        process = False

        try:
          codecType = self.node.dataType().split("/")[1]
        except: 
          codecType = "UTF-8"
        self.initShape(codecType)
        if self.node.size() > 30*(1024**2):
            if self.preview:
                self.renderButton.show()
                self.text.setText("The document you are trying to read is greater than 30MiB.\nIt will consume memory and take some time to process.\nif you really want to open it, click on Render button.")
            else:
                warn = "The document you are trying to read is greater than 30MiB.\nIt will consume memory and take some time to process.\nAre you sure you want to open it?"
            ret = QMessageBox.warning(self, self.tr("Text reader"), self.tr(warn), QMessageBox.Yes|QMessageBox.No)
            if ret == QMessageBox.Yes:
                process = True
        else:
            process = True
        if process:
            self.__process()

        
    def __process(self):
        self.render()
        self._finder = FindAndHighlight(self)
        self.connect(self._finder, SIGNAL("matchesAvailable"), self._update)
        self.connect(self, SIGNAL("updatePosition"), self.highlightAndMoveToPosition)



    def setUnformatedDocument(self):
        cursor = self.text.textCursor()
        position = cursor.position()
        document = QTextDocument(self.unicodeText)
        layout = QPlainTextDocumentLayout(document)
        document.setDocumentLayout(layout)
        cursor = QTextCursor(document)
        cursor.setPosition(position, QTextCursor.KeepAnchor)
        cursor.setPosition(position, QTextCursor.MoveAnchor)
        self._mutex.lock()
        self.text.setDocument(document)
        self.text.setTextCursor(cursor)
        self._mutex.unlock()
        

    def _update(self, document, matches):
        if document is None or len(matches) == 0:
            self.setUnformatedDocument()
            self._matches = []
            self._matchIdx = -1
            if self.__needle.size() == 0:
                self.text.emit(SIGNAL("matchChanged"), -1, -1)
            else:
                self.text.emit(SIGNAL("matchChanged"), 0, 0)
        else:
            self._matches = matches
            self._matchIdx = -1
            nlen = self.__needle.size()
            nearestMatch = -1
            cursor = self.text.textCursor()
            position = cursor.position()
            self._matchIdx, nearestMatch = min(enumerate(matches), key=lambda x: abs(x[1]-position))
            if nearestMatch != -1:
                position = nearestMatch
            cursor = QTextCursor(document)
            cursor.setPosition(position, QTextCursor.MoveAnchor)
            cursor.setPosition(position+nlen, QTextCursor.KeepAnchor)
            fmt = cursor.charFormat()
            fmt.setBackground(Qt.magenta)
            cursor.setCharFormat(fmt)
            cursor.setPosition(position, QTextCursor.KeepAnchor)
            layout = QPlainTextDocumentLayout(document)
            document.setDocumentLayout(layout)
            self._mutex.lock()
            self.text.setDocument(document)
            self.text.setTextCursor(cursor)
            self.text.ensureCursorVisible()
            self._mutex.unlock()
            self.text.emit(SIGNAL("matchChanged"), self._matchIdx + 1, len(self._matches))


    def highlightAndMoveToPosition(self, position, nlen):
        document = self.text.document()
        cursor = QTextCursor(document)
        cursor.setPosition(position, QTextCursor.MoveAnchor)
        cursor.setPosition(position+nlen, QTextCursor.KeepAnchor)
        fmt = cursor.charFormat()
        fmt.setBackground(Qt.magenta)
        cursor.setCharFormat(fmt)
        cursor.setPosition(position, QTextCursor.KeepAnchor)
        self._mutex.lock()
        self.text.setTextCursor(cursor)
        self._mutex.unlock()


    def unhighlight(self, position, nlen):
        fmt = QTextCharFormat()
        fmt.setBackground(Qt.green)
        cursor = self.text.textCursor()
        cursor.setPosition(position, QTextCursor.MoveAnchor)
        cursor.setPosition(position+nlen, QTextCursor.KeepAnchor)
        cursor.setCharFormat(fmt)
        cursor.setPosition(position, QTextCursor.KeepAnchor)


    def search(self, needle):
        if self._finder.isRunning():
            self._finder.stop()
            self._finder.quit()
            self._finder.wait()
        if needle.size() != 0:
            self.__needle = needle
            self._finder.setNeedle(needle)
            self._finder.setText(self.unicodeText)
            self._finder.unstop()
            self._finder.start()
        else:
            pass#self.setUnformatedDocument()


    def initShape(self, codecType = 'UTF-8'):
        self.listWidget = QListWidget()
        self.listWidget.setSortingEnabled(True)
        for codec in QTextCodec.availableCodecs():
            self.listWidget.addItem(str(codec))
        try:
          item = self.listWidget.findItems(codecType, Qt.MatchFixedString)[0]
        except:
          item = self.listWidget.findItems('UTF-8', Qt.MatchExactly)[0]
        self.currentCodec = item.text()
        self.listWidget.setCurrentItem(item)
        self.listWidget.scrollToItem(item)
        self.connect(self.listWidget, SIGNAL("itemSelectionChanged()"), self.codecChanged)

        self.renderButton = QPushButton("Render", self)
        self.renderButton.hide()
        self.connect(self.renderButton, SIGNAL("clicked()"), self.forceRendering)

        vbox = QVBoxLayout()
        vbox.addWidget(self.listWidget)
        vbox.addWidget(self.renderButton)
        lwidget = QWidget(self)
        lwidget.setLayout(vbox)

        self.text = QPlainTextEdit(self)
        self.text.setReadOnly(1)
        self.text.setWordWrapMode(QTextOption.NoWrap)
        self.text.setCenterOnScroll(True)
        horizontalScrollBar = TextHorizontalScrollBar(self.text)
        self.connect(horizontalScrollBar, SIGNAL("hide(void)"), self.__updateFindBarPosition)
        self.connect(horizontalScrollBar, SIGNAL("show(void)"), self.__updateFindBarPosition)
        self.text.setHorizontalScrollBar(horizontalScrollBar)
        
        self.findBar = FindBar(self.text)
        shortcut = QShortcut(QKeySequence(self.tr("Ctrl+f", "Search")), self)
        shortcut.setContext(Qt.WidgetWithChildrenShortcut)
        self.findBar.setGeometry(0, 0, 0, 0)
        self.connect(shortcut, SIGNAL("activated()"), self.toggleSearch)
        self.connect(self.findBar, SIGNAL("queryChanged"), self.search)
        self.connect(self.findBar, SIGNAL("next"), self._next)
        self.connect(self.findBar, SIGNAL("previous"), self._previous)
        
        self.addWidget(lwidget)
        self.addWidget(self.text)
        self.setStretchFactor(0, 0)
        self.setStretchFactor(1, 1)


    def _next(self):
        if self._matchIdx != -1:
            self.unhighlight(self._matches[self._matchIdx], self.__needle.size())
            if self._matchIdx < len(self._matches) - 1:
                self._matchIdx += 1
            else:
                self._matchIdx = 0
            self.highlightAndMoveToPosition(self._matches[self._matchIdx], self.__needle.size())
            self.text.emit(SIGNAL("matchChanged"), self._matchIdx + 1, len(self._matches))


    def _previous(self):
        if self._matchIdx != -1:
            self.unhighlight(self._matches[self._matchIdx], self.__needle.size())
            if self._matchIdx > 0:
                self._matchIdx -= 1
            else:
                self._matchIdx = len(self._matches) - 1
            self.highlightAndMoveToPosition(self._matches[self._matchIdx], self.__needle.size())
            self.text.emit(SIGNAL("matchChanged"), self._matchIdx + 1, len(self._matches))

            
    def codecChanged(self):
        self.currentCodec = self.listWidget.selectedItems()[0].text()
        self.render()


    def forceRendering(self):
        self.renderButton.hide()
        self.render()


    def toggleSearch(self):
        if self.findBar.height() == 0:
            self.showAnimation = QPropertyAnimation(self.findBar, "geometry")
            self.showAnimation.setDuration(200)
            geometry = self.text.geometry()
            if self.text.horizontalScrollBar().isVisible():
                bottomLeft = geometry.bottomLeft()
                bottomLeft.setY(bottomLeft.y() - self.text.horizontalScrollBar().height())
                geometry.setBottomLeft(bottomLeft)
            if not self.text.verticalScrollBar().isVisible():
                geometry.setWidth(geometry.width()+16)
            # XXX -9, -30 seems to be correct but is it working on all platform?
            startGeometry = QRect(-9, geometry.bottomLeft().y(), geometry.width(), 40)
            endGeometry = QRect(-9, geometry.bottomLeft().y()-30, geometry.width(), 40)
            self.showAnimation.setStartValue(startGeometry)
            self.showAnimation.setEndValue(endGeometry)
            self.showAnimation.start()
        self.findBar.enableFocus()

    
    def resizeEvent(self, event):
        super(CAT, self).resizeEvent(event)
        self.__updateFindBarPosition()


    def __updateFindBarPosition(self):
        if self.findBar.height() != 0:
            geometry = self.text.geometry()
            if self.text.horizontalScrollBar().isVisible():
                bottomLeft = geometry.bottomLeft()
                bottomLeft.setY(bottomLeft.y() - self.text.horizontalScrollBar().height())
                geometry.setBottomLeft(bottomLeft)
            if not self.text.verticalScrollBar().isVisible():
                geometry.setWidth(geometry.width()+16)
            self.findBar.setGeometry(-9, geometry.bottomLeft().y()-30, geometry.width(), 40)


    def render(self):
        try:
            vfile = self.node.open()
            buff = vfile.read()
            vfile.close()
        except:
            QMessageBox.critical(self, self.tr("Text reader"), 
                                 self.tr("Cannot open or read the content of ") + self.node.absolute(),  
                                 QMessageBox.Ok)
            return
        codec = QTextCodec.codecForName(self.currentCodec)
        decoder = codec.makeDecoder()
        self.unicodeText = decoder.toUnicode(buff)
        self.text.clear()
        document = QTextDocument(self.unicodeText)
        layout = QPlainTextDocumentLayout(document)
        document.setDocumentLayout(layout)
        self.text.setDocument(document)
        self.text.moveCursor(QTextCursor.Start)


    def updateWidget(self):
	pass


    def c_display(self):
        file = self.node.open()
        fsize = self.node.size()
        size = 0
        self.buff = ""
        while size < fsize:
            try:
                tmp = file.read(4096)
            except vfsError, e:
                print self.buff
                break
            if len(tmp) == 0:
                print tmp
                break         
            size += len(tmp)
            self.buff += tmp
            print tmp
        file.close()
        if len(self.buff): 
            return self.buff


class textviewer(Module):
    """Displays content of files as text
    ex:cat /myfile.txt"""
    def __init__(self):
        Module.__init__(self, "textviewer", CAT)
        self.conf.addArgument({"name": "file",
                               "description": "Text file to display",
                               "input": Argument.Required|Argument.Single|typeId.Node})
        self.conf.addArgument({"name": "preview",
			       "description": "Preview mode",
			       "input": Argument.Empty})
        self.conf.addConstant({"name": "mime-type", 
 	                       "type": typeId.String,
 	                       "description": "managed mime type",
 	                       "values": ["HTML", "ASCII", "XML", "text"]})
        self.tags = "Viewers"
        self.flags = ["console", "gui"]
        self.icon = ":text"
