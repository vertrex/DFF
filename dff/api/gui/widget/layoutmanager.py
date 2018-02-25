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

import os, types

from PyQt4.QtGui import QWidget, QMenu, QDialog, QLabel, QVBoxLayout, QSplitter, QDialogButtonBox, QFormLayout, QCheckBox, QComboBox, QLineEdit, QTextEdit, QListWidget, QHBoxLayout, QPushButton, QIcon, QFileDialog, QAbstractItemView, QRegExpValidator, QListWidgetItem, QApplication, QItemDelegate, QStandardItem, QStyle
from PyQt4.QtCore import Qt, QEvent, SIGNAL, QRegExp, QSize, QString, QChar, QVariant

from dff.api.vfs import vfs 
from dff.api.vfs.libvfs import VFS, Node
from dff.api.types.libtypes import typeId

class DialogNodeBrowser(QDialog):
    def __init__(self, parent=None):
        QDialog.__init__(self, parent)
        self.title = QLabel("Select a node in the Virtual File System :")
        self.createLayout()
        self.createButtons()

    def createLayout(self):
        self.baseLayout = QVBoxLayout(self)
        mw = QApplication.instance().mainWindow
        self.browser = mw.getNodeBrowser()
        self.baseLayout.addWidget(self.browser)
        self.setLayout(self.baseLayout)

    def createButtons(self):
        self.buttonBox = QDialogButtonBox()
        self.buttonBox.setStandardButtons(QDialogButtonBox.Cancel|QDialogButtonBox.Ok)
        self.connect(self.buttonBox, SIGNAL("accepted()"),self.accept)
        self.connect(self.buttonBox, SIGNAL("rejected()"),self.reject)
        self.baseLayout.addWidget(self.buttonBox)
        

    def getSelectedNodes(self):
        if len(self.browser.selection.get()) == 0:
            nodes = [self.browser.browserview.model.currentNode()]
        else:
            nodes = self.browser.selection.getNodes()
        return nodes


    def getSelectedNode(self):
        try:
            n = self.getSelectedNodes()[0]
            return n
        except:
            return None


    def changeEvent(self, event):
        """ Search for a language change event
        
        This event have to call retranslateUi to change interface language on
        the fly.
        """
        if event.type() == QEvent.LanguageChange:
            self.model.translation()
        else:
            QWidget.changeEvent(self, event)


class layoutManager(QWidget):
    '''Create a layout manager which will help widget creation and data managment
    The system work with a key / value system and return python type data (ex: str, int, long, list, tupple, etc..)
    '''
    def __init__(self, displaykey=False):
        QWidget.__init__(self)
        self.layout = QFormLayout()
        self.layout.setMargin(0)
        self.widgets = {}
        self.displaykey = displaykey
        self.setLayout(self.layout)
        self.translation()


    def overwriteKeys(self, key):
        '''
        Check if inserted key already exists in the layout system
        '''
        return self.widgets.has_key(key)


    def addBool(self, key, state = False):
        '''
        Create a non-exclusive checkbox widget and add it into the layout. It permit you to create Bool data representations
        '''
        if not self.overwriteKeys(key):
            if type(key).__name__=='str':
                w = QCheckBox(key)
                if not self.displaykey:
                    self.layout.addRow(w)
                else:
                    self.layout.addRow(key, w)
                self.widgets[key] = w
            else:
                return -1
        else:
            return -1
        return 1


    def addList(self, key, predefs, editable=False):
        if len(predefs) > 0 and not self.overwriteKeys(key):
            # Check if value list has the same type
            if type(key) == types.StringType:
                w = QComboBox()
		self.connect(w, SIGNAL("currentIndexChanged(QString)"), self.argumentChanged)
                w.setEditable(editable)
                w.setValidator(QIntValidator())
                w.setMinimumContentsLength(20)
                for value in predefs:
                    if type(value).__name__=='str':
                        if w.findText(value) == -1:
                            w.addItem(value)
                    elif type(value).__name__=='int':
                        if w.findText(str(value)) == -1:
                            w.addItem(str(value))
                    else:
                        return -1
                if not self.displaykey:
                    self.layout.addRow(w)
                else:
                    self.layout.addRow(key, w)
                self.widgets[key] = w
                return 1
            else: 
                return -1
        else:
            return -1


    def addSingleArgument(self, key, predefs, typeid, editable=False):
        if not self.overwriteKeys(key):
            if type(key) == types.StringType:
                if len(predefs) > 0:
                    w = QComboBox()
		    self.connect(w, SIGNAL("editTextChanged(QString)"), self.argumentChanged)
		    self.connect(w, SIGNAL("currentIndexChanged(QString)"), self.argumentChanged)
                    w.setEditable(editable)
                    for value in predefs:
                        w.addItem(value.toString())
                else:
                    w = QLineEdit()
		    self.connect(w, SIGNAL("editingFinished()"), self.argumentChanged)
                    if typeid not in (typeId.String, typeId.Char, typeId.Node, typeId.Path):
                        w.insert("0")
                    w.setReadOnly(not editable)
                w.setValidator(fieldValidator(self, typeid))
                if not self.displaykey:
                    self.layout.addRow(w)
                else:
                    self.layout.addRow(key, w)
                self.widgets[key] = w
                return 1
            else: 
                return -1
        else:
            return -1


    def addString(self, key, value=""):
        if not self.overwriteKeys(key):
            if type(key).__name__=='str':
                w = QLineEdit()
		self.connect(w, SIGNAL("editingFinished()"), self.argumentChanged)
                w.insert(value)
                if not self.displaykey:
                    self.layout.addRow(w)
                else:
                    self.layout.addRow(key, w)
                self.widgets[key] = w
                return 1
            else:
                return -1
        else:
            return -1
    

    def addText(self, key,  value=""):
        if not self.overwriteKeys(key):
            if type(key).__name__=='str':
                w = QTextEdit()
		self.connect(w, SIGNAL("textChanged()"), self.argumentChanged)
                w.setPlainText(value)
                if not self.displaykey:
                    self.layout.addRow(w)
                else:
                    self.layout.addRow(key, w)
                self.widgets[key] = w
                return 1
            else:
                return -1
        else:
            return -1


    def addSingleNode(self, key, predefs, selectednodes, editable=False, config=None):
        if config:
            predefs.push_front(config[0])
        if not self.overwriteKeys(key) and type(key).__name__=='str':
            vbox = QVBoxLayout()
            layout = QHBoxLayout()
            nodecontainer = NodeComboItem(self)
            self.connect(nodecontainer, SIGNAL("editTextChanged(QString)"), self.argumentChanged)
            self.connect(nodecontainer, SIGNAL("currentIndexChanged(QString)"), self.argumentChanged)
            nodecontainer.setEditable(editable)
            if len(predefs) > 0:
                if config:
                    for value in predefs:
                        node = value.value()
                        name = QString.fromUtf8(node.absolute())
                        nodecontainer.addSingleItem(name, node.uid())
                else:
                    category = self.tr("Predefined parameters")
                    nodecontainer.addParentItem(category)
                    for value in predefs:
                        node = value.value()
                        name = QString.fromUtf8(node.absolute())
                        nodecontainer.addChildItem(name, node.uid())
            if len(selectednodes) == 1:
                node = selectednodes[0]
                name = QString.fromUtf8(node.absolute())
                nodecontainer.addSingleItem(name, node.uid())
            elif len(selectednodes) > 0:
                category = self.tr("Selected nodes")
                nodecontainer.addParentItem(category)
                for node in selectednodes:
                    name = QString.fromUtf8(node.absolute())
                    nodecontainer.addChildItem(name, node.uid())
            browse = NodeSelectionButton(self, key, nodecontainer)
            layout.addWidget(nodecontainer, 2)
            layout.addWidget(browse, 0)
            vbox.addLayout(layout)
            if not self.displaykey:
                self.layout.addRow(vbox)
            else:
                self.layout.addRow(key, vbox)
            self.widgets[key] = nodecontainer
            return 1
        else:
            return -1


    def addNodeList(self, key, predefs, selectednodes):
        if not self.overwriteKeys(key) and type(key).__name__=='str':
            layout = QVBoxLayout()
            nodeList = NodeListItem()
            nodeList.setDragDropMode(QAbstractItemView.InternalMove)
            if len(predefs) > 0:
                if not self.checkUnifiedTypes(predefs):
                    return -1
                for predef in predefs:
                    nodeList.addSingleItem(str(predef), predef.value().uid())
            if selectednodes and len(selectednodes) > 0:
                for node in selectednodes:
                    name = QString.fromUtf8(node.absolute())
                    nodeList.addSingleItem(name, node.uid())
            hbox = QHBoxLayout()
            buttonbox = QDialogButtonBox()
            add = NodeSelectionButton(self, key, nodeList)
            buttonbox.addButton(add, QDialogButtonBox.ActionRole)
            rm = rmLocalPathButton(self, nodeList)
            buttonbox.addButton(rm, QDialogButtonBox.ActionRole)
            self.connect(add, SIGNAL("clicked()"), self.argumentChanged)
            self.connect(rm, SIGNAL("clicked()"), self.argumentChanged)
            hbox.addWidget(buttonbox, 3, Qt.AlignLeft)
            layout.addLayout(hbox, 0)
            layout.addWidget(nodeList, 2)
            if not self.displaykey:
                self.layout.addRow(layout)
            else:
                self.layout.addRow(key, layout)
            self.widgets[key] = nodeList
            return 1
        else:
            return -1


    def addSinglePath(self, key, predefs, editable=False, config=None):
        if config:
	  predefs.push_front(config[0]) 
        if not self.overwriteKeys(key) and type(key).__name__=='str':
            vbox = QVBoxLayout()
            layout = QHBoxLayout()
            pathcontainer = ComboItem(self)
            self.connect(pathcontainer, SIGNAL("editTextChanged(QString)"), self.argumentChanged)
            self.connect(pathcontainer, SIGNAL("currentIndexChanged(QString)"), self.argumentChanged)
            if len(predefs) > 0:
                if config:
                    for value in predefs:
                        val = value.value()
                        name = val.path
                        pathcontainer.addSingleItem(name)
                else:
                    category = self.tr("Predefined parameters")
                    pathcontainer.setEditable(editable)
                    pathcontainer.addParentItem(category)
                    for value in predefs:
                        val = value.value()
                        name = val.path
                        pathcontainer.addChildItem(name)
            combo = QComboBox()
            browse = PathSelectionButton(self, key, pathcontainer, inputchoice=combo)
            self.connect(combo, SIGNAL("editTextChanged(QString)"), self.argumentChanged)
            self.connect(combo, SIGNAL("currentIndexChanged(QString)"), self.argumentChanged)
            combo.addItem(self.inputFile)
            combo.addItem(self.inputDirectory)
            vbox.addWidget(combo)
            layout.addWidget(pathcontainer, 2)
            layout.addWidget(browse, 0)
            vbox.addLayout(layout)
            if not self.displaykey:
                self.layout.addRow(vbox)
            else:
                self.layout.addRow(key, vbox)
            self.widgets[key] = pathcontainer
            return 1
        else:
            return -1


    def addPathList(self, key, predefs):
        if not self.overwriteKeys(key) and type(key).__name__=='str':
            layout = QVBoxLayout()
            pathList = ListItem() ##XXX
            pathList.setDragDropMode(QAbstractItemView.InternalMove)
            if len(predefs) > 0:
                if not self.checkUnifiedTypes(predefs):
                    return -1
                for predef in predefs:
                    pathList.addSingleItem(str(predef))
            hbox = QHBoxLayout()
            buttonbox = QDialogButtonBox()
            combo = QComboBox()
            combo.setMinimumContentsLength(20)
            self.connect(combo, SIGNAL("editTextChanged(QString)"), self.argumentChanged)
            self.connect(combo, SIGNAL("currentIndexChanged(QString)"), self.argumentChanged)
            combo.addItem(self.inputFile)
            combo.addItem(self.inputDirectory)
            add = PathSelectionButton(self, key, pathList, combo)
            buttonbox.addButton(add, QDialogButtonBox.ActionRole)
            rm = rmLocalPathButton(self, pathList)
            buttonbox.addButton(rm, QDialogButtonBox.ActionRole)
            self.connect(add, SIGNAL("clicked()"), self.argumentChanged)
            self.connect(rm, SIGNAL("clicked()"), self.argumentChanged)
            hbox.addWidget(buttonbox, 3, Qt.AlignLeft)
            hbox.addWidget(combo, 1, Qt.AlignRight)
            layout.addLayout(hbox, 0)
            layout.addWidget(pathList, 2)
            if not self.displaykey:
                self.layout.addRow(layout)
            else:
                self.layout.addRow(key, layout)
            self.widgets[key] = pathList
            return 1
        else:
            return -1


    def addListArgument(self, key, typeid, predefs, editable=False, config=None):
        if not self.overwriteKeys(key) and type(key) == types.StringType:
            w = multipleListWidget(self, typeid, predefs, editable)
            if not self.displaykey:
                self.layout.addRow(w)
            else:
                self.layout.addRow(key, w)
            self.widgets[key] = w.valuelist
	    if config:
	      w.addParameterConfig(config)
            return 1
        else:
            return -1



    def checkUnifiedTypes(self, values):
        if len(values) == 0:
            return
        vtype = type(values[0]).__name__
        for v in values:
            if type(v).__name__ != vtype:
                return False
        return True


    def get(self, key):
        if self.widgets.has_key(key):
            widget = self.widgets[key]
            if isinstance(widget, ComboItem):
                return widget.getItem()
            elif isinstance(widget, ListItem):
                return widget.getItems()
            elif isinstance(widget, QLineEdit):
                return str(widget.text().toUtf8())
            elif isinstance(widget, QCheckBox):
                state = widget.checkState()
                if state == Qt.Unchecked:
                    return False
                else:
                    return True
            elif isinstance(widget, QTextEdit):
                return str(widget.toPlainText().toUtf8())
            elif isinstance(widget, QComboBox):
                return str(widget.currentText().toUtf8())
            else:
                return -1
        else:
            return -1


    def argumentChanged(self, event = None):
	self.emit(SIGNAL("argumentChanged()"))


    def translation(self):
        self.inputFile = self.tr("File")
        self.inputDirectory = self.tr("Directory")


class fieldValidator(QRegExpValidator):
    def __init__(self, parent, typeid):
        QRegExpValidator.__init__(self, parent)
        self.typeid = typeid
        self.init()

    def init(self):
        if self.typeid in (typeId.Int16, typeId.Int32, typeId.Int64):
            exp = "^(\+|-)?\d+$"
        elif self.typeid in (typeId.UInt16, typeId.UInt32, typeId.UInt64):
            exp = "^\d+$"
        else:
            exp = "^.+$"
        regexp = QRegExp(exp)
        regexp.setCaseSensitivity(Qt.CaseInsensitive)
        self.setRegExp(regexp)


class multipleListWidget(QWidget):
    def __init__(self, parent, typeid, predefs, editable):
        QWidget.__init__(self)
        self.parent = parent
        self.typeid = typeid
        self.editable = editable
        self.predefs = predefs
        self.init()

    def init(self):
        self.vbox = QVBoxLayout()
        self.vbox.setSpacing(5)
        self.vbox.setMargin(0)
        self.createHeader()
        self.valuelist = ListItem()
        self.vbox.addWidget(self.valuelist)
        self.setLayout(self.vbox)


    def createHeader(self):
        self.whead = QWidget()
        self.headerlayout = QHBoxLayout()
        self.headerlayout.setSpacing(0)
        self.headerlayout.setMargin(0)
        if self.typeid == typeId.Node and self.editable:
            self.addNode()
        elif self.typeid == typeId.Path and self.editable:
            self.addPath()
        else:
            self.addSingleArgument()

        self.addButton = QPushButton(QIcon(":add.png"), "")
        self.rmButton = QPushButton(QIcon(":del_dump.png"), "")
        self.addButton.setIconSize(QSize(16, 16))
        self.rmButton.setIconSize(QSize(16, 16))

        self.connect(self.addButton, SIGNAL("clicked()"), self.addParameter)
        self.connect(self.rmButton, SIGNAL("clicked()"), self.rmParameter)
        self.connect(self.addButton, SIGNAL("clicked()"), self.parent.argumentChanged)
        self.connect(self.rmButton, SIGNAL("clicked()"), self.parent.argumentChanged)

        self.headerlayout.addWidget(self.addButton, 0)
        self.headerlayout.addWidget(self.rmButton, 0)
        self.whead.setLayout(self.headerlayout)
        self.vbox.addWidget(self.whead)


    def addParameterConfig(self, config):
       try : 
        if len(config) :
          for item in config:
              self.valuelist.addSingleItem(item)
       except TypeError:
           self.valuelist.addSingleItem(config)


    def addParameter(self):
        if isinstance(self.container, QComboBox):
            item = self.container.currentText()
        else:
            item = self.container.text()
        self.valuelist.addSingleItem(item)


    def rmParameter(self):
        selected = self.valuelist.selectedItems()
        for item in selected:
            row = self.valuelist.row(item)
            self.valuelist.removeItem(row)


    def addSingleArgument(self):
        if len(self.predefs) > 0:
            if self.typeid == typeId.Node:
                self.container = NodeComboItem()
            else:
                self.container = ComboItem()
            for value in self.predefs:
                if self.typeid == typeId.Node:
                    node = value.value()
                    name = QString.fromUtf8(node.absolute())
                    self.container.addSingleItem(name, node.uid())
                else:
                    self.container.addSingleItem(value.toString())
                self.container.setEditable(self.editable)
        else:
            self.container = QLineEdit()
        self.headerlayout.addWidget(self.container, 2)


    def addNode(self):
        self.container = NodeComboItem()
        self.container.setReadOnly(False)
        for value in self.predefs:
            if self.typeid == typeId.Node:
                node = value.value()
                name = QString.fromUtf8(node.absolute())
                self.container.addSingleItem(name, node.uid())
        browse = NodeSelectionButton(self, key, self.container)
        self.headerlayout.addWidget(self.container, 2)
        self.headerlayout.addWidget(browse, 0)


    def addPath(self):
        self.container = ComboItem()
        self.container.setReadOnly(False)
        for value in self.predefs:
            self.container.addSingleItem(value.toString())
        browse = PathSelectionButton(self, key, self.container, isdir=False)
        self.headerlayout.addWidget(self.container, 2)
        self.headerlayout.addWidget(browse, 0)



class NodeSelectionButton(QPushButton):
    def __init__(self, parent, key, container, inputchoice=None):
        if isinstance(container, QListWidget):
            QPushButton.__init__(self, QIcon(":add.png"), "", parent)
        else:
            QPushButton.__init__(self, QIcon(":folder.png"), "...")
        self.setIconSize(QSize(16, 16))
        self.inputcombo = inputchoice
        self.ckey = key
        self.container = container
        self.connect(self, SIGNAL("clicked()"), self.browse)


    def browse(self):
        title = self.tr("Load") + " " + str(self.ckey)
        BrowseVFSDialog = DialogNodeBrowser(self.container)
        accept = BrowseVFSDialog.exec_()
        if accept:
            if isinstance(self.container, QListWidget):
                nodes = BrowseVFSDialog.getSelectedNodes()
            else:
                nodes = [BrowseVFSDialog.getSelectedNode()]
            if len(nodes):
                for node in nodes:
                    name = QString.fromUtf8(node.absolute())
                    self.container.addSingleItem(name, node.uid())
        BrowseVFSDialog.browser.__del__()


class PathSelectionButton(QPushButton):
    HomePath = os.path.expanduser('~')

    def __init__(self, parent, key, container, inputchoice=None):
        if isinstance(container, QListWidget):
            QPushButton.__init__(self, QIcon(":add.png"), "")#, parent)
        else:
            QPushButton.__init__(self, QIcon(":folder.png"), "...")#, parent)
        self.setIconSize(QSize(16, 16))
        self.manager = parent
        self.inputcombo = inputchoice
        self.ckey = key
        self.container = container
        self.connect(self, SIGNAL("clicked()"), self.browse)
       

    def setLastPath(self, path):
       path = str(path.toUtf8())
       PathSelectionButton.HomePath = os.path.dirname(path)


    def browse(self):
        title = self.tr("Load") + " " + str(self.ckey)
        if self.inputcombo and self.inputcombo.currentIndex() == 0:
            if isinstance(self.container, QListWidget):
                selectedFiles = QFileDialog.getOpenFileNames(self, title, PathSelectionButton.HomePath)
            elif isinstance(self.container, QComboBox):
                selectedFiles = [QFileDialog.getOpenFileName(self, title, PathSelectionButton.HomePath)]
            if len(selectedFiles) > 0:
                self.setLastPath(selectedFiles[0])
                for sfile in selectedFiles:
                    self.container.addSingleItem(sfile)
            else:
                return -1
        else:
            selectedFolder = QFileDialog.getExistingDirectory(self, title, PathSelectionButton.HomePath, 
                                                            QFileDialog.ShowDirsOnly|QFileDialog.DontResolveSymlinks)
            if selectedFolder:
                self.setLastPath(selectedFolder)
                self.container.addSingleItem(selectedFolder)
        self.manager.emit(SIGNAL("managerChanged"))



class rmLocalPathButton(QPushButton):
    def __init__(self, parent, container):
        QPushButton.__init__(self, QIcon(":del_dump.png"), "", parent)
        self.setIconSize(QSize(16, 16))
        self.container = container
        self.manager = parent
        self.connect(self, SIGNAL("clicked()"), self.rm)

    def rm(self):
        selected = self.container.selectedItems()
        for item in selected:
            row = self.container.row(item)
            self.container.removeItem(row)
        self.manager.emit(SIGNAL("managerChanged"))


class ComboItemDelegate(QItemDelegate):
    def __init__(self, parent=None):
        QItemDelegate.__init__(self)


    def paint(self, painter, option, index):
        itype = index.data(Qt.AccessibleDescriptionRole).toString()
        if itype == "parent":
            option.state |= QStyle.State_Enabled
        elif itype == "child":
            indent = option.fontMetrics.width(QString(4, QChar(' ')))
            option.rect.adjust(indent, 0, 0, 0)
            option.textElideMode = Qt.ElideNone
        QItemDelegate().paint(painter, option, index)


class ComboItem(QComboBox):
    def __init__(self, parent=None):
        QComboBox.__init__(self, parent)
        self.__delegate = ComboItemDelegate(self)
        self.setItemDelegate(self.__delegate)
        self._items = []
        # Avoid XXL line edit size
        self.setMinimumContentsLength(20)


    def setCurrentItem(self):
        index = self.model().index(0, 0)
        if index.isValid() and index.data(Qt.AccessibleDescriptionRole).toString() == "parent":
            for i in xrange(0, self.model().rowCount()):
                index = self.model().index(i, 0)
                if index.isValid() and index.data(Qt.AccessibleDescriptionRole).toString() == "child":
                    break
            self.setCurrentIndex(i)


    def addSingleItem(self, iname, val=None):
        if not val:
            val = iname
        if val not in self._items:
            self._items.append(val)
            idx = len(self._items) - 1
            item = QStandardItem(iname)
            item.setData(idx, Qt.UserRole)
            self.model().insertRow(0, [item])
            self.setCurrentIndex(0)


    def addParentItem(self, category):
        item = QStandardItem(category)
        item.setFlags(item.flags() & ~(Qt.ItemIsEnabled|Qt.ItemIsSelectable))
        item.setData("parent", Qt.AccessibleDescriptionRole)
        font = item.font()
        font.setBold(True)
        item.setFont(font)
        self.model().appendRow(item)


    def addChildItem(self, iname, val=None):
        if val is None:
            val = iname
        if val not in self._items:
            self._items.append(val)
            idx = len(self._items) - 1
            item = QStandardItem(iname)
            item.setData("child", Qt.AccessibleDescriptionRole)
            item.setData(idx, Qt.UserRole)
            self.model().appendRow(item)
            self.setCurrentItem()


    def getItem(self):
        item = self.model().item(self.currentIndex())
        idx, valid = item.data(Qt.UserRole).toInt()
        if valid:
            if isinstance(self._items[idx], QString):
                return str(self._items[idx].toUtf8())
            else:
                return self._items[idx]
        else:
            return None


# Specialization of ComboItem for nodes
class NodeComboItem(ComboItem):
    def __init__(self, parent=None):
        ComboItem.__init__(self, parent)


    def getItem(self):
        ret = None
        data = self.itemData(self.currentIndex(), Qt.UserRole)
        if data.isValid():
            idx, valid = data.toInt()
            if valid:
                uid = self._items[idx]
                node = VFS.Get().getNodeById(uid)
                ret = node
        return ret


class ListItem(QListWidget):
    def __init__(self, parent=None):
        QListWidget.__init__(self, parent)
        self._items = []


    def removeItem(self, row):
        item = self.item(row)
        idx, valid = item.data(Qt.UserRole).toInt()
        if valid:
            self._items[idx] = None
            self.takeItem(row)


    def addSingleItem(self, iname, val=None, top=False):
        if val is None:
            val = iname
        if val not in self._items:
            self._items.append(val)
            idx = len(self._items) - 1
            item = QListWidgetItem(iname)
            item.setData(Qt.UserRole, idx)
            if top:
                self.insertItem(0, item)
            else:
                self.insertItem(self.count(), item)
            self.setCurrentRow(0)


    def getItems(self):
        items = []
        for i in xrange(0, self.count()):
            item = self.item(i)
            idx, valid = item.data(Qt.UserRole).toInt()
            if valid:
                if isinstance(self._items[idx], QString):
                    items.append(str(self._items[idx].toUtf8()))
                else:
                    items.append(str(self._items[idx]))
        return items


# Specialization of ListItem for nodes
class NodeListItem(ListItem):
    def __init__(self, parent=None):
        ListItem.__init__(self, parent)


    def getItems(self):
        items = []
        for i in xrange(0, self.count()):
            item = self.item(i)
            idx, valid = item.data(Qt.UserRole).toInt()
            if valid:
                uid = self._items[idx]
                node = VFS.Get().getNodeById(uid)
                items.append(node)
        return items
