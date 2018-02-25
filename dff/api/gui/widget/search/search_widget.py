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
#  Jeremy MOUNIER <jmo@digital-forensic.org>
# 
import os
import sys
from os.path import exists, expanduser, normpath

from PyQt4 import QtCore, QtGui
from PyQt4.QtCore import QVariant, SIGNAL, QThread, Qt, QFile, QIODevice, QStringList, QRect, SLOT, QEvent, QString, QSignalMapper, pyqtSignal, pyqtSlot, SLOT
from PyQt4.QtGui import QWidget, QDateTimeEdit, QLineEdit, QHBoxLayout, QLabel, QPushButton, QMessageBox, QListWidget, QTableWidget, QTableWidgetItem, QAbstractItemView, QIcon, QInputDialog, QTableView, QMessageBox, QVBoxLayout, QComboBox, QCheckBox, QHeaderView, QDialog, QTreeWidget, QIntValidator, QDialogButtonBox, QApplication, QCursor, QFileDialog, QSizePolicy, QLayout, QSplitter, QTextEdit, QTreeWidgetItem

from dff.api.vfs import vfs
from dff.api.vfs.libvfs import VFS, Node, VLink, TagsManager
from dff.api.types.libtypes import Variant, typeId, ConfigManager
from dff.api.filters.libfilters import Filter

from dff.api.gui.widget.search.thread import SearchThread
from dff.api.gui.widget.search.dico_manager import DicoDialog
from dff.api.gui.widget.search.predefilters import DEFAULT_FILTERS

from dff.ui.gui.widget.SelectMimeTypes import MimeTypesTree
from dff.ui.gui.resources.ui_filter_add import Ui_filterAdd
from dff.ui.gui.resources.ui_filter_mime import Ui_filterMime
from dff.ui.gui.resources.ui_filter_dico import Ui_filterDico
from dff.ui.gui.resources.ui_filter_only import Ui_filterOnly
from dff.ui.gui.resources.ui_search_panel import Ui_searchPanel
from dff.ui.gui.resources.ui_filter_fields import Ui_filterFields
from dff.ui.gui.resources.ui_filter_matchmode import Ui_filterMatchMode
from dff.ui.gui.resources.ui_filter_attributes import Ui_filterAttributes
from dff.ui.gui.resources.ui_filter_mimedialog import Ui_filterMimeDialog
from dff.ui.gui.resources.ui_search_customtable import Ui_searchCustomTable
from dff.ui.gui.resources.ui_filter_conjunction import Ui_filterConjunction

# DEFINES COLUMNS
FIELDS = ["name", "data", "size", "time", "type", "dico", "deleted", "file", "attributes", "path", "extension", "tags", "module", "expression"]

SPECIAL_FIELDSID = range(5, 9)
CONJONCTIONS = ["and", "and not", "or", "or not"]
#ONLY = ["deleted", "file"]
MATCHMODE = ["w(", "re(", "fz(", "f("]
OPERATORS = ["<", "<=", "==", "!=", ">=", ">"]
SIZE_T = [1024, 1024*1024, 1024*1024*1024]
DICO_TYPE = ["name", "data"]
DICO_MATCH = [" any of ", " all of ", " none of "]

class SearchPanel(Ui_searchPanel, QWidget):
  def __init__(self, parent, searchview):
    super(QWidget, self).__init__(parent)
    self.setupUi(self)
    self.filters = CustomFiltersTable(self)
    self.searchFiltersLayout.addWidget(self.filters)
    self.browser = parent
    self.vfs = vfs.vfs()
    self.model = searchview.model
    self.searchview = searchview

    self.matched = 0
    self.searchTH = SearchThread(self)

    self.qmode = {0: "$",
                  1: "/",
                  2: "~",
                  3: "\""}
    self.configure()

  def configure(self):
    # Quick search
    self.connect(self.quickSearch, SIGNAL("clicked(bool)"), self.quickSearchMode)
    # Thread
    self.connect(self.startButton, SIGNAL("clicked(bool)"), self.startSearch)
    self.connect(self.stopButton, SIGNAL("clicked(bool)"), self.searchTH.stopSearch)
    self.connect(self.searchTH, SIGNAL("count"), self.updateProgressbar)
    self.connect(self.searchTH, SIGNAL("match"), self.updateMatchedNodes)
    self.connect(self.searchTH, SIGNAL("finished"), self.searchStoped)
    self.connect(self.searchTH, SIGNAL("started"), self.searchStarted)
    self.connect(self.searchTH, SIGNAL("stoped"), self.searchStoped)
    # Advanced search 
    self.connect(self.advancedSearch, SIGNAL("clicked(bool)"), self.advancedSearchMode)
    # Typebuttons
    self.connect(self.imageType, SIGNAL("clicked()"), self.buttonClicked)
    self.connect(self.videoType, SIGNAL("clicked()"), self.buttonClicked)
    self.connect(self.soundType, SIGNAL("clicked()"), self.buttonClicked)
    self.connect(self.documentType, SIGNAL("clicked()"), self.buttonClicked)
  
  def buttonClicked(self):
    if not self.buttonsChecked():
      self.quickEdit.setEnabled(True)
      self.quickMode.setEnabled(True)
    else:
      self.quickEdit.setEnabled(False)
      self.quickMode.setEnabled(False)
#    self.refreshQueryEdit()
  
  def buttonsChecked(self):
    self.quickEdit.clear()
    if self.imageType.isChecked() or self.videoType.isChecked() or self.soundType.isChecked() or self.documentType.isChecked():
      self.quickEdit.insert(self.generateButtonsClicked())
      return True
    return False

  def generateButtonsClicked(self):
    r = ""
    count = 0
    if self.imageType.isChecked():
      r += DEFAULT_FILTERS["Images"]
      count += 1
    if self.videoType.isChecked():
      if count != 0:
        r += " or "
      r += DEFAULT_FILTERS["Videos"]
      count += 1
    if self.soundType.isChecked():
      if count != 0:
        r += " or "
      r += DEFAULT_FILTERS["Audios"]
      count += 1
    if self.documentType.isChecked():
      if count != 0:
        r += " or "
      r += DEFAULT_FILTERS["Documents"]
      count += 1
    return r

  def startSearch(self):
    query = self.buildQuery()
    if query != None:
      if self.fromRoot.isChecked():
        rootnode = self.vfs.getnode("/")
      else:
        rootnode = self.browser.navigation.currentNode
      if self.browser.filter.isChecked():
        self.browser.viewpan.setCurrentWidget(self.browser.searchview)
      self.model.clearList()
      self.matchedNodeLabel.setText("0")
      self.matched = 0
      r = self.searchTH.setContext(query, rootnode, self.model)
      if r:
        self.searchTH.start()
    else:
      box = QMessageBox(QMessageBox.Critical, self.tr("Error"), self.tr("Please, specify your query"), \
                          QMessageBox.NoButton, self)
      box.exec_()

  def buildQuery(self):
    if self.quickSearch.isChecked():
      query = ""
      if self.quickEdit.text() != "":
        # Check if buttons are checked
        if not self.quickEdit.isEnabled():
          query += str(unicode(self.quickEdit.text()).encode('utf-8'))
        else:
          if self.quickMode.currentIndex() in xrange(0,4):
            pat = self.qmode[self.quickMode.currentIndex()]
            query += "name matches" + pat + str(unicode(self.quickEdit.text()).encode('utf-8')) + pat
          else:
            query += str(unicode(self.quickEdit.text()).encode('utf-8'))
      else:
        return None
      return query
    else:
      return self.filters.buildAllQueries()
      
  def updateProgressbar(self, count):
    self.searchProgress.setValue(count)

  def updateMatchedNodes(self):
    self.matched += 1
    self.matchedNodeLabel.setText(str(self.matched))
    self.searchview.refreshVisible()

  def searchStarted(self):
    self.searchProgress.setValue(0)
    self.matchedNodeLabel.setText(QString("0"))
    self.startButton.setEnabled(False)
    self.stopButton.setEnabled(True)

  def searchStoped(self):
    self.startButton.setEnabled(True)
    self.stopButton.setEnabled(False)
    if self.browser.filter.isChecked():
      self.browser.viewpan.setCurrentWidget(self.browser.filterview)
      self.browser.filterwidget.resetFilter()
    self.emit(SIGNAL("finished()"))

  def quickSearchMode(self, state):
    if state:
      self.advancedSearch.setChecked(False)
    else:
      self.advancedSearch.setChecked(True)

  def advancedSearchMode(self, state):
    if state:
      self.quickSearch.setChecked(False)
    else:
      self.quickSearch.setChecked(True)

# Search filter widget
class CustomFiltersTable(Ui_searchCustomTable, QWidget):
  def __init__(self, parent = None):
    super(QWidget, self).__init__(parent)
    self.setupUi(self)
    self.table.verticalHeader().hide()
    self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
    self.table.setSelectionMode(QAbstractItemView.SingleSelection)
    self.table.setColumnWidth(0, 180)
    self.filters = []
    self.enabled = []

    self.connect(self.newButton, SIGNAL("clicked(bool)"), self.add)
    self.connect(self.deleteButton, SIGNAL("clicked(bool)"), self.remove)
    self.connect(self.editButton, SIGNAL("clicked(bool)"), self.edit)
    self.connect(self.table, SIGNAL("cellClicked(int, int)"), self.cellClick)
    self.connect(self.loadButton, SIGNAL("clicked(bool)"), self.load)
    self.connect(self.saveButton, SIGNAL("clicked(bool)"), self.save)

    self.editButton.setEnabled(False)
    self.deleteButton.setEnabled(False)
    self.saveButton.setEnabled(False)
    
  def buildAllQueries(self):
    query = ""
    enabled = 0
    filters = self.get()
    for count, filt in enumerate(filters):
      if self.filterEnabled(filt):
        if enabled > 0:
          query += " and "
        query += filt.buildRequest()
        enabled += 1
    if query != "":
      return query
    else:
      return None

  def cellClick(self, row, col):
    try:
      filt = self.filters[row]
      self.deleteButton.setEnabled(True)
      if filt.isEditable():
        self.editButton.setEnabled(True)
      else:
        self.editButton.setEnabled(False)
      if self.filterEnabled(filt):
        self.saveButton.setEnabled(True)
      else:
        self.saveButton.setEnabled(False)
    except:
      pass

  def addFilter(self, name, query):
    filt = Filter(self, name, query)
    currow = self.table.rowCount()
    self.table.setRowCount(self.table.rowCount() + 1)
    name = QTableWidgetItem(QString(name))
    name.setFlags(Qt.ItemIsSelectable|Qt.ItemIsEnabled)
    self.table.setItem(currow, 0, name)
    check = QCheckBox()
    check.setChecked(True)
    self.filters.append(filt)
    self.emit(SIGNAL("filterAdded"))
    self.table.horizontalHeader().setResizeMode(1, QHeaderView.ResizeToContents)

  def add(self):
    filt = Filter(self)
    ret = filt.exec_()
    if ret == 1:
      currow = self.table.rowCount()
      self.table.setRowCount(self.table.rowCount() + 1)
      name = QTableWidgetItem(QString(filt.name()))
      name.setFlags(Qt.ItemIsSelectable|Qt.ItemIsEnabled)
      self.table.setItem(currow, 0, name)
      check = QCheckBox()
      check.setChecked(True)
      self.table.setCellWidget(currow, 1, check)
      self.filters.append(filt)
      self.emit(SIGNAL("filterAdded"))
      self.table.horizontalHeader().setResizeMode(1, QHeaderView.ResizeToContents)

  def remove(self):
    row = self.table.currentRow()
    if row >= 0:
      self.filters.pop(row)
      self.table.removeRow(row)
      self.emit(SIGNAL("filterRemoved"))
      if len(self.filters) == 0:
        self.editButton.setEnabled(False)

  def edit(self):
    row = self.table.currentRow()
    filt = self.filters[row]
    ret = filt.exec_()
    if ret == 1:
      cell = self.table.currentItem()
      cell.setText(QString(filt.name()))

  def get(self):
    return self.filters

  def closeEvent(self, event):
    pass

  def filterEnabled(self, filt):
    for count, f in enumerate(self.filters):
      if f == filt:
        state = self.table.cellWidget(count, 1).checkState()
        if state == Qt.Unchecked:
          return False
        else:
          return True

  def selectedFilters(self):
    f = []
    for count, filt in enumerate(self.filters):
      state = self.table.cellWidget(count, 1).checkState()
      if state == Qt.Checked:
        f.append(filt)
    return f

  def save(self):
    fdial = QFileDialog()
    sFileName = fdial.getSaveFileName(self, "Save as", os.path.expanduser('~'))
    if sFileName != "":
      sFileName += ".py"
      ufn = str(unicode(sFileName).encode('utf-8'))
      f = open(ufn, "w")
      filts = self.selectedFilters()
      buff = "# -*- coding: utf-8 -*-\n"
      buff += "FILTERS = {\n"
      for filt in filts:
        buff += "\t" + "\"" + filt.name() + "\"" + " : " + "'" + filt.buildRequest() + "'" + ",\n"
      buff += "}\n"
      f.write(buff)
      f.close

  def load(self):
    fdial = QFileDialog()
    sFileName = fdial.getOpenFileName(self, "Save as", os.path.expanduser('~'), "Python (*.py)")
    if sFileName != "":
      try:
        ufn = str(unicode(sFileName).encode('utf-8'))
        location = os.path.dirname(ufn)
        basename = os.path.basename(ufn)
        modname = os.path.splitext(basename)
        sys.path.append(location)
        f = __import__(modname[0])
        for name, query in f.FILTERS.iteritems():
          self.addFilter(name, query)
      except:
        pass


class Filter(Ui_filterAdd, QDialog):
  def __init__(self, filtertable, fname=None, query=None):
    super(QDialog, self).__init__(filtertable)
    self.filtertable = filtertable
    self.setupUi(self)
    self.editable = False
    self.defaultquery = None
    self.fname = None
    sizePolicy = QSizePolicy(QSizePolicy.Minimum, QSizePolicy.Minimum)
    sizePolicy.setHorizontalStretch(1)
    sizePolicy.setVerticalStretch(1)
    self.setSizePolicy(sizePolicy)
    self.requestLayout.setSpacing(6)
    self.requestLayout.setSizeConstraint(QLayout.SetMinimumSize)
    self.requestLayout.setMargin(0)
    self.__splitter = QSplitter(Qt.Vertical)
    self.__splitter.setHandleWidth(12)
    self.requestLayout.addWidget(self.__splitter)
    self.__query = QTextEdit()
    self.__query.setReadOnly(True)
    if (fname == None) and (query == None):
      self.editable = True
      self.filterRequest = FilterRequests(self)
      self.connect(self.filterRequest, SIGNAL("queryUpdated"), self.updateQuery)
      self.__splitter.addWidget(self.filterRequest)
      self.__splitter.addWidget(self.__query)
      self.__splitter.setStretchFactor(0, 80)
      self.__splitter.setStretchFactor(1, 20)
    else:
      self.defaultquery = query
      self.fname = fname

  def updateQuery(self):
    query = self.buildRequest()
    self.__query.setText(query)

  def reject(self):
    QDialog.reject(self)

  def accept(self):
    if not self.name().isEmpty():
      QDialog.accept(self)
    else:
      box = QMessageBox(QMessageBox.Critical, self.tr("Error"), self.tr("Please, specify a query name"), \
                          QMessageBox.NoButton, self)
      box.exec_()
    
  def isEditable(self):
    return self.editable

  def name(self):
    if self.editable:
      return self.filterName.text()
    else:
      return self.fname

  def buildRequest(self):
    if self.editable:
      row = 0
      res = "("
      while row < self.filterRequest.rowCount():
        if row > 0:
          conj = self.filterRequest.cellWidget(row, 0)
          res += " " + CONJONCTIONS[conj.conjunctionCombo.currentIndex()] + " "
        widget = self.filterRequest.cellWidget(row, 2)
        res +=  widget.request()
        row += 1
      res += ")"
      return res
    else:
      return self.defaultquery

class FilterRequests(QTableWidget):
  def __init__(self, parent = None):
    super(QTableWidget, self).__init__(parent)
    self.parent = parent
    self.configure()
    # Keep a list of FieldCombo object
    self.fieldMapper = []
    self.removeMapper = []
    self.addRequest()

  def configure(self):
    self.setColumnCount(5)
    self.setRowCount(0)
    self.verticalHeader().setDefaultSectionSize(30)
    self.horizontalHeader().setDefaultSectionSize(30)
    self.horizontalHeader().setResizeMode(1, QHeaderView.ResizeToContents)
    self.horizontalHeader().setResizeMode(2, QHeaderView.Stretch)
    self.horizontalHeader().setResizeMode(3, QHeaderView.ResizeToContents)
    self.horizontalHeader().setResizeMode(4, QHeaderView.ResizeToContents)
    self.setSelectionMode(QAbstractItemView.NoSelection)
    self.horizontalHeader().setStretchLastSection(False)
    self.setShowGrid(False)
    self.horizontalHeader().hide()
    self.verticalHeader().hide()

  def addRequest(self, widget=None):
    currow = self.rowCount()
    self.setRowCount(self.rowCount() + 1)
    # Add conjonctions if not First widget
    if len(self.fieldMapper) != 0:
      conjonction = ConjonctionCombo(self)
      self.connect(conjonction, SIGNAL("queryUpdated"), self.updateQuery)
      self.setCellWidget(currow, 0, conjonction)
      self.horizontalHeader().setResizeMode(0, QHeaderView.ResizeToContents)
    else:
      empty = QTableWidgetItem(QString(""))
      empty.setFlags(Qt.ItemIsSelectable|Qt.ItemIsEnabled)
      self.setItem(currow, 0, empty)
    # Add Field choice
    fields = FieldCombo(self)
    self.connect(fields, SIGNAL("fieldChanged"), self.changeFilterType)
    self.setCellWidget(currow, 1,  fields)
    self.fieldMapper.append(fields.fieldCombo)
    # Add Widget
    if widget == None:
      widget = StringRequest(self, 'name')
    self.connect(widget, SIGNAL("queryUpdated"), self.updateQuery)
    self.setCellWidget(currow, 2, widget)
    # Add request button
    add = self.createAddRequestButton()
    self.setCellWidget(currow, 3, add)
    # Remove request button
    rm = removeRequestButton()
    self.removeMapper.append(rm)
    self.connect(rm, SIGNAL("removeRequest"), self.removeRequest)
    self.setCellWidget(currow, 4, rm)
    self.updateQuery()
  
  def updateQuery(self):
    self.emit(SIGNAL("queryUpdated"))

  def changeFilterType(self, fieldwidget, index):
    # ["name", "data", "size", "time", "mime", "file", "deleted", "attributes"]
    if fieldwidget in self.fieldMapper:
      row = self.fieldMapper.index(fieldwidget)
      ftype = fieldwidget.currentIndex()
      if ftype == FIELDS.index("name"):
        widget = StringRequest(self, FIELDS[ftype])
      elif ftype == FIELDS.index("data"):
        widget = StringRequest(self, FIELDS[ftype])
      elif ftype == FIELDS.index("size"):
        widget = SizeRequest(self)
      elif ftype == FIELDS.index("time"):
        widget = DateRequest(self)
      elif ftype == FIELDS.index("type"):
        widget = MimeRequest(self)
      elif ftype == FIELDS.index("dico"):
        widget = DicoRequest(self)
      elif ftype == FIELDS.index("deleted"):
        widget = OnlyRequest(self, field="deleted")
      elif ftype == FIELDS.index("file"):
        widget = OnlyRequest(self, field="file")
      elif ftype == FIELDS.index("attributes"):
        widget = AttributeRequest(self)
      elif ftype == FIELDS.index("extension"):
        widget = StringRequest(self, FIELDS[ftype])
      elif ftype == FIELDS.index("path"):
        widget = StringRequest(self, FIELDS[ftype])
      elif ftype == FIELDS.index("tags"):
        widget = TagRequest(self)
      elif ftype == FIELDS.index("module"):
        widget = ModuleRequest(self)
      elif ftype == FIELDS.index("expression"):
        widget = RawStringRequest(self)
      else:
        return
      self.connect(widget, SIGNAL("queryUpdated"), self.updateQuery)
      self.setCellWidget(row, 2, widget)
      self.updateQuery()

  def removeRequest(self, rmbutton):
    if (rmbutton in self.removeMapper):
      if self.removeMapper.index(rmbutton) > 0:
        row = self.removeMapper.index(rmbutton)
        self.removeRow(row)
        self.fieldMapper.pop(row)
        self.removeMapper.pop(row)
        self.updateQuery()

  def createAddRequestButton(self):
    addRequestButton = QPushButton()
    addRequestButton.setIcon(QIcon(":add.png"))
    self.connect(addRequestButton, SIGNAL("clicked()"), self.addRequest)
    return addRequestButton

class removeRequestButton(QPushButton):
  def __init__(self):
    QPushButton.__init__(self)
    self.setIcon(QIcon(":remove.png"))
    self.connect(self, SIGNAL("clicked(bool)"), self.removeMapper)

  def removeMapper(self):
    self.emit(SIGNAL("removeRequest"), self)

class Request(QWidget):
  def __init__(self, parent):
    QWidget.__init__(self, parent)
    self.hlayout = QHBoxLayout(self)
    self.hlayout.setMargin(2)
    self.setLayout(self.hlayout)

class ConjonctionCombo(Ui_filterConjunction, Request):
  def __init__(self, parent):
    Request.__init__(self, parent)
    self.setupUi(self)
    self.hlayout.addWidget(self.conjunctionCombo)
    self.connect(self.conjunctionCombo, SIGNAL("currentIndexChanged ( int )"), self.updateQuery)
    self.connect(self.conjunctionCombo, SIGNAL("currentIndexChanged ( const QString &)"), self.updateQuery)

  def updateQuery(self, data):
    self.emit(SIGNAL("queryUpdated"))


class RawStringRequest(Request):
  def __init__(self, parent):
    Request.__init__(self, parent)
    self.setContent()

  def setContent(self):
    self.lineEdit = QLineEdit()
    self.hlayout.addWidget(self.lineEdit)
    self.connect(self.lineEdit, SIGNAL("textChanged(const QString &)"), self.updateQuery)
    self.connect(self.lineEdit, SIGNAL("textEdited(const QString &)"), self.updateQuery)

  def updateQuery(self, data):
    self.emit(SIGNAL("queryUpdated"))

  def request(self):
    # XXX Unicode ?
    return "(" + self.lineEdit.text() + ")"


class StringRequest(Ui_filterMatchMode, Request):
  def __init__(self, parent, keyword):
    Request.__init__(self, parent)
    self.key = keyword
    self.setupUi(self)
    self.setContent()
    self.setMatchMode()
    self.setCase()
    self.connect(self.matchModeCombo, SIGNAL("currentIndexChanged ( int )"), self.updateQuery)
    self.connect(self.matchModeCombo, SIGNAL("currentIndexChanged ( const QString &)"), self.updateQuery)

  def updateQuery(self, data):
    self.emit(SIGNAL("queryUpdated"))

  def setContent(self):
    self.content = QLineEdit(self)
    self.hlayout.addWidget(self.content)
    self.connect(self.content, SIGNAL("textChanged(const QString &)"), self.updateQuery)
    self.connect(self.content, SIGNAL("textEdited(const QString &)"), self.updateQuery)

  def setMatchMode(self):
    self.hlayout.addWidget(self.matchModeCombo)

  def setCase(self):
    self.casse.setChecked(True)
    self.hlayout.addWidget(self.casse)
    self.connect(self.casse, SIGNAL("stateChanged ( int )"), self.updateQuery)

  def request(self):
    result = "("
    result += self.key + " matches "
    result += MATCHMODE[self.matchModeCombo.currentIndex()]
    result += "\"" + str(unicode(self.content.text()).encode('utf-8')) + self.case() + ")"
    return result

  def case(self):
    if not self.casse.isChecked():
      return  "\",i)"
    else:
      return "\")"


class SizeRequest(Request):
  def __init__(self, parent):
    Request.__init__(self, parent)
    self.setOperators()
    self.setContent()
    self.setSizeType()

  def setOperators(self):
    self.operatorCombo = OperatorCombo(self)
    self.hlayout.addWidget(self.operatorCombo)
    self.connect(self.operatorCombo, SIGNAL("currentIndexChanged ( int )"), self.updateQuery)
    self.connect(self.operatorCombo, SIGNAL("currentIndexChanged ( const QString &)"), self.updateQuery)

  def updateQuery(self, data):
    self.emit(SIGNAL("queryUpdated"))

  def setContent(self):
    self.content = QLineEdit(self)
    self.validator = QIntValidator(0,2147483647, self)
    self.content.setValidator(self.validator)
    self.hlayout.addWidget(self.content)
    self.connect(self.content, SIGNAL("textChanged(const QString &)"), self.updateQuery)
    self.connect(self.content, SIGNAL("textEdited(const QString &)"), self.updateQuery)

  def setSizeType(self):
    self.stype = QComboBox(self)
    self.stype.addItem(QString("KB"))
    self.stype.addItem(QString("MB"))
    self.stype.addItem(QString("GB"))
    self.hlayout.addWidget(self.stype)
    self.connect(self.stype, SIGNAL("currentIndexChanged ( int )"), self.updateQuery)
    self.connect(self.stype, SIGNAL("currentIndexChanged ( const QString &)"), self.updateQuery)

  def request(self):
    operator = str(self.operatorCombo.currentText())
    factor = SIZE_T[self.stype.currentIndex()]
    size = self.content.text().toULongLong()[0]
    size = size * factor
    res = "(size " + operator + " " + str(size) + ")"
    return res


class DateRequest(Request):
  def __init__(self, parent):
    Request.__init__(self, parent)
    self.setOperators()
    self.setDateTime()

  def setOperators(self):
    self.operatorCombo = OperatorCombo(self)
    self.hlayout.addWidget(self.operatorCombo)
    self.connect(self.operatorCombo, SIGNAL("currentIndexChanged ( int )"), self.updateQuery)
    self.connect(self.operatorCombo, SIGNAL("currentIndexChanged ( const QString &)"), self.updateQuery)

  def updateQuery(self, data):
    self.emit(SIGNAL("queryUpdated"))

  def setDateTime(self):
    self.datetime = QDateTimeEdit(self)
    self.datetime.setCalendarPopup(True)
    self.hlayout.addWidget(self.datetime, 50)
    self.connect(self.datetime, SIGNAL("dateChanged ( const QDate &)"), self.updateQuery)
    self.connect(self.datetime, SIGNAL("dateTimeChanged ( const QDateTime &)"), self.updateQuery)
    self.connect(self.datetime, SIGNAL("timeChanged ( const QTime &)"), self.updateQuery)

  def request(self):
    res = "(time " +  str(self.operatorCombo.currentText())
    date_time = self.datetime.dateTime()
    res += str(date_time.toString("yyyy-MM-ddThh:mm:ss")) + ")"
    return res


class MimeRequest(Ui_filterMime, Request):
  def __init__(self, parent):
    Request.__init__(self, parent)
    self.setupUi(self)
    self.setContent()
    self.setSelectButton()
    #XXX
    # temporary workaround to maintain selected items
    # issue is that it won't populate new types if it happens
    self.dialog = MimeDialog(self)

  def setContent(self):
    self.content.setReadOnly(True)
    self.hlayout.addWidget(self.content, 50)
    self.connect(self.content, SIGNAL("textChanged(const QString &)"), self.updateQuery)
    self.connect(self.content, SIGNAL("textEdited(const QString &)"), self.updateQuery)

  def updateQuery(self, data):
    self.emit(SIGNAL("queryUpdated"))

  def setSelectButton(self):
    self.hlayout.addWidget(self.selectButton)
    self.connect(self.selectButton, SIGNAL("clicked()"), self.selectMimeDialog)

  def selectMimeDialog(self):
    ret = self.dialog.exec_()
    if ret == 1:
      result = self.dialog.selectedTypes()
      self.content.clear()
      self.content.setText(result)

  def request(self):
    res = "(type in[" + str(unicode(self.content.text()).encode('utf-8')) + "])"
    return res


class TagRequest(Request):
  def __init__(self, parent):
    Request.__init__(self, parent)
    self.tagsmanager = TagsManager.get()
    self.selectedTags = []
    self.content = QLineEdit(self)
    self.connect(self.content, SIGNAL("textChanged(const QString &)"), self.updateQuery)
    self.connect(self.content, SIGNAL("textEdited(const QString &)"), self.updateQuery)
    self.content.setReadOnly(True)
    self.selectButton = QPushButton(self.tr("Select ..."))
    self.connect(self.selectButton, SIGNAL("clicked()"), self.selectTagsDialog)
    self.layout().addWidget(self.content, 50) 
    self.layout().addWidget(self.selectButton)
    

  def updateQuery(self, data):
    self.emit(SIGNAL("queryUpdated"))

    
  def selectTagsDialog(self):
    dialog = ListSelectionDialog(self, self.tr("Select tags to look for"))
    tags = self.tagsmanager.tags()
    tags = [unicode(tag.name(), 'utf-8') for tag in tags]    
    dialog.populate(tags, self.selectedTags)
    ret = dialog.exec_()
    if ret == 1:
      self.selectedTags = dialog.selectedItems()
      query = ""
      for tag in self.selectedTags:
        if len(query):
          query += ', "'+ str(tag.toUtf8()) + '"'
        else:
          query += '"'+ str(tag.toUtf8()) + '"'
      self.content.setText(query)


  def request(self):
    res = "(tags in[" + str(unicode(self.content.text()).encode('utf-8')) + "])"
    return res


class ModuleRequest(Request):
  def __init__(self, parent):
    Request.__init__(self, parent)
    self.configs = ConfigManager.Get()
    self.selectedModules = []
    self.content = QLineEdit(self)
    self.connect(self.content, SIGNAL("textChanged(const QString &)"), self.updateQuery)
    self.connect(self.content, SIGNAL("textEdited(const QString &)"), self.updateQuery)
    self.content.setReadOnly(True)
    self.selectButton = QPushButton(self.tr("Select ..."))
    self.connect(self.selectButton, SIGNAL("clicked()"), self.selectModuleDialog)
    self.layout().addWidget(self.content, 50) 
    self.layout().addWidget(self.selectButton)
    self.selectedModules = []

  def updateQuery(self, data):
    self.emit(SIGNAL("queryUpdated"))

    
  def selectModuleDialog(self):
    modules = []
    configs = self.configs.configs()
    for config in configs:
      mime = config.constantByName("mime-type")
      ext = config.constantByName("extension-type")
      modname = config.origin()
      if modname.find("viewer") == -1:
        if mime is not None:
          modules.append(config.origin())
        elif ext is not None:
          modules.append(config.origin())
    dialog = ListSelectionDialog(self, self.tr("Select modules to look for"))
    dialog.populate(modules, self.selectedModules)
    ret = dialog.exec_()
    if ret == 1:
      self.selectedModules = dialog.selectedItems()
      query = ""
      for module in self.selectedModules:
        if len(query):
          query += ', "'+ str(module.toUtf8()) + '"'
        else:
          query += '"'+ str(module.toUtf8()) + '"'
      self.content.setText(query)


  def request(self):
    res = "(module in [" + str(unicode(self.content.text()).encode('utf-8')) + "])"
    return res


class ListSelectionDialog(Ui_filterMimeDialog, QDialog):
  def __init__(self, parent, title):
    QDialog.__init__(self, parent)
    self.setupUi(self)
    self.setWindowTitle(title)
    self.items = []

    
  def populate(self, items, selected):
    for item in items:
      treeItem = QTreeWidgetItem(self.treeWidget)
      treeItem.setFlags(Qt.ItemIsUserCheckable|Qt.ItemIsEnabled|Qt.ItemIsSelectable)
      if item in selected:
        treeItem.setCheckState(0, Qt.Checked)
      else:
        treeItem.setCheckState(0, Qt.Unchecked)
      treeItem.setText(0, item)
      self.items.append(treeItem)
    self.treeWidget.resizeColumnToContents(0)
    
    
  def selectedItems(self):
    selected = []
    for item in self.items:
      i = 0
      if item.checkState(0) == Qt.Checked:
        selected.append(item.text(0))
    return selected

    
class MimeDialog(Ui_filterMimeDialog, QDialog):
  def __init__(self, parent):
    QDialog.__init__(self, parent)
    self.setupUi(self)
    self.setWindowTitle(self.tr("Select types to look for"))
    self.mime = MimeTypesTree(self.treeWidget)

  def selectedTypes(self):
    mimes = self.mime.selectedItems()
    result = ""
    for count, mime in enumerate(mimes):
      result += "\"" + mime + "\""
      if count < len(mimes) - 1:
        result += ","
    return result


class DicoRequest(Ui_filterDico, Request):
  def __init__(self, parent):
    Request.__init__(self, parent)
    self.setupUi(self)
    self.setContent()
    self.dicos = []

  def setContent(self):
    self.hlayout.addWidget(self.dicoPath, 50)
    self.hlayout.addWidget(self.dicoManager, 5)
    self.hlayout.addWidget(self.dicoType, 10)
    self.hlayout.addWidget(self.dicoMatch, 10)
    self.connect(self.dicoManager, SIGNAL("clicked()"), self.selectDico)
    self.connect(self.dicoPath, SIGNAL("textChanged(const QString &)"), self.updateQuery)
    self.connect(self.dicoPath, SIGNAL("textEdited(const QString &)"), self.updateQuery)
    self.connect(self.dicoType, SIGNAL("currentIndexChanged ( int )"), self.updateQuery)
    self.connect(self.dicoType, SIGNAL("currentIndexChanged ( const QString &)"), self.updateQuery)
    self.connect(self.dicoMatch, SIGNAL("currentIndexChanged ( int )"), self.updateQuery)
    self.connect(self.dicoMatch, SIGNAL("currentIndexChanged ( const QString &)"), self.updateQuery)

  def updateQuery(self, data):
    self.emit(SIGNAL("queryUpdated"))

  def selectDico(self):
    dialog = DicoDialog(self)
    r = dialog.exec_()
    if r > 0:
      self.dicos = dialog.manager.selectedDicoNames()
      if self.dicos != None:
        label = str()
        for dico in self.dicos:
          label += dico
        self.dicoPath.clear()
        self.dicoPath.insert(QString.fromUtf8(label))

  def request(self):
    res = str("(")
    if len(self.dicos) > 0:
      res += DICO_TYPE[self.dicoType.currentIndex()] + " matches"
      res += DICO_MATCH[self.dicoMatch.currentIndex()] + "["
      for count, dico in enumerate(self.dicos):
        res += dico + ":"
        if count < len(self.dicos) - 1:
          res += ","
      res += "])"
    return res
     
 
class OnlyRequest(Ui_filterOnly, Request):
  def __init__(self, parent, field):
    Request.__init__(self, parent)
    self.setupUi(self)
    self.field = field
    self.setOnly()

  def setOnly(self):
    self.hlayout.addWidget(self.onlyCombo)
    self.connect(self.onlyCombo, SIGNAL("currentIndexChanged ( int )"), self.updateQuery)
    self.connect(self.onlyCombo, SIGNAL("currentIndexChanged ( const QString &)"), self.updateQuery)

  def updateQuery(self, data):
    self.emit(SIGNAL("queryUpdated"))

  def request(self):
    index = self.onlyCombo.currentIndex()
    # Deleted
    if self.field == "deleted":
      res = "(deleted == "
    elif self.field == "file":
      res = "(file == "
    # Files
    if index == 0:
      res += "true)"
    else:
      res += "false)"
    return res


class AttributeRequest(Ui_filterAttributes, Request):
  def __init__(self, parent, iss=True):
    Request.__init__(self, parent)
    self.setupUi(self)
    self.setOperators()
    self.setShape()

  def setOperators(self):
    self.operatorCombo = OperatorCombo(self, attrmode=True)
    self.hlayout.addWidget(self.operatorCombo)

  def setShape(self):
    self.hlayout.addWidget(self.key)
    self.hlayout.addWidget(self.operatorCombo)
    self.hlayout.addWidget(self.value)
    self.connect(self.key, SIGNAL("textChanged(const QString &)"), self.updateQuery)
    self.connect(self.key, SIGNAL("textEdited(const QString &)"), self.updateQuery)
    self.connect(self.value, SIGNAL("textChanged(const QString &)"), self.updateQuery)
    self.connect(self.value, SIGNAL("textEdited(const QString &)"), self.updateQuery)
    self.connect(self.operatorCombo, SIGNAL("currentIndexChanged ( int )"), self.updateQuery)
    self.connect(self.operatorCombo, SIGNAL("currentIndexChanged ( const QString &)"), self.updateQuery)

  def updateQuery(self, data):
    self.emit(SIGNAL("queryUpdated"))

  def request(self):
    res = "(@" + str(unicode(self.key.text()).encode('utf-8')) + "@ "
    res += str(self.operatorCombo.currentText()) + " "
    res += str(unicode(self.value.text()).encode('utf-8')) + " )"
    return res


class FieldCombo(Ui_filterFields, Request):
  def __init__(self, parent):
    Request.__init__(self, parent)
    self.setupUi(self)
    self.hlayout.addWidget(self.fieldCombo)
    self.connect(self.fieldCombo, SIGNAL("currentIndexChanged(int)"), self.indexChangedMapper)

  def indexChangedMapper(self, index):
    self.emit(SIGNAL("fieldChanged"), self.fieldCombo, index)

class OperatorCombo(QComboBox):
  def __init__(self, parent, attrmode=False):
    QComboBox.__init__(self, parent)
    if attrmode:
      self.addItem(QString("matches"))
    for op in OPERATORS:
      self.addItem(QString(op))
