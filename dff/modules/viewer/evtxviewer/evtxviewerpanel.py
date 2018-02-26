# DFF -- An Open Source Digital Forensics Framework
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
#  Romain BERTHOLON < rbe@digital-forensic.fr>
#

from PyQt4.QtCore import QSize, SIGNAL, QString, Qt, QObject,  SIGNAL, PYQT_VERSION_STR, QMetaObject, QCoreApplication
from PyQt4.QtGui import QWidget, QVBoxLayout, QIcon, QMessageBox, QTableWidget, QTableWidgetItem, QHeaderView, QPixmap, QAbstractItemView, QDialog, QSplitter, QPushButton, QSpacerItem, QComboBox, QLabel, QLineEdit, QDateTimeEdit, QListWidget, QListWidgetItem, QHBoxLayout, QTextEdit, QMenu, QCursor, QApplication, QSizePolicy, QTabWidget, QTreeView, QDialogButtonBox 

from xml.etree.ElementTree import dump, tostring

from dff.api.vfs.libvfs import VFS
from dff.api.module.manager import ModuleProcessusManager

from dff.modules.evtx.record import EvtxInfo
from dff.modules.evtx.evtx_xml import EvtxXml
from dff.modules.evtxviewer.evtxviewertree import EvtxTree


try:
    _fromUtf8 = QString.fromUtf8
except AttributeError:
    _fromUtf8 = lambda s: s

class Ui_ViewEvtx(object):
    def setupUi(self, ViewEvtx):
        ViewEvtx.setObjectName(_fromUtf8("ViewEvtx"))
        ViewEvtx.resize(600, 480)
        ViewEvtx.setWindowTitle(QApplication.translate("ViewEvtx", "Dialog", None, QApplication.UnicodeUTF8))

        self.mainLayout = QHBoxLayout(ViewEvtx)

        self.buttonLayout = QVBoxLayout()
        spacerItem = QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding)
        self.buttonLayout.addItem(spacerItem)

        self.next_evtx = QPushButton(QIcon(":/next.png"), "")
        self.next_evtx.setToolTip("Next record")
        self.prev_evtx = QPushButton(QIcon(":/previous.png"), "")
        self.prev_evtx.setToolTip("Previous record")

        self.buttonLayout.addWidget(self.prev_evtx)
        self.buttonLayout.addWidget(self.next_evtx)
       
        self.verticalLayout_2 = QVBoxLayout()
        self.verticalLayout_2.setObjectName(_fromUtf8("verticalLayout_2"))

        self.verticalLayout = QVBoxLayout()
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        
        self.tabWidget = QTabWidget(ViewEvtx)
        self.tabWidget.setObjectName(_fromUtf8("tabWidget"))
        self.ViewSimple = QWidget()
        self.ViewSimple.setObjectName(_fromUtf8("ViewSimple"))
        self.verticalLayout_3 = QVBoxLayout(self.ViewSimple)
        self.verticalLayout_3.setObjectName(_fromUtf8("verticalLayout_3"))
        self.view = QTreeView(self.ViewSimple)
        self.view.setObjectName(_fromUtf8("view"))
        self.view.setWordWrap(True)
        self.verticalLayout_3.addWidget(self.view)
        
        self.tabWidget.addTab(self.ViewSimple, _fromUtf8(""))
        self.ViewXml = QWidget()
        self.ViewXml.setObjectName(_fromUtf8("ViewXml"))
        self.horizontalLayout = QHBoxLayout(self.ViewXml)
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.textEdit = QTextEdit(self.ViewXml)
        self.textEdit.setReadOnly(True)
        self.textEdit.setObjectName(_fromUtf8("textEdit"))
        self.horizontalLayout.addWidget(self.textEdit)
        self.tabWidget.addTab(self.ViewXml, _fromUtf8(""))
        self.verticalLayout.addWidget(self.tabWidget)
        
        spacerItem = QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding)
        self.buttonLayout.addItem(spacerItem)

        self.buttonBox = QDialogButtonBox(ViewEvtx)
        self.buttonBox.setOrientation(Qt.Horizontal)
        self.buttonBox.setStandardButtons(QDialogButtonBox.Cancel|QDialogButtonBox.Ok)
        self.buttonBox.setObjectName(_fromUtf8("buttonBox"))
        
        self.verticalLayout.addWidget(self.buttonBox)
        self.verticalLayout_2.addLayout(self.verticalLayout)

        self.mainLayout.addLayout(self.verticalLayout_2)
        self.mainLayout.addLayout(self.buttonLayout)

        self.retranslateUi(ViewEvtx)
        self.tabWidget.setCurrentIndex(1)

        QObject.connect(self.buttonBox, SIGNAL(_fromUtf8("accepted()")), ViewEvtx.accept)
        QObject.connect(self.buttonBox, SIGNAL(_fromUtf8("rejected()")), ViewEvtx.reject)
        QMetaObject.connectSlotsByName(ViewEvtx)

    def retranslateUi(self, ViewEvtx):
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.ViewSimple), QApplication.translate("ViewEvtx", "Simple view", None, QApplication.UnicodeUTF8))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.ViewXml), QApplication.translate("ViewEvtx", "XmlView", None, QApplication.UnicodeUTF8))

class ViewEvtx(QDialog, Ui_ViewEvtx):
    def __init__(self, parent = None):
        super(QDialog, self).__init__()
        self.setupUi(self)

class EvtxAdminPannel(QWidget):
    def __init__(self, parent = None, chunks = []):
        super(EvtxAdminPannel, self).__init__(parent)
        self.verticalLayout = QVBoxLayout(self)
        spacerItem = QSpacerItem(20, 259, QSizePolicy.Minimum, QSizePolicy.Expanding)

        self.verticalLayout.setMargin(3)
        self.verticalLayout.addWidget(QLabel("Number of chunk(s) : " + str(len(chunks))))

        nb_rec = 0
        for i in chunks:
            nb_rec += i.nbRecord()

        self.nb_rec = nb_rec
        self.verticalLayout.addWidget(QLabel("Number of record(s) : " + str(nb_rec)))

        tmp_widget = QWidget()
        self.verticalLayout.addWidget(tmp_widget)
        hor_layout = QHBoxLayout(tmp_widget)
        hor_layout.addWidget(QLabel("Display :"))

        self.admin_events = QPushButton(QIcon(":/green_configure.png"), "Admin. events")
        hor_layout.addWidget(self.admin_events)

        self.choose_event_type = QComboBox()
        self.choose_event_type.addItem(QIcon(":/internet_explorer"), "All", 42)
        self.choose_event_type.addItem(QIcon(":/audit_success"), "Audit success", 0)
        self.choose_event_type.addItem(QIcon(":/audit_failure"), "Audit failure", 1)
        self.choose_event_type.addItem(QIcon(":/error"), "Error", 2)
        self.choose_event_type.addItem(QIcon(":/warning"), "Warning", 3)
        self.choose_event_type.addItem(QIcon(":/info"), "Information", 4)
        self.choose_event_type.addItem(QIcon(":/chat.png"), "Comment", 5)

        hor_layout.addWidget(self.choose_event_type)

        tmp_widget = QWidget()
        self.verticalLayout.addWidget(tmp_widget)
        hor_layout = QHBoxLayout(tmp_widget)
        self.id = QLineEdit()
        hor_layout.addWidget(QLabel("Id :"))
        self.cb = self.initId(chunks, 'id')
        self.cb.setMaxVisibleItems(15)
        hor_layout.addWidget(self.cb)
        hor_layout.addWidget(self.id)
        self.search_id = QPushButton("Go")
        hor_layout.addWidget(self.search_id)

        tmp_widget = QWidget()
        self.verticalLayout.addWidget(tmp_widget)
        hor_layout = QHBoxLayout(tmp_widget)
        self.source = QLineEdit()
        hor_layout.addWidget(QLabel("Source :"))
        self.cbs = self.initId(chunks, 'source')
        hor_layout.addWidget(self.cbs)
        hor_layout.addWidget(self.source)
        self.search_source = QPushButton("Go")
        hor_layout.addWidget(self.search_source)

        self.verticalLayout.addWidget(QLabel("Date debut :"))
        self.select_date_b = QDateTimeEdit()

        self.select_date_b.setDisplayFormat("MMM dd yyyy hh:mm AP")

        self.verticalLayout.addWidget(self.select_date_b)
        
        self.verticalLayout.addWidget(QLabel("date fin:"))
        self.select_date_e = QDateTimeEdit()
        self.select_date_e.setDisplayFormat("MMM dd yyyy hh:mm AP")

        self.verticalLayout.addWidget(self.select_date_e)
        self.search_date = QPushButton("Go")
        self.verticalLayout.addWidget(self.search_date)

        self.verticalLayout.addItem(spacerItem)
        
    def initId(self, chunks, param):
        cb = QComboBox()
        tmp_list = []
        for chunk in chunks:
            events = chunk.events()
            for event in events:
                tmp_list.append(str(events[event][param]))
        tmp_list = self.unique(tmp_list)
        cb.addItems(tmp_list)
        return cb

    def unique(self, seq, idfun=None): 
        # order preserving
        if idfun is None:
            def idfun(x): return x
        seen = {}
        result = []
        for item in seq:
            marker = idfun(item)
            if marker in seen: continue
            seen[marker] = 1
            if item is not None:
                result.append(item)
        return sorted(result)

class EvtxSelectorMenu(QMenu):
  def __init__(self, parent):
     QMenu.__init__(self, parent)
     action = self.addAction(self.tr("Select"))
     self.connect(action, SIGNAL("triggered()"), parent.select) 
     action = self.addAction(self.tr("Unselect"))
     self.connect(action, SIGNAL("triggered()"), parent.unselect) 
     action = self.addAction(self.tr("Select all"))
     self.connect(action, SIGNAL("triggered()"), parent.selectAll) 
     action = self.addAction(self.tr("Unselect all"))
     self.connect(action, SIGNAL("triggered()"), parent.unselectAll) 


class EventxItem(QTableWidgetItem):
  def __init__(self, parent, event):
     QTableWidgetItem.__init__(self)
     self.__parent = parent
     self.__event = event
     try :
        isChecked = self.__parent.checked[event]
        if isChecked:
           checkState = Qt.Checked
        else:
           checkState = Qt.Unchecked
     except KeyError:
        checkState = Qt.Unchecked
     self.setFlags(Qt.ItemIsSelectable | Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
     self.setCheckState(checkState)

  def setData(self, role, value):
     if role == Qt.CheckStateRole:
       if value == Qt.Checked:
         self.__parent.checked[self.event()] = True
       else:
         self.__parent.checked[self.event()] = False
     QTableWidgetItem.setData(self, role, value)

  def event(self):
     return self.__event

  def offset(self):
     return self.__event.offset()

  def chunk(self):
     return self.__event.event()

  def node(self):
     return self.__event.node()

class EvtxTableView(QTableWidget):
  def __init__(self, splitter, parent):
     QTableWidget.__init__(self, splitter)
     self.menu = EvtxSelectorMenu(self)
     self.parent = parent
     self.setColumnCount(6)
     self.hideColumn(4)
     self.hideColumn(5)
     self.checked = {}   

     self.setHorizontalHeaderLabels(['level','id', 'date', 'source'])
     self.horizontalHeader().setStretchLastSection(True)
     self.verticalHeader().hide()
     self.setSortingEnabled(True)
     self.setSelectionBehavior(QAbstractItemView.SelectRows)
     self.setEditTriggers(QAbstractItemView.NoEditTriggers)

  def addEvents(self, events):
     self.setSortingEnabled(False)
     self.setColumnCount(7)
     for i in range(4, 8):
       self.hideColumn(i)
     for event in events:
        self.addEvent(event)
     self.setSortingEnabled(True)

  def addEvent(self, event):
        chunk = event.event()
        node = event.node()

        rows = self.rowCount()
        self.setRowCount(rows + 1)

        item = EventxItem(self, event)

        try:
            item.setText(self.parent.txt[chunk['level']])
        except IndexError:
            item.setText("Unknown")

        try:
            item.setIcon(QIcon(QPixmap(self.parent.level[chunk['level']])))
        except IndexError:
            item.setIcon(QIcon(QPixmap(":/cancel.png")))
                
        self.setItem(rows, 0, item)
                
        item = QTableWidgetItem(str(chunk['id']))
        self.setItem(rows, 1, item)

        item = QTableWidgetItem(chunk['date'])
        self.setItem(rows, 2, item)
                
        item = QTableWidgetItem(chunk['source'])
        self.setItem(rows, 3, item)

        item = QTableWidgetItem(str(event.offset()))
        self.setItem(rows, 4, item)
                
        item = QTableWidgetItem(str(event.count()))
        self.setItem(rows, 5, item)

        if node:
          item = QTableWidgetItem(str(long(node)))
          self.setItem(rows, 6, item)

  def selectedEvents(self):
     selected = []
     for event in self.checked:
        if self.checked[event]:
          selected.append(event)
     if len(selected):
       return selected
     return None


  def mousePressEvent(self, e):
      index = self.indexAt(e.pos())
      if index.isValid():
        item = self.itemAt(e.pos())
        if e.button() == Qt.RightButton:
	  self.menu.popup(QCursor.pos())
      QTableWidget.mousePressEvent(self, e)

  def select(self):
     for item in self.selectedItems():
        if item.column() == 0:
          item.setCheckState(Qt.Checked)	

  def unselect(self):
     for item in self.selectedItems():
        if item.column() == 0:
  	  item.setCheckState(Qt.Unchecked)

  def selectAll(self):
     for itemId in range(self.rowCount()):
       QCoreApplication.processEvents()
       item = self.item(itemId, 0)
       item.setCheckState(Qt.Checked)

  def unselectAll(self):
     for itemId in range(self.rowCount()):
       QCoreApplication.processEvents()
       item = self.item(itemId, 0)
       item.setCheckState(Qt.Unchecked)


class EventLogViewer(QWidget):
    def __init__(self, node = None, chunks=None, parent = None):
        super(EventLogViewer, self).__init__(parent)

        self.display_mode = 0
        #  self.chunks = chunks
        self.node = node

        self.evtx_parser = EvtxXml(chunks, self.node)

        self.level = [
            ':/audit_success',
            ':/audit_failure',
            ':/error',
            ':/warning',
            ':/info',
            ':/chat.png'
            ]
        
        self.txt = [
            'Audit success',
            'Audit failure',
            'Error',
            'Warning',
            'Information',
            'Comment'
            ]

        self.disp = None
        self.current_row = 0
        self.widget = None

        self.verticalLayout = QVBoxLayout(self)
        self.verticalLayout.setMargin(3)
        self.splitter = QSplitter(self)
        self.splitter.setOrientation(Qt.Horizontal)

        #self.evtx_table_view = QTableWidget(self.splitter)
        self.evtx_table_view = EvtxTableView(self.splitter, self)
        self.admin_pannel = EvtxAdminPannel(self.splitter, chunks or [])

        self.verticalLayout.addWidget(self.splitter)
        self.splitter.setStretchFactor(0, 2)

        if PYQT_VERSION_STR >= "4.5.0":
            self.evtx_table_view.cellDoubleClicked.connect(self.dispEvent)
            self.admin_pannel.admin_events.clicked.connect(self.dispAdminEvents)
            self.admin_pannel.choose_event_type.activated.connect(self.dispEventType)

            self.admin_pannel.cb.activated.connect(self.dispIdL)
            self.admin_pannel.cbs.activated.connect(self.dispSourceL)

            self.admin_pannel.search_id.clicked.connect(self.dispId)
            self.admin_pannel.search_source.clicked.connect(self.dispSource)
            self.admin_pannel.search_date.clicked.connect(self.dispDate)
        else:
            QObject.connect(self.evtx_table_view, SIGNAL("cellDoubleClicked(int, int)"), self.dispEvent)
            QObject.connect(self.admin_pannel.admin_events, SIGNAL("clicked(bool)"), self.dispAdminEvents)
            QObject.connect(self.admin_pannel.search_id, SIGNAL("clicked(bool)"), self.dispId)
            QObject.connect(self.admin_pannel.search_source, SIGNAL("clicked(bool)"), self.dispSource)
            QObject.connect(self.admin_pannel.search_date, SIGNAL("clicked(bool)"), self.dispSource)
            QObject.connect(self.admin_pannel.choose_event_type, SIGNAL("currentIndexChanged(int)"), self.dispEventType)

    def addEvents(self, events):
       self.evtx_table_view.addEvents(events)

    def display(self, chunks, node=None):
        self.evtx_table_view.clearContents()
        self.evtx_table_view.setRowCount(0)
        nb_chunk = 0
        evtxInfos = []
        for chunk in chunks:
            events = chunk.events()
            for event in events:
               QCoreApplication.processEvents()
               if node:
                 nodePtr = node.uid()
               elif self.node:
                 nodePtr =  self.node.uid()
               else:
                 nodePtr = None
               evtxInfo = EvtxInfo(event, events[event], nb_chunk, nodePtr)
               evtxInfos.append(evtxInfo)
            nb_chunk += 1
        self.addEvents(evtxInfos)
    
    def display_chunk(self, events):
        self.evtx_table_view.clearContents()
        self.evtx_table_view.setRowCount(0)
        evtxInfos = []
        for event in events:
            for evtx in event:
              QCoreApplication.processEvents()
              evtxInfo = EvtxInfo(evtx, event[evtx], event[evtx]['chunk_nb'], self.node.uid())
              evtxInfos.append(evtxInfo)

    def dispAdminEvents(self, checked):
        self.evtx_table_view.clearContents()
        if self.display_mode == 0:
            error_list = self.evtx_parser.getEventBylevel(2)
            self.admin_pannel.admin_events.setText("All events")
            tmp_list = self.evtx_parser.getEventBylevel(3)
            error_list.extend(tmp_list)
            self.display_mode = 1
            self.display_chunk(error_list)
        elif self.display_mode == 1:
            self.admin_pannel.admin_events.setText("Admin. events")
            self.display_mode = 0
            processus_manager = ModuleProcessusManager()
            evtx = processus_manager.get('evtx')
            chunks = evtx.data(self.node.uid())
            self.display(chunks, self.node)

    def dispId(self, checked):
        txt = self.admin_pannel.id.text()
        if txt == "":
           return
        try:
            event_list = self.evtx_parser.getEventById(int(txt))
            self.evtx_table_view.clearContents()
            self.evtx_table_view.setRowCount(0)
            self.display_chunk(event_list)
        except ValueError:
            pass

    def dispIdL(self):
        txt = self.admin_pannel.id.text()
        txt = self.admin_pannel.cb.currentText()
        try:
            event_list = self.evtx_parser.getEventById(int(txt))
            self.evtx_table_view.clearContents()
            self.evtx_table_view.setRowCount(0)
            self.display_chunk(event_list)
        except ValueError:
            pass

    def fill_log_viewer(self, item):
        ptr = item.data(QListWidgetItem.UserType)
        node = VFS.Get().getNodeById(ptr.toULongLong()[0])

        processus_manager = ModuleProcessusManager()
        evtx = processus_manager.get('evtx')

        self.node = node
        self.evtx_parser.chunks = evtx.data(ptr.toULongLong()[0])
        self.evtx_parser.node = node

        self.admin_pannel.cb =  self.admin_pannel.initId(evtx.data(ptr.toULongLong()[0]), 'id')
        self.admin_pannel.cbs = self.admin_pannel.initId(evtx.data(ptr.toULongLong()[0]), 'source')

        self.display(evtx.data(ptr.toULongLong()[0]), node)

    def dispDate(self, checked):
        date_begin =  str(self.admin_pannel.select_date_b.dateTime().toString("yyyy-MM-ddThh:mm:ss"))
        date_end =  str(self.admin_pannel.select_date_e.dateTime().toString("yyyy-MM-ddThh:mm:ss"))
        self.evtx_table_view.clearContents()
        self.evtx_table_view.setRowCount(0)
        event_list = self.evtx_parser.getEventsBetween(date_begin, date_end)
        self.display_chunk(event_list)

    def dispSource(self, checked):
        txt = self.admin_pannel.source.text()

        if txt == "":
            return

        self.evtx_table_view.clearContents()
        self.evtx_table_view.setRowCount(0)
        event_list = self.evtx_parser.getEventBySource(txt)
        self.display_chunk(event_list)

    def dispSourceL(self, checked):
        txt = self.admin_pannel.cbs.currentText()

        self.evtx_table_view.clearContents()
        self.evtx_table_view.setRowCount(0)
        event_list = self.evtx_parser.getEventBySource(txt)
        self.display_chunk(event_list)

    def dispEventType(self, index):
        if index == 0:
            processus_manager = ModuleProcessusManager()
            evtx = processus_manager.get('evtx')
            chunks = evtx.data(self.node.uid())
            self.display(chunks, self.node)
        else:
            self.evtx_table_view.clearContents()
            self.evtx_table_view.setRowCount(0)
            event_list = self.evtx_parser.getEventBylevel(index - 1)
            self.display_chunk(event_list)

    def dispEvent(self, row, column):
        item = self.evtx_table_view.item(row, 4)
        offset_str = item.text()
        offset = int(offset_str)

        item = self.evtx_table_view.item(row, 5)
        chunk_str = item.text()
        chunk_nb = int(chunk_str)

        if self.evtx_table_view.columnCount() == 7:
            item = self.evtx_table_view.item(row, 6).data(QTableWidgetItem.Type)
            n = item.toULongLong()[0]
            self.evtx_parser.node = VFS.Get().getNodeById(n)

        xml = self.evtx_parser.getXML(chunk_nb, offset, self.evtx_parser.node)
        xml_str = tostring(xml, "utf-8")

        self.disp = ViewEvtx()
        self.disp.view.setAlternatingRowColors(1)
        self.disp.view.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.disp.view.setSelectionMode(QAbstractItemView.SingleSelection)

        self.current_row = row
        if not row:
            self.disp.prev_evtx.setEnabled(False)

        if row + 1 == self.evtx_table_view.rowCount():
            self.disp.next_evtx.setEnabled(False)

        self.widget = EvtxTree(xml_str, self.disp)

        self.disp.textEdit.setText(self.widget.doc.toString(3))
        self.disp.view.expandAll()
        self.disp.view.resizeColumnToContents(0)
        
        if PYQT_VERSION_STR >= "4.5.0":
            self.disp.next_evtx.clicked.connect(self.nextEvent)
            self.disp.prev_evtx.clicked.connect(self.prevEvent)
    
        self.disp.exec_()
        
        del self.disp
        self.disp = None
    
    def nextEvent(self, checked):
        row = self.current_row + 1

        self.disp.prev_evtx.setEnabled(True)

        while row + 1 != self.evtx_table_view.rowCount() and self.evtx_table_view.isRowHidden(row):
            row += 1

        # row = self.current_row

        item = self.evtx_table_view.item(row, 4)
        offset_str = item.text()
        offset = int(offset_str)

        item = self.evtx_table_view.item(row, 5)
        chunk_str = item.text()
        chunk_nb = int(chunk_str)

        node = None
        if self.evtx_table_view.columnCount() == 7:
            item = self.evtx_table_view.item(row, 6)
            node = VFS.Get().getNodeById(long(item.text()))
        else:
            node = self.node

        self.evtx_table_view.setCurrentCell(row, 0)
        xml = self.evtx_parser.getXML(chunk_nb, offset, node)
        xml_str = tostring(xml, "utf-8")

        self.widget = EvtxTree(xml_str, self.disp)

        self.disp.textEdit.setText(self.widget.doc.toString(3))
        self.disp.view.expandAll()
        self.disp.view.resizeColumnToContents(0)

        self.current_row = row

        while row + 1 != self.evtx_table_view.rowCount():
            row += 1
            if not self.evtx_table_view.isRowHidden(row): return

        self.disp.next_evtx.setEnabled(False)

    def prevEvent(self, checked):
        row = self.current_row - 1

        self.disp.next_evtx.setEnabled(True)

        while row != 0 and self.evtx_table_view.isRowHidden(row):
            row -= 1

        item = self.evtx_table_view.item(row, 4)
        offset_str = item.text()
        offset = int(offset_str)

        item = self.evtx_table_view.item(row, 5)
        chunk_str = item.text()
        chunk_nb = int(chunk_str)

        node = None
        if self.evtx_table_view.columnCount() == 7:
            item = self.evtx_table_view.item(row, 6)
            node = VFS.Get().getNodeById(long(item.text()))
        else:
            node = self.node

        self.current_row = row
        self.evtx_table_view.setCurrentCell(self.current_row, 0)
        
        xml = self.evtx_parser.getXML(chunk_nb, offset, node)
        xml_str = tostring(xml, "utf-8")

        self.widget = EvtxTree(xml_str, self.disp)

        self.disp.textEdit.setText(self.widget.doc.toString(3))
        self.disp.view.expandAll()
        self.disp.view.resizeColumnToContents(0)

        while row != 0:
            row -= 1
            if not self.evtx_table_view.isRowHidden(row): return

        self.disp.prev_evtx.setEnabled(False)
