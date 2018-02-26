# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2011 ArxSys
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
#  Romain Bertholon <rbe@digital-forensic.org>
#  Solal Jacob <sja@digital-forensic.org>

from PyQt4.QtCore import Qt, SIGNAL
from PyQt4.QtGui import QWidget, QTableWidget, QTableWidgetItem, QAbstractItemView, QDialog, QHBoxLayout, QVBoxLayout, QLabel, QTextEdit, QPushButton, QIcon, QSplitter, QListWidget, QListWidgetItem, QComboBox, QLineEdit, QDateTimeEdit, QMessageBox, QPixmap, QSizePolicy, QSpacerItem, QMenu, QCursor, QStackedWidget

from dff.api.vfs.libvfs import VFS 
from dff.api.module.manager import ModuleProcessusHandler, ModuleProcessusManager

#from dff.pro.api.report.document import ReportFramedDocument, ReportDocument, ReportFragmentTable, ReportFragmentHtml, ReportManager XXX REPORT

from dff.modules.evt.evt_header import EVENTLOG_AUDIT_SUCCESS, EVENTLOG_AUDIT_FAILURE, EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE

#class EvtDocument(ReportFramedDocument):
  #def __init__(self, events, name = "Evt", path = "Case"):
     #ReportFramedDocument.__init__(self, name, path)   
     #self.__name = name
     #self.events = events
     #if len(self.events):
       #frame = self.generateFrame()
       #self.addFrames(name, frame)
       #self.generatePageEventsTable(frame)
       #self.generatePagesEvent(frame)
        
  #def generateFrame(self):
     #frame = ReportDocument(self.__name)
     #frame.addHtml('<html><body style="position: absolute;top: 0;bottom: 0;left: 0;right: 0;overflow: hidden;"><iframe src="eventtable.html" name="eventtable" width="100%" style="height: 50%;border: 0px;margin: 0px;padding: 0px;border-bottom:1px solid black"> </iframe> <iframe name="result" src=1.html stlye="border:0" style="border: 0px !important;margin: 0px; width: 100%;height: 50%;margin: 0px;border: 0px;padding: 0px;background: white;"> </iframe></body></html>')
     #return frame

  #def generatePageEventsTable(self, frame):
     #eventsTable = ReportDocument("eventtable", frame.path() + "/" + frame.name())
     #eventsTable.addHtml('<h1>' + 'Event' + '</h1><br>')
     #table = ReportFragmentTable()
     #table.setRowStyle(table.rows(), "background-color:rgb(4,59,76); color:white;")
     #table.insertRowHtml(table.rows(), ('<h2>Date</h2>', '<h2>Id</h2>','<h2>source</h2>', '<h2>level</h2>', ))
     #count = 1 
     #for event in self.events:
	#table.insertRowText(table.rows(), ('<a href=dff-frame-page:' + str(count) + '.html target=result>' + str(event.getTimeGenerated()) + '</a>', str(event.EventID), str(event.sourceName()), str(event.getSingleType()),))
        #count += 1
     #eventsTable.addFragment(table)
     #self.addFrames("eventtable", eventsTable)

  #def generatePagesEvent(self, frame):
     #count = 1
     #for event in self.events:
        #eventDocument = ReportDocument(str(count), frame.path() + "/" + frame.name())
        #table = ReportFragmentTable()
        #message = ""
        #for log in event.getStrings():
          #if log:
            #message += log + '<br>'
        #tableText = (("Event Id", str(event.EventID)),
                     #("Source Name", str(event.sourceName())),
                     #("Level", str(event.getSingleType())),
                     #("Date", str(event.getTimeGenerated())),
                     #("Category", str(event.EventCategory)),
                     #("Computer", str(event.computerName())),
                     #("Message", message),)
        #table.insertTableHtml(tableText)
        #eventDocument.addFragment(table)
        #self.addPages(str(count) + ".html" , eventDocument)
        #count += 1



class EvtControlPannel(QWidget):
    def __init__(self, evt_widget, parent=None):
        QWidget.__init__(self, parent)
        self.evt_widget = evt_widget
        
        self.verticalLayout = QVBoxLayout(self)
        spacerItem = QSpacerItem(20, 259, QSizePolicy.Minimum, QSizePolicy.Expanding)

        tmp_widget = QWidget()
        self.verticalLayout.addWidget(tmp_widget)
        hor_layout = QHBoxLayout(tmp_widget)
        hor_layout.addWidget(QLabel("Display :"))

        self.admin_events = QPushButton(QIcon(":/green_configure.png"), "Admin. events")

        self.choose_event_type = QComboBox()
        self.choose_event_type.addItem(QIcon(":/internet_explorer"), "All", 42)
        self.choose_event_type.addItem(QIcon(":/audit_success"), "Audit success", EVENTLOG_AUDIT_SUCCESS)
        self.choose_event_type.addItem(QIcon(":/audit_failure"), "Audit failure", EVENTLOG_AUDIT_FAILURE)
        self.choose_event_type.addItem(QIcon(":/error"), "Error", EVENTLOG_ERROR_TYPE)
        self.choose_event_type.addItem(QIcon(":/warning"), "Warning", EVENTLOG_WARNING_TYPE)
        self.choose_event_type.addItem(QIcon(":/info"), "Information", EVENTLOG_INFORMATION_TYPE)
        self.choose_event_type.addItem(QIcon(":/chat.png"), "Comment", 5)

        hor_layout.addWidget(self.choose_event_type)

        tmp_widget = QWidget()
        self.verticalLayout.addWidget(tmp_widget)
        hor_layout = QHBoxLayout(tmp_widget)
        self.id = QLineEdit()
        hor_layout.addWidget(QLabel("Id :"))

        self.cb = QComboBox()
        self.cbs = QComboBox()
        self.init()

        hor_layout.addWidget(self.cb)

        tmp_widget = QWidget()
        self.verticalLayout.addWidget(tmp_widget)
        hor_layout = QHBoxLayout(tmp_widget)
        self.source = QLineEdit()
        hor_layout.addWidget(QLabel("Source :"))
        hor_layout.addWidget(self.cbs)

        self.verticalLayout.addWidget(QLabel("Start date :"))
        self.select_date_b = QDateTimeEdit()
        self.select_date_b.setDisplayFormat("MMM dd yyyy hh:mm AP")
        self.verticalLayout.addWidget(self.select_date_b)
        self.verticalLayout.addWidget(QLabel("End date:"))
        self.select_date_e = QDateTimeEdit()
        self.select_date_e.setDisplayFormat("MMM dd yyyy hh:mm AP")
        self.verticalLayout.addWidget(self.select_date_e)
        self.search_date = QPushButton("Go")
        self.verticalLayout.addWidget(self.search_date)
        self.verticalLayout.addItem(spacerItem)

        self.search_date.clicked.connect(self.filterByDate)
        self.cb.activated.connect(self.filterById)
        self.cbs.activated.connect(self.filterBySource)
        self.choose_event_type.activated.connect(self.filterByLvl)

    def filterByDate(self, checked):
        date_begin = self.select_date_b.dateTime()
        date_end = self.select_date_e.dateTime()

        date_begin_str = str(date_begin.toString('yyyy-MM-dd hh:mm:ss'))
        date_end_str = str(date_end.toString('yyyy-MM-dd hh:mm:ss'))

        if date_begin > date_end:
            message = QMessageBox()
            message.setText('Date mismatch.')
            message.exec_()
        else:
            for i in range(self.evt_widget.rowCount()):
                data = self.evt_widget.item(i, 2)
                if data.text() >= date_begin_str and data.text() <= date_end_str:
                    self.evt_widget.showRow(i)
                else:
                    self.evt_widget.hideRow(i)

    def filterById(self, index):
        lvl = self.cb.currentText()
        for i in range(self.evt_widget.rowCount()):
            item = self.evt_widget.item(i, 1)
            data = item.text()
            if data != lvl:
                self.evt_widget.hideRow(i)
            else:
                self.evt_widget.showRow(i)

    def dispAll(self):
        for i in range(self.evt_widget.rowCount()):
            self.evt_widget.showRow(i)

    def filterByLvl(self, index):
        type_e = self.choose_event_type.currentText()
        if type_e == 'All':
            self.dispAll()
        else:
            for i in range(self.evt_widget.rowCount()):
                item = self.evt_widget.item(i, 0)
                data = item.text()
                if data != type_e:
                    self.evt_widget.hideRow(i)
                else:
                    self.evt_widget.showRow(i)

    def reload(self, item):
        self.init()

    def filterBySource(self, index):
        lvl = self.cbs.currentText()        
        for i in range(self.evt_widget.rowCount()):
            item = self.evt_widget.item(i, 3)
            data = item.text()
            if data != lvl:
                self.evt_widget.hideRow(i)
            else:
                self.evt_widget.showRow(i)
    
    def init(self):
        tmp_list = []
        tmp_list2 = []
        self.cb.clear()
        self.cbs.clear()

        for i in range(self.evt_widget.rowCount()):
            item = self.evt_widget.item(i, 1).text()
            tmp_list.append(item)
            item = self.evt_widget.item(i, 3).text()
            tmp_list2.append(item)

        tmp_list = self.unique(tmp_list)
        tmp_list2 = self.unique(tmp_list2)

        self.cb.addItems(tmp_list)
        self.cbs.addItems(tmp_list2)

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

class EvtSelectorMenu(QMenu):
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

class EvtTableWidget(QTableWidget):
    def __init__(self, parent=None):
        QTableWidget.__init__(self,  parent)
        self.setColumnCount(6)

        self.setHorizontalHeaderLabels(['level','id', 'date', 'source'])
        self.horizontalHeader().setStretchLastSection(True)
        self.verticalHeader().hide()
        self.setSortingEnabled(True)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)

        self.setShowGrid(False)
        self.setAlternatingRowColors(True)

        self.hideColumn(4)
        self.hideColumn(5)

        self.cellDoubleClicked.connect(self.dispSingleEvent)
        self.menu = EvtSelectorMenu(self)      

    def selectedEvents(self):
      selected = []
      for itemId in range(self.rowCount()):
	item = self.item(itemId, 0)
        if item.checkState() != Qt.Unchecked:
	  selected.append(self.itemRecord(itemId))

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
	item = self.item(itemId, 0)
        item.setCheckState(Qt.Checked)

    def unselectAll(self):
       for itemId in range(self.rowCount()):
        item = self.item(itemId, 0)
        item.setCheckState(Qt.Unchecked)

    def itemRecord(self, row):
       node_ptr = self.item(row, 4).text()
       index = int(self.item(row, 5).text())
        
       processus_manager = ModuleProcessusManager()
       evt = processus_manager.get('evt')
       record = evt.evts[long(node_ptr)][index]
       return record
 
    def dispSingleEvent(self, row, column):
        box = QDialog()

        main_layout = QHBoxLayout(box)
        main_widget = QWidget()
        main_layout.addWidget(main_widget)

        layout = QVBoxLayout(main_widget)
        node_ptr = self.item(row, 4).text()
        index = int(self.item(row, 5).text())
        
        processus_manager = ModuleProcessusManager()
        evt = processus_manager.get('evt')
        record = evt.evts[long(node_ptr)][index]

        self.label1 = QLabel("Date : " + record.getTimeGenerated())
        self.label2 = QLabel("Source : " + record.sourceName())
        self.label3 = QLabel("Type : " + record.getSingleType())
        self.lab_icon = QLabel()
        self.lab_icon.setPixmap(QPixmap(record.getIcon()).scaled(32, 32, Qt.KeepAspectRatio))

        weed = QWidget()
        l = QHBoxLayout(weed)
        l.addWidget(self.lab_icon)
        l.addWidget(self.label3)

        self.label4 = QLabel("Category : " + str(record.EventCategory))
        self.label5 = QLabel("EventId : " + str(record.EventID))
        self.label6 = QLabel("Computer : " + record.computerName())

        layout.addWidget(self.subWidget(self.label1, self.label2))
        layout.addWidget(self.subWidget(weed, self.label4))
        layout.addWidget(self.subWidget(self.label5, self.label6))

        layout.addWidget(QLabel('Messages :'))

        self.log_strings = QTextEdit('')
        self.log_strings.setReadOnly(True)
        self.log_strings.setLineWrapMode(QTextEdit.WidgetWidth)

        for log in record.getStrings():
            if log is not None:
                self.log_strings.setPlainText(self.log_strings.toPlainText() + log + "\n\n")

        layout.addWidget(self.log_strings)
        button_widget = QWidget()        
        main_layout.addWidget(button_widget)
        
        self.next_evt = QPushButton(QIcon(":/next.png"), "")
        self.next_evt.setToolTip("Next record")
        self.prev_evt = QPushButton(QIcon(":/previous.png"), "")
        self.prev_evt.setToolTip("Previous record")
        self.next_evt.clicked.connect(self.dispNextEvent)
        self.prev_evt.clicked.connect(self.dispPrevEvent)

        if row == 0:
            self.prev_evt.setEnabled(False)
        elif row + 1 == self.rowCount():
            self.next_evt.setEnabled(False)
        else:
            self.hideOrDipsButton()

        button_layout = QVBoxLayout(button_widget)
        button_layout.addWidget(self.prev_evt)
        button_layout.addWidget(self.next_evt)

        spacerItem = QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding)
        button_layout.addItem(spacerItem)

        close_button = QPushButton("Close")
        close_button.clicked.connect(box.done)
        button_layout.addWidget(close_button)
        
        box.exec_()

    def subWidget(self, label1, label2):
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.addWidget(label1)
        layout.addWidget(label2)
        return widget

    def dispNextEvent(self, checked):
        row = self.currentRow() + 1
        while row + 1 != self.rowCount() and self.isRowHidden(row):
            row += 1
        self.display(row)

        # is there a next record ?
        while row + 1 != self.rowCount():
            row += 1
            if not self.isRowHidden(row) : return
        self.next_evt.setEnabled(False)
    
    def dispPrevEvent(self, checked):
        row = self.currentRow() - 1
        while row != 0 and self.isRowHidden(row):
            row -= 1
        self.display(row)
        
        # is there a previous record ?
        while row != 0:
            row -= 1
            if not self.isRowHidden(row): return

        self.prev_evt.setEnabled(False)

    def display(self, row):

        self.setCurrentCell(row, 0)
        
        node_ptr = self.item(row, 4).text()
        index = int(self.item(row, 5).text())
        
        processus_manager = ModuleProcessusManager()
        evt = processus_manager.get('evt')
        record = evt.evts[long(node_ptr)][index]

        self.label1.setText("Date : " + record.getTimeGenerated())
        self.label2.setText("Source : " + record.sourceName())
        self.lab_icon.setPixmap(QPixmap(record.getIcon()).scaled(32, 32, Qt.KeepAspectRatio))
        self.label3.setText("Type : " + record.getSingleType())
        self.label4.setText("Category : " + str(record.EventCategory))
        self.label5.setText("EventId : " + str(record.EventID))
        self.label6.setText("Computer : " + record.computerName())

        self.log_strings.setPlainText('')
        for log in record.getStrings():
           if log is not None:
             self.log_strings.setPlainText(self.log_strings.toPlainText() + log + "\n")
        self.hideOrDipsButton()

    def hideOrDipsButton(self):
        row = self.currentRow()
        if row == 0:
            self.prev_evt.setEnabled(False)
        else:
            self.prev_evt.setEnabled(True)

        if row + 1 == self.rowCount():
            self.next_evt.setEnabled(False)
        else:
            self.next_evt.setEnabled(True)

        # is there a next record ?
        row = self.currentRow()
        next_e = False
        while row + 1 != self.rowCount():
            row += 1
            if not self.isRowHidden(row) :
                next_e = True
                break
        if next_e == False:
            self.next_evt.setEnabled(False)

        row = self.currentRow()
        # is there a previous record ?
        prev_e = False
        while row != 0:
            row -= 1
            if not self.isRowHidden(row): 
                prev_e = True
                break
        if prev_e == False:
            self.prev_evt.setEnabled(False)

    def setItemFlags(self, item):
       item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
       item.setCheckState(Qt.Checked)


    def addItemToTable(self, record, widget, rows, node_ptr, count):
        if count == -1:
            count = rows
           
        item = QTableWidgetItem(QIcon(record.getIcon()), str(record.getSingleType()))
        self.setItemFlags(item)
        widget.setItem(rows, 0, item)
                
        item = QTableWidgetItem(str(record.EventID))
        widget.setItem(rows, 1, item)

        item = QTableWidgetItem(str(record.getTimeGenerated()))
        widget.setItem(rows, 2, item)
                
        item = QTableWidgetItem(str(record.sourceName()))
        widget.setItem(rows, 3, item)

        item = QTableWidgetItem(str(long(node_ptr)))
        widget.setItem(rows, 4, item)
                
        item = QTableWidgetItem(str(count))
        widget.setItem(rows, 5, item)

class EvtFilteredWidget(QSplitter):
  def __init__(self, parent, name, value):
    QSplitter.__init__(self, Qt.Horizontal)
    self.__name = name
    self.__parent = parent 
    self.reportBase = "Analyse/"
    self.table = EvtTableWidget()
    self.fillTable(value)

    self.addWidget(self.table)
    self.addWidget(EvtControlPannel(self.table))
    self.setStretchFactor(0, 2)

  def parentName(self):
     return self.__parent.name

  def fillTable(self, value):
    self.table.setRowCount(len(value))
    self.table.setSortingEnabled(False)
    count = 0 
    for record in value:
      self.table.addItemToTable(record.record(), self.table, count, long(record.node()), record.count())
      count += 1
    self.table.setSortingEnabled(True)

  def report(self):	
     reportManager = ReportManager()
     events = self.table.selectedEvents()
     if events and len(events):
       doc = EvtDocument(events, str(self.__name), str(self.reportBase + self.parentName()))
       reportManager.addReportDocument(doc)


class EvtWidget(EvtFilteredWidget):
  def __init__(self, parent, name, events, node):
     self.node = node 
     EvtFilteredWidget.__init__(self, None, name, events)
     self.reportBase = "Case/"

  def parentName(self):
     return "Events/"

  def fillTable(self, value):
    self.table.setRowCount(len(value))
    self.table.setSortingEnabled(False)
    count = 0 
    for record in value:
      self.table.addItemToTable(record, self.table, count, self.node, count)
      count += 1
    self.table.setSortingEnabled(True)

class EvtPreviewWidget(EvtTableWidget):
  def __init__(self, events, node):
     EvtTableWidget.__init__(self)
     self.setRowCount(len(events))
     self.setSortingEnabled(False)
     count = 0
     for record in events:
        self.addItemToTable(record, self, count, node, count) 
        count += 1
     self.setSortingEnabled(True)

  def setItemFlags(self, item):
     pass

  def mousePressEvent(self, e):
     QTableWidget.mousePressEvent(self, e)

class FileItem(QListWidgetItem):
  def __init__(self, icon, name, node):
     QListWidgetItem.__init__(self, icon, name)
     self.__node = node
     self.__table = None

  def table(self, table = None):
     if table == None:
        return self.__table
     self.__table = table

  def node(self):
     return self.__node

class EvtsFilesWidget(QSplitter):
  def __init__(self, manager, root="/"):
     """
     \returns a QSplitter() containing a QLIstWidget() listing all evt files,
     an EVtTableWIdget() and an EvtControlPannel
     """
     QSplitter.__init__(self, Qt.Horizontal)
     self.manager = manager
        
     self.evtFileListWidget = QListWidget()
     self.evtFileListWidget.itemClicked.connect(self.switchEventTable)
     fileLabel = QLabel('Windows events')

     w = QWidget()
     self.stackedWidget = QStackedWidget()
     vboxLayout = QVBoxLayout(w)
     vboxLayout.addWidget(fileLabel)
     vboxLayout.addWidget(self.evtFileListWidget)
     vboxLayout.setSpacing(2)
     vboxLayout.setContentsMargins(2, 2, 2, 2)

     for evt in self.manager.evts:
      try:
        events = self.manager.evts[evt]
        if events and len(events):
          fileItem = self.getFileItems(evt, root)
          if fileItem:
            self.evtFileListWidget.addItem(fileItem)
            currentTable = EvtWidget(None, fileItem.text(), events, evt)
            self.stackedWidget.addWidget(currentTable)
            fileItem.table(currentTable)
      except Exception as e:
        pass

     self.addWidget(w)
     self.addWidget(self.stackedWidget)
     self.currentItem = self.evtFileListWidget.item(0)
     if self.currentItem:
       self.switchEventTable(self.currentItem)
     self.setStretchFactor(1, 2)

  def switchEventTable(self, fileItem):
     table = fileItem.table()
     self.currentItem = fileItem
     if table:
       self.stackedWidget.setCurrentWidget(table)   

  def getFileItems(self, evt, root):
        node = VFS.Get().getNodeById(evt)
        if node is None:
            return None
        if node.absolute()[:len(root)] != root:
            return None
        fileItem = FileItem(QIcon(':/toggle_log'), node.name(), node) 
        return fileItem   
 
  def report(self):
     reportManager = ReportManager()
     for itemID in range(self.evtFileListWidget.count()):
       fileItem = self.evtFileListWidget.item(itemID)
       fileItem.table().report() 

class EvtManager(ModuleProcessusHandler):
    def __init__(self, name):
        ModuleProcessusHandler.__init__(self, name)
        self.evts = {}
        
    def update(self, processus):
        self.evts[processus.node.uid()] = processus.record_list

    def getAllEvtFiles(self, root = '/'):
       return EvtsFilesWidget(self, root)

    def previewWidget(self, evt, root = '/'):
       try :
         events = self.evts[evt]
         return EvtPreviewWidget(events, evt) 
       except Exception as e:
         print e
         return None
       
