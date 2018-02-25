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
#  Frederic Baguelin <fba@arxsys.fr>

import time, types
import datetime
import apsw
from PyQt4 import QtCore, QtGui
from dff.api.module.manager import ModuleProcessusManager
from dff.api.datatype.magichandler import magicHandler


class SqliteTablesCountItem(QtGui.QTableWidgetItem):
    def __init__(self, count):
        super(SqliteTablesCountItem, self).__init__()
        self.__count = count
        self.setText(QtCore.QString.number(count))


    def countData(self):
        return self.__count

    
    def __lt__(self, other):
        return self.__count < other.countData()


class BlobDialog(QtGui.QDialog):
    def __init__(self, data, parent=None):
        super(BlobDialog, self).__init__(parent)
        self.setLayout(QtGui.QHBoxLayout())
        self.__data = data
        if type(self.__data) == types.BufferType:
            mime = magicHandler.typeFromBuffer(str(self.__data))
            if mime.find("image") != -1:
                pixmap = QtGui.QPixmap()
                pixmap.loadFromData(self.__data)
                label = QtGui.QLabel()
                label.setPixmap(pixmap)
                self.layout().addWidget(label)
            if mime.find("text") != -1:
                lineEdit = QTextEdit()
                lineEdit.setPlainText(str(self.__data))
                self.layout().addWidget(lineEdit)
            else:
                pass

        
class SqliteTablesWidget(QtGui.QTableWidget):
    def __init__(self, database, parent=None):
        super(SqliteTablesWidget, self).__init__(parent)
        self.setColumnCount(2)
        self.setHorizontalHeaderLabels(["Table", "Number of rows"])
        self.verticalHeader().setVisible(False)
        self.setSelectionBehavior(QtGui.QAbstractItemView.SelectRows)
        self.setShowGrid(False)
        self.setSortingEnabled(True)
        sqlitedriver = ModuleProcessusManager().get('SqliteDB')
        query = 'SELECT tbl_name FROM sqlite_master where type="table";'
        tables = sqlitedriver.executeFrom(database, query)
        if tables is not None:
            idx = self.rowCount()
            for table in tables:
                self.setRowCount(idx+1)
                query = "select count(*) from {}".format(table[0])
                counter = sqlitedriver.executeFrom(database, query)
                count = 0
                if counter:
                    data = counter.fetchone()
                    if data is not None and len(data) > 0:
                        count = data[0]
                nameItem = QtGui.QTableWidgetItem()
                nameItem.setText(QtCore.QString.fromUtf8(table[0]))
                countItem = SqliteTablesCountItem(count)
                self.setItem(idx, 0, nameItem)
                self.setItem(idx, 1, countItem)
                idx += 1
        self.resizeColumnsToContents()


class SqliteRowsWidget(QtGui.QTableWidget):    
    def __init__(self, parent=None):
        super(SqliteRowsWidget, self).__init__(parent)
        self.setSortingEnabled(True)
        self.verticalHeader().setVisible(False)
        self.setHorizontalScrollMode(QtGui.QAbstractItemView.ScrollPerPixel)
        self.setSelectionMode(QtGui.QAbstractItemView.ExtendedSelection)
        self.setTextElideMode(QtCore.Qt.ElideRight)
        self.setSelectionBehavior(QtGui.QAbstractItemView.SelectRows)
        self.setContextMenuPolicy(QtCore.Qt.ActionsContextMenu)
        self.itemDoubleClicked.connect(self.__itemDoubleClicked)
        copyAction = QtGui.QAction(self.tr("Copy"), self)
        copyAction.setShortcuts(QtGui.QKeySequence(QtCore.Qt.CTRL + QtCore.Qt.Key_C))
        copyAction.setShortcutContext(QtCore.Qt.WidgetWithChildrenShortcut)
        copyAction.triggered.connect(self.__copy)
        decodeAction = QtGui.QAction(self.tr("Decode column as"), self)
        decoderMenu = QtGui.QMenu(self)
        for decoderName, decoderType in SqliteRowItemWidget.Decoders.iteritems():
            decoderAction = QtGui.QAction(decoderName, self)
            decoderAction.setData(QtCore.QVariant(decoderType))
            decoderAction.triggered.connect(self.__decodeColumn)
            decoderMenu.addAction(decoderAction)
        decodeAction.setMenu(decoderMenu)
        resetColumnDataAction = QtGui.QAction(self.tr("Reset column's data"), self)
        resetColumnDataAction.setData(QtCore.QVariant(SqliteRowItemWidget.DefaultDecoder))
        resetColumnDataAction.triggered.connect(self.__decodeColumn)
        self.addAction(copyAction)
        self.addAction(decodeAction)
        self.addAction(resetColumnDataAction)



    def __itemDoubleClicked(self, item):
        if item is None:
            return
        if not item.isBlob():
            return
        blobDialog = BlobDialog(item.rawData())
        blobDialog.move(QtGui.QCursor.pos())
        blobDialog.exec_()


    def __decodeColumn(self):
        action = self.sender()
        data = action.data()
        if not data.isValid():
            return
        decoder, success = data.toInt()
        if not success:
            return
        item = self.currentItem()
        if item is None:
            return
        column = item.column()
        mismatch = False
        for row in xrange(0, self.rowCount()):
            item = self.item(row, column)
            if item is not None:
                if not item.decode(decoder):
                    mismatch = True
        if mismatch:
            decoderName = action.text()
            warning = action.text() + self.tr(" decoder cannot be applied")
            QtGui.QMessageBox.warning(self, self.tr("Sqlite viewer"),
                                      warning)

                
    def __resetColumnData(self):
        item = self.currentItem()
        if item is None:
            return
        column = item.column()
        for row in xrange(0, self.rowCount()):
            item = self.item(row, column)
            if item is not None:
                item.reset()
        

    def __copy(self):
        items = self.selectedItems()
        if not len(items):
            return
        seen = set()
        html = """<style type="text/css"
        tr:nth-child(even) {background: #CCC}
        tr:nth-child(odd) {background: #FFF}
        </style>"""
        html = """<table style="width:100%", cellpadding="10">\n<tr>\n"""
        text = ""
        for column in xrange(0, self.columnCount()):
            columnText = self.horizontalHeaderItem(column).text().toUtf8()
            html += "\t<th>{}</th>\n".format(columnText)
            if len(text):
                text += "\t"
            text += columnText
        html += "</tr>\n"
        text += "\n"
        count = 0
        for item in items:
            row = item.row()
            if row not in seen:
                rowHtml, rowText = self.__rowToText(row)
                if count % 2 == 0:
                    html += '<tr bgcolor="#f1f1f1">\n{}</tr>\n'.format(rowHtml)
                else:
                    html += '<tr>\n{}</tr>\n'.format(rowHtml)
                count += 1
                text += rowText + "\n"
                seen.add(row)
        html += "</table>"
        mimeData = QtCore.QMimeData()
        mimeData.setHtml(html)
        mimeData.setText(QtCore.QString.fromUtf8(text))
        QtGui.QApplication.clipboard().clear()
        QtGui.QApplication.clipboard().setMimeData(mimeData)


    def __rowToText(self, row):
        html = ""
        text = ""
        for column in xrange(0, self.columnCount()):
            item = self.item(row, column)
            html += "\t<td>{}</td>\n".format(str(item.text().toUtf8()))
            if len(text):
                text += "\t"
            text += item.text().toUtf8()
        return (html, text)
        

    def populate(self, database, query):
        self.clear()
        self.setColumnCount(0)
        self.setRowCount(0)
        sqlitedriver = ModuleProcessusManager().get('SqliteDB')
        try:
            rows = sqlitedriver.executeFrom(database, query)
        except apsw.Error:
            return
        try:
            descriptions = rows.getdescription()
        # if there's no row, this exception is thrown
        except apsw.ExecutionCompleteError:
            return
        header = []
        for description in descriptions:
            header.append(description[0])
        self.setColumnCount(len(header))
        self.setHorizontalHeaderLabels(header)
        for idx in xrange(0, len(header)):
            self.horizontalHeaderItem(idx).setTextAlignment(QtCore.Qt.AlignLeft)
        finished = False
        idx = 0
        # we use next to be able to continue if there's an error while getting
        # one row.
        while not finished:
            try:
                row = rows.next()
                self.setRowCount(idx+1)
                for column, data in enumerate(row):
                    if self.__isDate(descriptions[column][0]):
                        item = SqliteRowItemWidget(data, descriptions[column][1], True)
                    else:
                        item = SqliteRowItemWidget(data, descriptions[column][1])
                    self.setItem(idx, column, item)
                idx += 1
            except StopIteration:
                finished = True
            except apsw.Error:
                continue
        self.resizeColumnsToContents()


    def __isDate(self, name):
        if name.lower().find("date") != -1:
            return True
        if name.lower().find("modif") != -1:
            return True
        return False


class SqliteRowItemWidget(QtGui.QTableWidgetItem):

    DefaultDecoder = 0
    DefaultDateDecoder = DefaultDecoder + 1
    MicrosecondsSinceEpoch = DefaultDecoder + 2
    MicrosecondsSinceGregorian = DefaultDecoder + 3
    MillisecondsSinceEpoch = DefaultDecoder + 4

    Decoders = {"Microseconds since 01/01/1970": MicrosecondsSinceEpoch,
                "Microseconds since 01/01/1601": MicrosecondsSinceGregorian,
                "Milliseconds since 01/01/1970": MillisecondsSinceEpoch,
                "Seconds since 01/01/1970": DefaultDateDecoder}
    
    def __init__(self, data, datatype, datetype=False):
        super(SqliteRowItemWidget, self).__init__()
        self.__data = data
        self.__datatype = datatype
        self.__datetype = datetype
        self.setFlags(QtCore.Qt.ItemIsSelectable|QtCore.Qt.ItemIsEnabled)
        self.decodeDefault()


    def decode(self, decoder=0):
        if decoder == SqliteRowItemWidget.DefaultDateDecoder:
            return self.decodeDefaultDate()
        if decoder == SqliteRowItemWidget.MicrosecondsSinceEpoch:
            return self.decodeMicrosecondsSinceEpoch()
        if decoder == SqliteRowItemWidget.MicrosecondsSinceGregorian:
            return self.decodeMicrosecondsSinceGregorian()
        if decoder == SqliteRowItemWidget.MillisecondsSinceEpoch:
            return self.decodeMillisecondsSinceEpoch()
        return self.decodeDefault()

        
    def decodeDefaultDate(self):
        self.setBackgroundColor(QtGui.QColor(204, 255, 204))
        if type(self.__data) in [types.IntType, types.LongType]:
            try:
                timestamp = datetime.datetime.fromtimestamp(self.__data)
                self.setText(str(timestamp))
                return True
            except:
                self.setText(QtCore.QString.number(long(self.__data)))
                return False
        elif type(self.__data) == types.FloatType:
            self.setText(QtCore.QString.number(float(self.__data)))
            return True
        self.decodeDefault()
        return False


    # Firefox
    def decodeMicrosecondsSinceEpoch(self):
        self.setBackgroundColor(QtGui.QColor(204, 255, 204))
        if type(self.__data) in [types.IntType, types.LongType]:
            epoch = datetime.datetime(1970, 1, 1)
            try:
                delta = datetime.timedelta(microseconds=self.__data)
                timestamp = epoch + delta
                self.setText(str(timestamp))
                return True
            except Exception as e:
                self.setText(QtCore.QString.number(long(self.__data)))
                return False
        self.decodeDefault()
        return False


    # Solmail
    def decodeMillisecondsSinceEpoch(self):
        self.setBackgroundColor(QtGui.QColor(204, 255, 204))
        if type(self.__data) in [types.IntType, types.LongType]:
            epoch = datetime.datetime(1970, 1, 1)
            try:
                delta = datetime.timedelta(milliseconds=self.__data)
                timestamp = epoch + delta
                self.setText(str(timestamp))
                return True
            except:
                self.setText(QtCore.QString.number(long(self.__data)))
                return False
        self.decodeDefault()
        return False
        

    # Chrome
    def decodeMicrosecondsSinceGregorian(self):
        self.setBackgroundColor(QtGui.QColor(204, 255, 204))
        if type(self.__data) in [types.IntType, types.LongType]:
            epoch = datetime.datetime(1601, 1, 1)
            try:
                delta = datetime.timedelta(microseconds=self.__data)
                timestamp = epoch + delta
                self.setText(str(timestamp))
                return True
            except:
                self.setText(QtCore.QString.number(long(self.__data)))
                return False
        self.decodeDefault()
        return False

    
    def decodeDefault(self):
        if self.__data is None:
            self.setText(QtCore.QString(""))
            self.setBackgroundColor(QtGui.QColor(255, 204, 204))
            return True
        if type(self.__data) in [types.IntType, types.LongType]:
            self.setBackgroundColor(QtGui.QColor(204, 255, 204))
            self.setText(QtCore.QString.number(long(self.__data)))
            return True
        if type(self.__data) == types.FloatType:
            self.setBackgroundColor(QtGui.QColor(204, 255, 204))
            self.setText(QtCore.QString.number(float(self.__data)))
            return True
        if type(self.__data) in [types.StringType, types.UnicodeType]:
            self.setText(QtCore.QString.fromUtf8(self.__data))
            self.setBackgroundColor(QtGui.QColor(204, 255, 255))
            return True
        if type(self.__data) == types.BufferType:
            self.setBackgroundColor(QtGui.QColor(204, 204, 255))
            mime = magicHandler.typeFromBuffer(str(self.__data))
            if mime.find("image") != -1:
                pixmap = QtGui.QPixmap()
                pixmap.loadFromData(self.__data)
                icon = QtGui.QIcon(pixmap)
                self.setIcon(icon)
            if mime.find("text") != -1:
                self.setText(QtCore.QString.fromUtf8(str(self.__data)))
            else:
                cellContent = "Blob of type {} ({:d} bytes)".format(mime, len(self.__data))
                self.setText(cellContent)
            return True
        self.setText(QtCore.QString(self.tr("Unsupported data type")))
        self.setBackgroundColor(QtGui.QColor(255, 204, 204))
        return True


    def rawData(self):
        return self.__data


    def isBlob(self):
        return type(self.__data) == types.BufferType
        
        
    def __lt__(self, other):
        if other.rawData() is None:
            return True
        if type(self.__data) in [types.IntType, types.LongType, types.FloatType,
                                 types.StringType, types.UnicodeType]:
            return self.__data < other.rawData()
        return False


class SqliteCustomQuery(QtGui.QTextEdit):
    def __init__(self, parent=None):
        super(SqliteCustomQuery, self).__init__(parent)
        self.__history = []
        self.__historyIndex = 0
        self.__currentEdtion = ""
        self.__saveEdition = False
        self.setText("query> ")


    def sizeHint(self):
        return QtCore.QSize(30, 30)
        
        
    def keyPressEvent(self, event):
        key = event.key()
        if key == QtCore.Qt.Key_Backspace and \
           self.textCursor().position() == self.queryStartPosition():
            return
        if key == QtCore.Qt.Key_Return or key == QtCore.Qt.Key_Enter:
            return self.__executeQuery()
        if key == QtCore.Qt.Key_Up:
            return self.__previousHistory()
        if key == QtCore.Qt.Key_Down:
            return self.__nextHistory()
        super(SqliteCustomQuery, self).keyPressEvent(event)
        if self.__saveEdition:
            self.__currentEdition = self.currentQuery()


    def __executeQuery(self):
        query = self.currentQuery()
        if query.length() > 0:
            self.emit(QtCore.SIGNAL("executeQuery(QString)"), query)
            self.__history.append(query)
            self.__historyIndex = len(self.__history)
            self.__currentEdition = ""
            self.__saveEdition = True
        self.append("query> ")
        return


    def __nextHistory(self):
        if len(self.__history) == 0:
            return
        if self.__historyIndex < len(self.__history) - 1:
            self.__historyIndex += 1
            self.__insertHistory(self.__history[self.__historyIndex])
            return
        else:
            self.__insertHistory(self.__currentEdition)
            self.__historyIndex = len(self.__history)
            self.__saveEdition = True
        return
        
        
    def __previousHistory(self):
        if len(self.__history) == 0:
            return
        self.__saveEdition = False
        if self.__historyIndex - 1 >= 0:
            self.__historyIndex -= 1
            self.__insertHistory(self.__history[self.__historyIndex])
            return
        return


    def currentQuery(self):
        text = self.toPlainText()
        idx = text.lastIndexOf("\n")
        if idx == -1:
            idx = 7
        else:
            idx += 8
        return text.mid(idx)


    def queryStartPosition(self):
        text = self.toPlainText()
        idx = text.lastIndexOf("\n")
        if idx == -1:
            idx = 7
        else:
            idx += 8
        return idx


    def queryEndPosition(self):
        return self.toPlainText().length()

    
    def __insertHistory(self, query):
        text = self.toPlainText()
        startIdx = text.lastIndexOf("\n")
        if startIdx == -1:
            startIdx = 7
        else:
            startIdx += 8
        endIdx = text.length()
        if startIdx != endIdx:
            cursor = self.textCursor()
            cursor.setPosition(endIdx,  QtGui.QTextCursor.MoveAnchor)
            cursor.setPosition(startIdx, QtGui.QTextCursor.KeepAnchor)
            cursor.removeSelectedText()
        self.insertPlainText(query)

import traceback

class SqliteDatabaseWidget(QtGui.QSplitter):
    def __init__(self, database, parent=None):
        super(SqliteDatabaseWidget, self).__init__(parent)
        self.__database = database
        try:
            self.__tables = SqliteTablesWidget(database)
        except:
            traceback.print_exc()
        self.__rows = SqliteRowsWidget()
        self.__tables.itemClicked.connect(self.__displayTable)
        self.__customQuery = SqliteCustomQuery()
        self.connect(self.__customQuery, QtCore.SIGNAL("executeQuery(QString)"),
                     self.__executeQuery)
        rightSide = QtGui.QSplitter(self)
        rightSide.setOrientation(QtCore.Qt.Vertical)
        rightSide.addWidget(self.__customQuery)
        rightSide.addWidget(self.__rows)
        self.addWidget(self.__tables)
        self.addWidget(rightSide)
        self.setStretchFactor(1, 1)


    def __executeQuery(self, query):
        self.__rows.populate(self.__database, query.toUtf8())


    def __displayTable(self, item):
        table = self.__tables.item(item.row(), 0).text()
        query = "select * from {}".format(table)
        self.__rows.populate(self.__database, query)
        

# class Manager2(Ui_SQLiteManager, QWidget):
#     def __init__(self):
#         QWidget.__init__(self)
#         self.setupUi(self)
#         self.databases = []
#         self.proc = ModuleProcessusManager().get('SqliteDB')
#         self.createTables()

#         self.connect(self.databaseTree, SIGNAL("itemClicked(QTreeWidgetItem*,int)"), self.selectTable)
#         self.connect(self.queryRun, SIGNAL("clicked()"), self.runQuery)
#         self.connect(self.selectDatabase, SIGNAL("currentIndexChanged(int )"), self.customDatabaseChanged)
#         self.connect(self.tableResult, SIGNAL("itemClicked(QTableWidgetItem*)"), self.tableClicked)
#         self.connect(self.queryResult, SIGNAL("itemClicked(QTableWidgetItem*)"), self.tableClicked)
#         self.connect(self.refreshButton, SIGNAL("clicked()"), self.refreshDatabases)
#         # Actions
#         self.connect(self.actionExport_selection_CSV, SIGNAL("triggered(bool)"), self.exportCSV)
#         self.connect(self.actionExtract_Binary_BLOB, SIGNAL("triggered(bool)"), self.exportBLOB)
#         self.connect(self.actionDecode_date_column, SIGNAL("triggered(bool)"), self.decodeDate)
#         self.connect(self.actionReset_column, SIGNAL("triggered(bool)"), self.resetColumn)

#         self.searchForDatabases()
#         self.currentDB = None
#         self.queryMessage.setTextColor(Qt.red)

#     def resetColumn(self):
#         table = self.currentTable()
#         item = table.currentItem()
#         if item:
#             column = item.column()
#             for row in xrange(0, table.rowCount()):
#                 table.item(row, column).format()

#     def decodeDate(self):
#         table = self.currentTable()
#         item = table.currentItem()
#         if item:
#             column = item.column()
#             for row in xrange(0, table.rowCount()):
#                 i = table.item(row, column)
#                 ts = i.getData()
#                 if ts:
#                     dt = datetime.fromtimestamp(ts/1000000)
#                     i.setText(QString(dt.isoformat()))

#     def exportCSV(self, state):
#         # Get current table
#         table = self.currentTable()
#         columns = table.columnCount()
#         csv = QString("")
#         header = table.horizontalHeader()
#         # Build CSV header
#         for colid in xrange(0, columns):
#             csv.append(table.horizontalHeaderItem(colid).text())
#             csv.append(",")
#         csv.append("\n")
#         # Get selected Rows (id)
#         selectedRows = self.selectedRows(table)
#         # Build csv
#         for row in selectedRows:
#             for col in xrange(0, table.columnCount()):
#                 item = table.item(row, col)
#                 csv.append(item.text())
#                 csv.append(",")
#             csv.append("\n")
#         # Write to file
#         sFileName = QFileDialog.getSaveFileName(self, "Export CSV", "sqlite.csv")
#         if sFileName:
#             with open(sFileName, "w") as f:
#                 f.write(csv)        

#     def selectedRows(self, table):
#         selectedRows = []
#         for row in xrange(0, table.rowCount()):
#             if table.item(row, 0).isSelected():
#                 selectedRows.append(row)
#         return selectedRows

#     def currentTable(self):
#         if TABINDEX[self.tabWidget.currentIndex()] is "CUSTOM":
#             return self.queryResult
#         else:
#             return self.tableResult

#     def exportBLOB(self, state):
#         table = self.currentTable()
#         data = table.currentItem().getData()
#         sFileName = QFileDialog.getSaveFileName(self, "Export Binary content", "Specify")
#         if sFileName:
#             with open(sFileName, "w") as f:
#                 f.write(data)

#     def createTables(self):
#         self.queryResult = TableResult(self, custom=True)
#         self.tableResult = TableResult(self)

#         self.customResultLayout.addWidget(self.queryResult)
#         self.tableResultLayout.addWidget(self.tableResult)

#     def tableClicked(self, item):
#         table = item.tableWidget()

#     def customDatabaseChanged(self, index):
#         self.setCurrentDatabase(self.databases[index])

#     def runQuery(self):
#         self.customStack.setCurrentIndex(0)
#         query = self.queryEdit.toPlainText()
#         if self.currentDB:
#             self.buildDatabaseTable(self.queryResult, query, self.currentDB)

#     def headerList(self, cursor):
#         heads = []
#         if cursor:
#             try:
#                 description = cursor.getdescription()
#             except:
#                 return heads
#             for head in description:
#                 heads.append(head[0])
#         return heads

#     def currentDatabase(self):
#         item = self.databaseTree.currentItem()

#     def buildDatabaseTable(self, table, query, database):
#         table.setRowCount(0)
#         try:
#             cursor = self.proc.executeFrom(database, query)
#         except apsw.SQLError, e:
#             if TABINDEX[self.tabWidget.currentIndex()] is "CUSTOM":
#                 self.queryMessage.clear()
#                 self.queryMessage.insertPlainText(QString(str(unicode(e).encode('utf-8'))))
#                 self.customStack.setCurrentIndex(1)
#             return
#         heads = self.headerList(cursor)
#         table.setColumnCount(len(heads))
#         table.setHorizontalHeaderLabels(heads)
#         # Align header title
#         for count, head in enumerate(heads):
#             table.horizontalHeaderItem(count).setTextAlignment(Qt.AlignLeft)
#         for row, c in enumerate(cursor):
#             for count, data in enumerate(c):
#                 table.setRowCount(row + 1)
#                 table.setItem(row, count, DatabaseTableItem(data))

#     def setCurrentDatabase(self, db):
#         self.currentDB = db
#         self.selectDatabase.setCurrentIndex(self.databases.index(db))

#     def selectTable(self, item, col):
#         if item.isTable():
#             self.setCurrentDatabase(item.nodeDB())
#             query = "SELECT * FROM " + item.text(0)
#             self.buildDatabaseTable(self.tableResult, query, item.nodeDB())
#             qschema = "pragma table_info('" + item.text(0) + "')"
#             self.populateSchema(item.nodeDB(), qschema)

#     def populateSchema(self, db, query):
#         self.schemaTable.setRowCount(0)
#         try:
#             rows = self.proc.executeFrom(db, query).fetchall()
#         except apsw.SQLError, e:
#             return
#         for rcount, row in enumerate(rows):
#             for ccount, col in enumerate(row):
#                 self.schemaTable.setRowCount(rcount + 1)
#                 self.schemaTable.setItem(rcount, ccount, DatabaseTableItem(col))

#     def populateTree(self):
#         for db in self.databases:
#             item = DatabaseTreeItem(self.databaseTree, db)
#             item.setText(0, QString.fromUtf8(db.name() + " (" + db.path() + ")"))
#             item.setIcon(0, QIcon(":database"))
#             cursor = self.proc.executeFrom(db, 'SELECT tbl_name FROM sqlite_master where type="table";')
#             for c in cursor:
#                 tableitem = DatabaseTreeItem(item, db, isTable=True)
#                 tableitem.setText(0, QString.fromUtf8(c[0]))


#     def refreshDatabases(self):
#         self.databaseTree.clear()
#         self.searchForDatabases()

#     def searchForDatabases(self):
#         if len(self.proc.databases):
#           self.databases = []
#           for base, node in self.proc.databases.iteritems():
#             already = 0
#             for n in self.databases:
#               if node.absolute() == n.absolute():
#                 already = 1       
#             if not already:
#               self.databases.append(node)
#               self.selectDatabase.addItem(QString.fromUtf8(node.name()))
#           self.populateTree()

# class DatabaseTableItem(QTableWidgetItem):
#     def __init__(self, data):
#         QTableWidgetItem.__init__(self)
#         self.__data = data
#         self.setFlags(Qt.ItemIsSelectable|Qt.ItemIsEnabled)
#         self.__type = None
#         self.format()

#     def getType(self):
#         return self.__type

#     def format(self):
#         self.__type = t = type(self.__data).__name__
#         if t == "int":
#             self.setText(QString(str(self.__data)))
#             self.setBackgroundColor(QColor(204, 255, 204))
#             return str(self.__data)
#         elif t == "unicode":
#             self.setText(QString.fromUtf8(self.__data))
#             self.setBackgroundColor(QColor(204, 255, 255))
#             return self.__data
#         elif t == "long":
#             self.setText(QString.fromUtf8(str(self.__data)))
#             self.setBackgroundColor(QColor(204, 255, 204))
#             return str(self.__data)
#         elif t == "buffer":
#             self.setText(QString("BLOB (Size: " + str(len(self.__data)) + ")"))
#             self.setBackgroundColor(QColor(204, 204, 255))
#             return "BLOB (Size: " + str(len(self.__data))
#         elif t == "NoneType":
#             self.setText(QString(""))
#             self.setBackgroundColor(QColor(255, 204, 204))
#             return ""
#         else:
#             return None

#     def getData(self):
#         return self.__data

# class DatabaseTreeItem(QTreeWidgetItem):
#     def __init__(self, parent, nodeDB, isTable=False):
#         QTreeWidgetItem.__init__(self, parent)
#         self.__isTable = isTable
#         self.__nodeDB = nodeDB
#         self.setFlags(Qt.ItemIsSelectable|Qt.ItemIsEnabled)

#     def nodeDB(self):
#         return self.__nodeDB

#     def isTable(self):
#         return self.__isTable

# class TableResult(QTableWidget):
#     def __init__(self, parent, custom=False):
#         QTableWidget.__init__(self, parent)
#         self.manager = parent
#         self.custom = custom
#         self.config()
#         self.__selectedItem = None

#     def config(self):
#         # Horizontal Header configuration
#         header = QHeaderView(Qt.Horizontal)
#         header.setVisible(True)
#         self.setHorizontalHeader(header)
#         # Vertical Header configuration
#         vheader = QHeaderView(Qt.Vertical)
#         vheader.setVisible(False)
#         vheader.setDefaultSectionSize(20)
#         vheader.setMinimumSectionSize(20)
#         self.setVerticalHeader(vheader)
#         # Table Configuration
#         self.setSortingEnabled(True)
#         self.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
#         self.setSelectionMode(QAbstractItemView.ExtendedSelection)
#         self.setTextElideMode(Qt.ElideRight)
#         self.setSelectionBehavior(QAbstractItemView.SelectRows)

#     def currentItem(self):
#         return self.__selectedItem

#     def mousePressEvent(self, event):
#         item = self.itemAt(event.pos())
#         if item != None:
#             self.__selectedItem = item
#             if event.button() == Qt.RightButton:
#                 self.buildMenu(event)
#         return QAbstractItemView.mousePressEvent(self, event)

#     def buildMenu(self, event):
#         item = self.itemAt(event.pos())
#         menu = QMenu(self)
#         menu.addAction(self.manager.actionExport_selection_CSV)
#         if item.getType() == "buffer":
#             menu.addAction(self.manager.actionExtract_Binary_BLOB)
#         menu.addAction(self.manager.actionDecode_date_column)
#         menu.addAction(self.manager.actionReset_column)
#         menu.popup(event.globalPos())

