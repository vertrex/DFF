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
import os, sys, inspect, threading
import signal; signal.signal(signal.SIGINT, signal.SIG_DFL)
from code import InteractiveInterpreter 

from PyQt4.QtGui import QAction, QApplication, QTextEdit, QTextCursor , QPalette, QColor, QBrush, QHBoxLayout, QIcon, QDockWidget
from PyQt4.QtCore import Qt, QString, QThread, QSemaphore, SIGNAL, QObject, QEvent

from dff.ui.redirect import RedirectIO
from dff.ui.gui.resources.ui_interpreter import Ui_Interpreter

class InterpreterView(QTextEdit, InteractiveInterpreter, Ui_Interpreter):
    def __init__(self, parent=None, log=''):
        QTextEdit.__init__(self, parent)
	InteractiveInterpreter.__init__(self, None)
        self.setupUi(self)
        self.name = self.windowTitle()
        self.log = log or ''
        self.__canwrite = True

        if parent is None:
            self.eofKey = Qt.Key_D
        else:
            self.eofKey = None
       
        self.line    = QString()
        self.lines   = []
        self.point   = 0
        self.more    = 0
        self.reading = 0
        self.history = []
        self.pointer = 0
        self.cursor_pos   = 0
        self.fgcolor = QColor("white")
        self.selcolor = QColor("green")
        self.strcolor = QColor("red")

	self.redirect = RedirectIO()
	self.sig = "Iputtext"
	self.connect(self, SIGNAL(self.sig), self.puttext)
	self.redirect.addparent(self, ["dff.ui.gui.widget.interpreter", "code", "__console__", "pydoc"])

        self.ps1 = ">>> "
        self.ps2 = "... "
        self.writePrompt()
        api_imports = ["from dff.api.types.libtypes import Variant, VList, VMap, DateTime, typeId, Argument, Parameter, ConfigManager, Constant, Config, Path",
                       "from dff.api.vfs.vfs import vfs",
                       "from dff.api.vfs.libvfs import VFS, FileMapping, ABSOLUTE_ATTR_NAME, RELATIVE_ATTR_NAME",
                       "from dff.api.filters.libfilters import Filter",
                       "from dff.api.search.libsearch import Search",
                       "from dff.api.events.libevents import EventHandler, event",
                       "from dff.api.datatype.libdatatype import DataTypeManager, DataTypeHandler",
                       "from dff.api.loader.loader import loader",
                       "from dff.api.module.module import Module, Script",
                       "from dff.api.taskmanager.taskmanager import TaskManager"]
        for api_import in api_imports:
            self.more = self.runsource(api_import)

    def writePrompt(self):
        self.write('\n')
        self.write(self.ps1)
        
    def write(self, str):
	self.redirect.write(str)

    def puttext(self, text):
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.End)
        pos1 = cursor.position()
        cursor.insertText(text)
        self.cursor_pos = cursor.position()
        self.setTextCursor(cursor)
        self.ensureCursorVisible()
        cursor.setPosition(pos1, QTextCursor.KeepAnchor)
        format = cursor.charFormat()
        format.setForeground(QBrush(self.fgcolor))
        cursor.setCharFormat(format)


    def get_interpreter(self):
        """ Return the interpreter object """
	return self

    def moveCursor(self, operation, mode=QTextCursor.MoveAnchor):
        """
        Convenience function to move the cursor
        This function will be present in PyQT4.2
        """
        cursor = self.textCursor()
        cursor.movePosition(operation, mode)
        self.setTextCursor(cursor)

    def flush(self):
        pass

    def isatty(self):
        return 1

    def clear(self):
        """ Clear """

    def readline(self):
        self.reading = 1
        self.__clearLine()
        self.moveCursor(QTextCursor.End)
        while self.reading:
            QtGui.qApp.processEvents()
        if self.line.length() == 0:
            return '\n'
        else:
            return str(self.line) 
    

    def writelines(self, text):
        """
        Simulate stdin, stdout, and stderr.
        """
        map(self.write, text)


    def fakeUser(self, lines):
        """
        Simulate a user: lines is a sequence of strings, (Python statements).
        """
        for line in lines:
            self.line = QString(line.rstrip())
            self.write(self.line)
            self.write('\n')
            self.run()

    def runsource_callback(self, source):
        self.__canwrite = False
        self.more = self.runsource(source)
        if self.more:
            self.write(self.ps2)
        else:
            self.write(self.ps1)
            self.lines = []
        self.__clearLine()
        self.__canwrite = True


    def run(self):
        self.pointer = 0
        self.history.append(QString(self.line))
        try:
            self.lines.append(str(self.line))
        except Exception,e:
            print e
	source = '\n'.join(self.lines)
        thread = threading.Thread(target=self.runsource_callback, args=(source, ))
        thread.start()
        #self.more = self.runsource(source)
        #if self.more:
        #    self.write(self.ps2)
        #else:
        #    self.write(self.ps1)
        #    self.lines = []
        #self.__clearLine()


    def __clearLine(self):
        """
        Clear input line buffer
        """
        self.line.truncate(0)
        self.point = 0
        
    def __insertText(self, text):
        """
        Insert text at the current cursor position.
        """
        self.line.insert(self.point, text)
        self.point += text.length()
        cursor = self.textCursor()
        cursor.insertText(text)
        self.color_line()


    def keyPressEvent(self, e):
        """
        Handle user input a key at a time.
        """
        text  = e.text()
        key   = e.key()

        if not self.__canwrite:
            e.ignore()
            return

        if key == Qt.Key_Backspace:
            if self.point:
                cursor = self.textCursor()
                cursor.movePosition(QTextCursor.PreviousCharacter, QTextCursor.KeepAnchor)
                cursor.removeSelectedText()
                self.color_line()
                self.point -= 1 
                self.line.remove(self.point, 1)

        elif key == Qt.Key_Delete:
            cursor = self.textCursor()
            cursor.movePosition(QTextCursor.NextCharacter, QTextCursor.KeepAnchor)
            cursor.removeSelectedText()
            self.color_line()
            self.line.remove(self.point, 1)
            
        elif key == Qt.Key_Return or key == Qt.Key_Enter:
            self.write('\n')
            if self.reading:
                self.reading = 0
            else:
                self.run()
                
        elif key == Qt.Key_Tab:
	    self.__insertText(text)
        elif key == Qt.Key_Left:
            if self.point : 
                self.moveCursor(QTextCursor.Left)
                self.point -= 1 
        elif key == Qt.Key_Right:
            if self.point < self.line.length():
                self.moveCursor(QTextCursor.Right)
                self.point += 1 

        elif key == Qt.Key_Home:
            cursor = self.textCursor ()
            cursor.setPosition(self.cursor_pos)
            self.setTextCursor (cursor)
            self.point = 0 

        elif key == Qt.Key_End:
            self.moveCursor(QTextCursor.EndOfLine)
            self.point = self.line.length() 

        elif key == Qt.Key_Up:
            if len(self.history):
                if self.pointer == 0:
                    self.pointer = len(self.history)
                self.pointer -= 1
                self.__recall()
                
        elif key == Qt.Key_Down:
            if len(self.history):
                self.pointer += 1
                if self.pointer == len(self.history):
                    self.pointer = 0
                self.__recall()

        elif text.length():
            self.__insertText(text)
            return

        else:
            e.ignore()

    def __recall(self):
        """
        Display the current item from the command history.
        """
        cursor = self.textCursor ()
        cursor.select( QTextCursor.LineUnderCursor )
        cursor.removeSelectedText()
        if self.more:
            self.write(self.ps2)
        else:
            self.write(self.ps1)
        self.__clearLine()
        self.__insertText(self.history[self.pointer])

    def mousePressEvent(self, e):
        """
        Keep the cursor after the last prompt.
        """
        if e.button() == Qt.LeftButton:
            self.moveCursor(QTextCursor.End)
            

    def contentsContextMenuEvent(self,ev):
        """
        Suppress the right button context menu.
        """
        pass
    
    def dragEnterEvent(self, event):
        event.setAccepted(event.mimeData().hasFormat("text/plain"))

    def dragMoveEvent(self, event):
        if (event.mimeData().hasFormat("text/plain")):
            event.setDropAction(QtCore.Qt.MoveAction)
            event.accept()
        else:
            event.ignore()
            
    def dropEvent(self, event):
        if(event.mimeData().hasFormat("text/plain")):
            line = event.mimeData().text()
            self.__insertTextAtEnd(line)
            self.setFocus()
            event.setDropAction(QtCore.Qt.MoveAction)
            event.accept()
        else:
            event.ignore()

    def color_line(self):
        """ Color the current line """
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.StartOfLine)
        newpos = cursor.position()
        pos = -1
        while(newpos != pos):
            cursor.movePosition(QTextCursor.NextWord)
            pos = newpos
            newpos = cursor.position()
            cursor.select(QTextCursor.WordUnderCursor)
            word = str(cursor.selectedText ().toAscii())
            if(not word) : continue
            color = self.get_color(word)
            format = cursor.charFormat()
            format.setForeground(QBrush(color))
            cursor.setCharFormat(format)

    keywords = set(["and", "del", "from", "not", "while",
                "as", "elif", "global", "or", "with",
                "assert", "else", "if", "pass", "yield",
                "break", "except", "import", "print",
                "class", "exec", "in", "raise",              
                "continue", "finally", "is", "return",
                "def", "for", "lambda", "try"])

    def get_color(self, word):
        stripped = word.strip()
        if(stripped in self.keywords):
            return (self.selcolor)
        elif(self.is_python_string(stripped)):
            return (self.strcolor)
        else:
            return (self.fgcolor)

    def is_python_string(self, str):
        """ Return True if str is enclosed by a string mark """
        return ((str.startswith("'''") and str.endswith("'''")) or (str.startswith('"""') and str.endswith('"""')) or \
             (str.startswith("'") and str.endswith("'")) or (str.startswith('"') and str.endswith('"')))

    def changeEvent(self, event):
        """ Search for a language change event

        This event have to call retranslateUi to change interface language on
        the fly.
        """
        if event.type() == QEvent.LanguageChange:
            self.retranslateUi(self)
            self.writePrompt()
            
        else:
            QTextEdit.changeEvent(self, event)


class InterpreterActions(QObject):
  def __init__(self, mainwindow):
    QObject.__init__(self)
    self.mainwindow = mainwindow

  def create(self):
      self.mainwindow.addSingleDock("Interpreter", InterpreterView)	
