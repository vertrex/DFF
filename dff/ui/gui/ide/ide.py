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
#  Jeremy Mounier <jmo@digital-forensic.org>
# 
from PyQt4.QtCore import *
from PyQt4.QtGui import *

from dff.api.loader import *

from dff.ui.gui.ide.idewizard import IdeWizard
from dff.ui.gui.ide.generatecode import GenerateCode
from dff.ui.gui.ide.messagebox import MessageBoxWarningSave
from dff.ui.gui.ide.editor import codeEditor
from dff.ui.gui.ide.explorer import Explorer
from dff.ui.gui.resources.ui_ide import Ui_Ide

class Ide(QWidget, Ui_Ide):
    def __init__(self, parent):
        super(Ide,  self).__init__(parent)
        self.setupUi(self)
        self.loader = loader.loader()

        self.name = "IDE"
        self.pages = []
        self.mainWindow = parent

        self.initCallBacks()
        self.translation()
        self.addMainMenuActions()
        self.g_display()
        

    def initCallBacks(self):
        self.newemptyact.connect(self.newemptyact,  SIGNAL("triggered()"), self.newempty)
        self.newact.connect(self.newact,  SIGNAL("triggered()"), self.new)
        self.openact.connect(self.openact,  SIGNAL("triggered()"), self.open)
        self.saveact.connect(self.saveact,  SIGNAL("triggered()"), self.save)
        self.saveasact.connect(self.saveasact,  SIGNAL("triggered()"), self.saveAs)
        self.runact.connect(self.runact,  SIGNAL("triggered()"), self.run)
        self.undoact.connect(self.undoact,  SIGNAL("triggered()"), self.undo)
        self.redoact.connect(self.redoact,  SIGNAL("triggered()"), self.redo)
        self.commentact.connect(self.commentact,  SIGNAL("triggered()"), self.comment)
        self.uncommentact.connect(self.uncommentact,  SIGNAL("triggered()"), self.uncomment)

        # save on CTRL + S
        self.seq = QKeySequence(Qt.CTRL + Qt.Key_S)
        self.ctrl_s_save = QShortcut(self)
        self.ctrl_s_save.setContext(Qt.WindowShortcut)
        self.ctrl_s_save.setKey(self.seq)
        self.ctrl_s_save.connect(self.ctrl_s_save, SIGNAL("activated()"), self.save)
        #self.ctrl_s_save.connect(self.ctrl_s_save, SIGNAL("activatedAmbiguously()"), self.save)

    def addMainMenuActions(self):
        self.mainWindow.menuIDE.addSeparator()
        self.mainWindow.menuIDE.addAction(self.newemptyact)
        self.mainWindow.menuIDE.addAction(self.newact)
        self.mainWindow.menuIDE.addAction(self.openact)
        self.mainWindow.menuIDE.addAction(self.saveact)
        self.mainWindow.menuIDE.addAction(self.saveasact)
        self.mainWindow.menuIDE.addAction(self.runact)
        self.mainWindow.menuIDE.addSeparator()
        self.mainWindow.menuIDE.addAction(self.undoact)
        self.mainWindow.menuIDE.addAction(self.redoact)
        self.mainWindow.menuIDE.addAction(self.commentact)
        self.mainWindow.menuIDE.addAction(self.uncommentact)

    def g_display(self):
        self.splitter = QSplitter()
        self.createExplorer()
        self.createTabWidget()
        self.splitter.setSizes([1, 4])
        self.vbox.addWidget(self.splitter)
        self.refreshToolbar()
        self.setLayout(self.vbox)

    def createExplorer(self):
        self.explorer = Explorer(parent=self)
        self.splitter.addWidget(self.explorer)

    def createTabWidget(self):
        self.scripTab = QTabWidget()
        self.buttonCloseTab = QPushButton("")
        self.buttonCloseTab.setFixedSize(QSize(23,  23))
        self.buttonCloseTab.setIcon(QIcon(":cancel.png"))
        self.buttonCloseTab.setEnabled(False)
        self.buttonCloseTab.setFlat(True)
        self.scripTab.setCornerWidget(self.buttonCloseTab,  Qt.TopRightCorner)
        self.scripTab.connect(self.buttonCloseTab, SIGNAL("clicked()"), self.closeTabWidget)
        self.splitter.addWidget(self.scripTab)

    def createPage(self,  buffer):
        page = codeEditor()
        page.setPlainText(QString(buffer))
        self.pages.append(page)
        return page

    def new(self):
        self.ideWiz = IdeWizard(self)
        ret = self.ideWiz.exec_()
        if ret > 0:
            scriptname = self.ideWiz.field("name").toString()
            path = self.ideWiz.field("path").toString()
            stype = self.ideWiz.field("typeS").toBool()
            gtype = self.ideWiz.field("typeG").toBool()
            dtype = self.ideWiz.field("typeD").toBool()
            category = self.ideWiz.category.currentText()
            description = self.ideWiz.field("description").toString()
            authfname = self.ideWiz.field("authFName").toString()
            authlname = self.ideWiz.field("authLName").toString()
            authmail = self.ideWiz.field("authMail").toString()

            generate = GenerateCode()
            generate.set_header(authfname, authlname, authmail)
            generate.setTag(category)
            generate.setDescription(description)
            if stype == True:
                buffer = generate.generate_script(str(scriptname))
                scin = self.createPage(buffer)
            if dtype == True:
                buffer = generate.generate_drivers(str(scriptname))
                scin = self.createPage(buffer)
            if gtype == True:
                buffer = generate.generate_script_gui(str(scriptname))
                scin = self.createPage(buffer)
            
            filename = scriptname + ".py"                
            scin.setName(filename)

            if path[-1] != "/":
                path += "/"
            lpath = path + filename
            scin.setScriptPath(lpath)
            self.scripTab.addTab(scin,  filename)
            self.buttonCloseTab.setEnabled(True)
            self.refreshToolbar()

    def newempty(self):
        page = self.createPage("")
        name = "Default_" + self.checkTabNames("Default")
        page.setName(name)
        self.scripTab.addTab(page,  name)
        self.buttonCloseTab.setEnabled(True)
        self.refreshToolbar()

    def checkTabNames(self, name):
        tab = self.scripTab.tabBar()
        cp = 0
        for i in xrange(tab.count()):
            if tab.tabText(i).startsWith(name):
                cp += 1
        return str(cp)
    
    def open(self, path=None):
        if path == None:
            sFileName = QFileDialog.getOpenFileName(self.mainWindow, self.openFile, "/home")
        else:
            sFileName = path
        if sFileName:
            file = open(sFileName,  "r")
            page = self.createPage("")
            buffer = QString()
            buffer = file.read()
            page.setPlainText(buffer)
            script = sFileName.split("/")
            
            scriptname = script[len(script) - 1]
            page.setName(scriptname)
            
            page.setScriptPath(sFileName)
            self.scripTab.addTab(page,  scriptname)
            self.buttonCloseTab.setEnabled(True)
            self.refreshToolbar()
            file.close
    
    def save(self):
        index = self.scripTab.currentIndex()
        page = self.pages[index]
        path = page.getScriptPath()
        if path != "":
            file = open(path,  "w")
            file.write(page.toPlainText())
            file.close()
        else:
            self.saveasactBack()
            
    def saveAs(self):
        index = self.scripTab.currentIndex()
        title = self.scripTab.tabText(index)
        if title:
            sFileName = QFileDialog.getSaveFileName(self, self.saveFileAs, title)
            page = self.pages[index]
            file = open(str(sFileName),"w")
            file.write(page.toPlainText())
            file.close()
        
    def run(self):
        if self.scripTab.count() > 0:
            index = self.scripTab.currentIndex()
            page = self.pages[index]
            self.save()

            path = page.getScriptPath()
            self.loader.do_load(str(path))
        else:
            print self.noFileFound
        
    def undo(self):
        if self.scripTab.count() > 0:
            index = self.scripTab.currentIndex()
            page = self.pages[index]
            page.undo()

    def redo(self):
        if self.scripTab.count() > 0:
            index = self.scripTab.currentIndex()
            page = self.pages[index]
            page.redo()

    def comment(self):
        if self.scripTab.count() > 0:
            index = self.scripTab.currentIndex()
            page = self.pages[index]
            page.comment()

    def uncomment(self):
        if self.scripTab.count() > 0:
            index = self.scripTab.currentIndex()
            page = self.pages[index]
            page.uncomment()


    def refreshToolbar(self):
        if self.scripTab.count() == 0:
            self.saveact.setEnabled(False)
            self.saveasact.setEnabled(False)
            self.runact.setEnabled(False)
            self.undoact.setEnabled(False)
            self.redoact.setEnabled(False)
            self.commentact.setEnabled(False)
            self.uncommentact.setEnabled(False)
        else:
            self.saveact.setEnabled(True)
            self.saveasact.setEnabled(True)
            self.runact.setEnabled(True)
            self.undoact.setEnabled(True)
            self.redoact.setEnabled(True)
            self.commentact.setEnabled(True)
            self.uncommentact.setEnabled(True)

    def closeTabWidget(self):
        if self.scripTab.count() > 0:
            index = self.scripTab.currentIndex()
            currentPage = self.scripTab.currentWidget()
            warning = MessageBoxWarningSave(self,  self.saveQuestion)
            warning.exec_()

            self.scripTab.removeTab(index)
            page = self.pages[index]
            self.pages.remove(page)
            currentPage.destroy(True, True)
            if self.scripTab.count() == 0:
                self.buttonCloseTab.setEnabled(False)
                self.refreshToolbar()

    def translation(self):
        self.saveQuestion = self.tr("Save document ?")
        self.noFileFound = self.tr("No file found")
        self.openFile = self.tr("Open file")
        self.saveFileAs = self.tr("Save file as")

    def changeEvent(self, event):
        """ Search for a language change event
        
        This event have to call retranslateUi to change interface language on
        the fly.
        """
        if event.type() == QEvent.LanguageChange:
            self.retranslateUi(self)
            self.translation()
        else:
            QWidget.changeEvent(self, event)
