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
#  Solal Jacob <sja@arxsys.fr>
# 

import sys, os

from Queue import Empty 

from PyQt4.QtGui import QAction,  QApplication, QDockWidget, QFileDialog, QIcon, QMainWindow, QMessageBox, QMenu, QTabWidget, QTextEdit, QTabBar, QPushButton, QCheckBox, QHBoxLayout, QVBoxLayout, QWidget, QStackedWidget, QSizePolicy, QPixmap
from PyQt4.QtCore import QEvent, Qt,  SIGNAL, QModelIndex, QSettings, QFile, QString, QTimer
from PyQt4 import QtCore, QtGui

from dff.api.vfs import vfs
from dff.api.vfs.libvfs import VFS, Node, ModulesRootNode 
from dff.api.taskmanager import scheduler

from dff.ui.gui.widget.textedit import TextEdit
from dff.ui.gui.widget.dockwidget import DockWidget 
from dff.ui.gui.widget.nodelistwidgets import NodeListWidgets
from dff.ui.gui.dialog.applymodule import ApplyModule

from dff.ui.conf import Conf

from dff.ui.gui.widget.taskmanager import Processus
from dff.ui.gui.widget.modules import Modules
from dff.ui.gui.widget.stdio import STDErr, STDOut

from dff.ui.gui.widget.shell import ShellActions
from dff.ui.gui.widget.interpreter import InterpreterActions
from dff.ui.gui.widget.preview import Preview

from dff.ui.gui.utils.utils import Utils
from dff.ui.gui.utils.menu import MenuTags
from dff.ui.gui.dialog.dialog import Dialog
from dff.ui.gui.resources.ui_mainwindow import Ui_MainWindow

from dff.ui.gui.widget.help import Help

from dff.ui.gui.widget.postprocessstate import PostProcessStateWidget
from dff.ui.gui.wizard.autowizard import AutoWizard
try:
  from dff.ui.gui.widget.reporteditor import ReportEditor 
  REPORT_EDITOR = True
except Exception as e:
  print("Can't load report editor : " + str(e))
  REPORT_EDITOR = False

class MainWindow(QMainWindow, Ui_MainWindow):
    def __init__(self,  app, debug = False):
        super(MainWindow,  self).__init__()
        # Tab management private attributes, modify at own risk
        self.__tabMoved = False
        self.__tabAreaInformation = (-1, -1, [])
        self.__tabConnections = set()
        self.app = app
        self.debug = debug
        self.sched = scheduler.sched
        self.vfs = vfs.vfs()
        self.createRootNodes()
        self.dialog = Dialog(self)
	self.initCallback()
        self.setupUi(self)
        self.translation()
        self.setWindowModality(QtCore.Qt.ApplicationModal)
        self.resize(QtCore.QSize(QtCore.QRect(0,0,1014,693).size()).expandedTo(self.minimumSizeHint()))
	self.shellActions = ShellActions(self)
	self.interpreterActions = InterpreterActions(self)
        self.setCentralWidget(None)
        self.setDockNestingEnabled(True)
        self.init()
        self.status = QStackedWidget()
        sizePolicy = QSizePolicy(QSizePolicy.Minimum, QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(1)
        sizePolicy.setVerticalStretch(1)
        self.status.setSizePolicy(sizePolicy)
        self.statusBar().addWidget(self.status)

    def setupUi(self, MainWindow):
      self.actionWizard = QAction(self)
      icon = QIcon()   
      icon.addPixmap(QPixmap(QString.fromUtf8(":/wizard")), QIcon.Normal, QIcon.Off)
      self.actionWizard.setIcon(icon)
      self.actionWizard.setObjectName(QString.fromUtf8("actionWizard"))

      Ui_MainWindow.setupUi(self, MainWindow)  
      self.menuFile.insertAction(self.actionOpen_evidence, self.actionWizard)
      self.retranslateUi(MainWindow)
    
      if REPORT_EDITOR:
        self.actionReport = QAction(self)
        icon = QIcon()
        icon.addPixmap(QPixmap(QString.fromUtf8(":report")), QIcon.Normal, QIcon.Off)
        self.actionReport.setIcon(icon)
        self.actionReport.setObjectName(QString.fromUtf8("actionReport"))

        self.menuReport = QMenu(self.menubar)
        self.menuReport.setObjectName(QString.fromUtf8("menuReport"))
        self.menuReport.addAction(self.actionReport)
	self.actionReport.setText(QApplication.translate("MainWindow", "Report", None, QApplication.UnicodeUTF8))
        self.actionReport.setToolTip(QApplication.translate("MainWindow", "Open the report editor", None, QApplication.UnicodeUTF8))
        try:
          self.menuReport.setTitle(QApplication.translate("MainWindow", "Report", None, QApplication.UnicodeUTF8))
        except AttributeError:
          pass


    def retranslateUi(self, MainWindow):
      Ui_MainWindow.retranslateUi(self, MainWindow)
      self.actionWizard.setText(QApplication.translate("MainWindow", "Wizard", None, QApplication.UnicodeUTF8))
        
    def init(self):
        self.initConnection()
        # Set up toolbar
        self.initToolbarList()
        self.setupToolBar()

        # Set up modules menu
        self.MenuTags = MenuTags(self, self)
        self.refreshTabifiedDockWidgets()

    def cclose(self):
       #stats = yappi.get_func_stats()
       #stats.save("func_stats_cgrind.out", type="callgrind")
       #stats.save("func_stats_pstat.out", type="pstat")
       #threadstats = yappi.get_thread_stats()
       #threadstats.save("thread_stats_cgrind.out", type="callgrind")
       #threadstats.save("thread_stats_pstat.out", type="pstat")
       self.close()

    def initConnection(self):
        ## File menu
        self.connect(self.actionOpen_evidence, SIGNAL("triggered()"), self.dialog.addFiles)
        self.connect(self.actionOpen_device, SIGNAL("triggered()"), self.dialog.addDevices)
        self.connect(self.actionExit, SIGNAL("triggered()"), self.cclose)
        ## Edit menu
        self.connect(self.actionPreferences, SIGNAL("triggered()"), self.dialog.preferences)
        ## Module menu
        self.connect(self.actionLoadModule, SIGNAL("triggered()"), self.dialog.loadDriver)
        self.connect(self.actionBrowse_modules, SIGNAL("triggered()"), self.dialog.manager)
        ## Ide menu
        #self.connect(self.actionIdeOpen, SIGNAL("triggered()"), self.addIde)
        ## View menu
        self.connect(self.actionMaximize, SIGNAL("triggered()"), self.maximizeDockwidget)
        self.connect(self.actionFullscreen_mode, SIGNAL("triggered()"), self.fullscreenMode)
        self.connect(self.actionNodeBrowser, SIGNAL("triggered()"), self.addNodeBrowser)
        self.connect(self.actionShell, SIGNAL("triggered()"), self.shellActions.create)
        self.connect(self.actionPython_interpreter, SIGNAL("triggered()"), self.interpreterActions.create)        ## About menu 

        self.connect(self.actionHelp, SIGNAL("triggered()"), self.addHelpWidget)
        self.connect(self.actionAbout, SIGNAL("triggered()"), self.dialog.about)       
        self.connect(self.actionWizard, SIGNAL('triggered()'), self.autoWizard)
        if REPORT_EDITOR:
          self.connect(self.actionReport, SIGNAL("triggered()"), self.addReportEdit)
          self.connect(self, SIGNAL("addReportEdit()"), self.addReportEdit)

    def initToolbarList(self):
        self.toolbarList = [
			    self.actionOpen_evidence,
                            self.actionOpen_device,
                            None,
                            self.actionNodeBrowser,
                            self.actionShell,
                            self.actionPython_interpreter,
#                            self.actionIdeOpen,
#                            self.actionHelp,
#                            None,
#                            self.actionMaximize,
#                            self.actionFullscreen_mode,
#                            self.actionBrowse_modules,
                            ]
        self.toolbarList.insert(0, self.actionWizard)  
        if REPORT_EDITOR:
          self.toolbarList.insert(len(self.toolbarList) - 1, self.actionReport)

#############  DOCKWIDGETS FUNCTIONS ###############
    def createDockWidget(self, widget, widgetName):
        dockwidget = DockWidget(self, widget, widgetName)
        dockwidget.setAllowedAreas(Qt.AllDockWidgetAreas)
        return dockwidget

    def addDockWidgets(self, widget, internalName, master=True):
        if widget is None:
            return
        if self.last_state is not None:
            self.maximizeDockwidget()
        if widget.windowTitle() != "":
          wname = widget.windowTitle()
        else:
          wname = widget.name
        new_master = self.getMasterDockWidget()
        if new_master != None:
            self.master = new_master
        dockwidget = self.createDockWidget(widget, wname)
        docIndex, docTitle = self.getWidgetName(wname)
        dockwidget.setWindowTitle(QString.fromUtf8(docTitle))
        self.connect(dockwidget, SIGNAL("resizeEvent"), widget.resize)

        self.addDockWidget(self.masterArea, dockwidget)
        if master:
            self.tabifyDockWidget(self.master, dockwidget)
        else:
            self.tabifyDockWidget(self.second, dockwidget)

        if docIndex:
            self.dockWidget[internalName + str(docIndex)] = dockwidget
        else:
            self.dockWidget[internalName] = dockwidget
        self.refreshTabifiedDockWidgets()

    def getWidgetName(self, name):
        did = 0
        for d in self.dockWidget:
            if self.dockWidget[d].windowTitle().startsWith(QString(name)):
                did += 1
        if did > 0:
            name = name + ' ' + str(did)
        return (did, name)

    def addSingleDock(self, name, cl, master=False):
        try:
            self.dockWidget[name].show()
            self.refreshTabifiedDockWidgets()
        except KeyError:
            w = cl(self)
            self.addDockWidgets(w, name, master)
           

    def getNodeBrowser(self):
        nb = self.nodeListWidgets()
        return nb

    def addNodeBrowser(self, rootpath=None, selectedNode=None):
        nb = self.getNodeBrowser()
        self.addDockWidgets(nb, 'nodeBrowser')
        nb.setCurrentContext(rootpath, selected=selectedNode)


    def addSearchTab(self, search):
        self.addDockWidgets(search, 'Searchr')

    def addHelpWidget(self):
        if hasattr(sys, "frozen"):
           path = os.path.abspath(os.path.join(os.path.dirname(sys.executable), "resources/docs/dff_doc.qhc"))
        else:
           conf = Conf()
           path = conf.docPath
        file = QFile(path)
        if not file.exists(path):
            if path:
                dialog = QMessageBox.warning(self, self.errorLoadingHelp, QString(path) + ": " + self.notAnHelpFile)
            else:
                dialog = QMessageBox.warning(self, self.errorLoadingHelp, self.noSuchHelpFile)
            return                
        self.addDockWidgets(Help(self, path=path), 'help')

    def addInterpreter(self):
       self.addSingleDock("Interpreter", Interpreter)

    def initDockWidgets(self):
        """Init Dock in application and init DockWidgets"""
        widgetPos = [ ( Qt.TopLeftCorner, Qt.LeftDockWidgetArea, QTabWidget.North),
	 (Qt.BottomLeftCorner, Qt.BottomDockWidgetArea, QTabWidget.North), 
	 (Qt.TopLeftCorner, Qt.TopDockWidgetArea, QTabWidget.North), 
	 (Qt.BottomRightCorner, Qt.RightDockWidgetArea, QTabWidget.North) ]

        for corner, area, point in widgetPos:
            self.setCorner(corner, area)
            try:
                self.setTabPosition(area, point)
            except AttributeError:
                pass
        self.dockWidget = {}
        self.widget = {}
        self.masterArea = Qt.TopDockWidgetArea
        self.secondArea = Qt.BottomDockWidgetArea
        self.last_state = None
        self.last_dockwidget = None
        self.last_widget = None

        self.createFirstWidgets()
        
        self.refreshSecondWidgets()
        self.refreshTabifiedDockWidgets()
        if REPORT_EDITOR:
          self.addReportEdit()
          self.dockWidget['Report'].setVisible(False)

    def autoWizard(self):
        autoWiz = AutoWizard(self)
        autoWiz.exec_()

    def nodeListWidgets(self, parent = None):
       return NodeListWidgets(parent)

    def createProcessusWidget(self):
        return Processus(self)

    def createSTDOutWidget(self):
       return STDOut(self, self.debug)

    def createSTDErrWidget(self):
       return STDErr(self, self.debug)

    def addReportEdit(self):
        self.addSingleDock("Report", ReportEditor, master=True)

    def showReportEdit(self):
        self.emit(SIGNAL("addReportEdit()"))

    def createFirstWidgets(self):
        self.nodeBrowser = self.nodeListWidgets(parent=self)
        root = self.vfs.getnode('/')
        self.nodeBrowser.setCurrentContext(root)

        self.master = self.createDockWidget(self.nodeBrowser, self.nodeBrowser.name)
        self.master.setAllowedAreas(Qt.AllDockWidgetAreas)
        self.master.setWindowTitle(self.nodeBrowser.name)
        self.dockWidget["nodebrowser"] = self.master

        self.wprocessus = self.createProcessusWidget()
        self.second = self.createDockWidget(self.wprocessus, "Task manager")
        self.second.setAllowedAreas(Qt.AllDockWidgetAreas)
        self.second.setWindowTitle(self.wprocessus.windowTitle())
        self.dockWidget["Task manager"] = self.second
        self.addDockWidget(self.masterArea, self.master)
        self.addDockWidget(self.secondArea, self.second)
        self.timer = QTimer(self)
	self.connect(self.timer, SIGNAL("timeout()"), self.refreshSecondWidgets)
        self.timer.start(2000)      

        self.wstdout = self.createSTDOutWidget()
        self.wstderr = self.createSTDErrWidget()

        self.addDockWidgets(self.wstdout, 'stdout', master=False)
        self.addDockWidgets(self.wstderr, 'stderr', master=False)
        self.wmodules = Modules(self)
        self.addDockWidgets(self.wmodules, 'modules', master=False)
        self.preview = Preview(self)
        self.addDockWidgets(self.preview, 'preview', master=False)
        self.connect(self, SIGNAL("previewUpdate"), self.preview.update)

        self.wpostprocess = PostProcessStateWidget(self)
        self.addDockWidgets(self.wpostprocess, "Post Process State", False)

    def maximizeDockwidget(self):
        if self.last_state is None:
            self.last_state = self.saveState()
            focus_widget = QApplication.focusWidget()
            for key, dock in self.dockWidget.iteritems():
                dock.hide()
                if dock.isAncestorOf(focus_widget):
                    self.last_dockwidget = dock
            if self.last_dockwidget != None:
                self.last_widget = self.last_dockwidget.widget()
                self.last_dockwidget.toggleViewAction().setDisabled(True)
                self.setCentralWidget(self.last_dockwidget.widget())
                self.last_dockwidget.visibility_changed(True)
                self.actionNodeBrowser.setEnabled(False)
                self.actionShell.setEnabled(False)
                self.actionPython_interpreter.setEnabled(False)
                #self.actionIdeOpen.setEnabled(False)
                self.actionHelp.setEnabled(False)
            else:
                self.last_state = None
        else:
            self.last_dockwidget.setWidget(self.last_widget)
            self.last_dockwidget.toggleViewAction().setEnabled(True)
            self.setCentralWidget(None)
            self.restoreState(self.last_state)
            self.last_dockwidget.setFocus()
            self.last_state = None
            self.last_widget = None
            self.last_dockwidget = None
            self.refreshTabifiedDockWidgets()
            self.actionNodeBrowser.setEnabled(True)
            self.actionShell.setEnabled(True)
            self.actionPython_interpreter.setEnabled(True)
            #self.actionIdeOpen.setEnabled(True)
            self.actionHelp.setEnabled(True)

    def fullscreenMode(self):
        if self.isFullScreen():
            self.showNormal()
        else:
            self.showFullScreen()

    def refreshSecondWidgets(self):
        if self.dockWidget["Task manager"].visibility():
	  self.wprocessus.LoadInfoProcess()
        if self.dockWidget["modules"].visibility():
          self.wmodules.LoadInfoModules()


    #
    # Following methods are in charge of tab management
    # By default tabified dock widgets are not movable.
    # And juste setting setMovable(True) is not enough.
    # All the magic is done in private class of Qt and
    # can't be overloaded. The last chance is to play
    # with signal and children management.
    #
    def updateTabConnections(self):
        children = self.children()
        for child in children:
            if child.inherits("QTabBar"):
                tabCount = child.count()
                child.setMovable(True)
                if child not in self.__tabConnections:
                    child.tabMoved.connect(self.tabMoved, type=Qt.UniqueConnection)
                    self.__tabConnections.add(child)


    # overloaded to add connections on new tabbar item
    def tabifyDockWidget(self, first, second):
        QMainWindow.tabifyDockWidget(self, first, second)
        self.updateTabConnections()


    # overloaded to connect to dockwidget location update
    def addDockWidget(self, area, dockwidget):
        dockwidget.dockLocationChanged.connect(self.updateTabConnections)
        return QMainWindow.addDockWidget(self, area, dockwidget)


    def event(self, event):
        mouse_status = int(QApplication.mouseButtons())
        # if updating tabbar while mouse pressed, behaviour can be weird
        if mouse_status & 0x00000001 == 0 and self.__tabMoved:
            self.__tabMoved = False
            self.updateTabBar()
        return QMainWindow.event(self, event)


    def updateTabBar(self):
        tab, to, _from = self.__tabAreaInformation
        dockwidget, siblings = self.findDockWidgetsFromTabBar(tab)
        updated_siblings = []
        visible = []
        hidden = []
        for sibling in siblings:
            if sibling.isVisible():
                visible.append(sibling)
            else:
                hidden.append(sibling)
        if to == 0:
            updated_siblings.append(dockwidget)
            updated_siblings += visible + hidden
        else:
            master = visible.pop(0)
            updated_siblings.append(master)
            visible.insert(to-1, dockwidget)
            updated_siblings += visible + hidden
        master = updated_siblings.pop(0)
        for sibling in updated_siblings:
            # always check if sibling != None or result in segfault if happens
            if sibling is not None:
                self.tabifyDockWidget(master, sibling)
        tab.setCurrentIndex(to)
        self.refreshTabifiedDockWidgets()


    # returns the location of the master dock widget (first created browser)
    def getMasterDockWidget(self):
        x_max = self.geometry().bottomRight().x()
        y_max = self.geometry().bottomRight().y()
        children = self.children()
        item = None
        for child in children:
            if child.inherits("QTabBar") or (child.inherits("QDockWidget") and child.isVisible()):
                child_x = child.geometry().topLeft().x()
                child_y = child.geometry().topLeft().y()
                if child_x >= 0 and child_y >= 0 and child_x <= x_max and child_y <= y_max:
                    x_max = child_x
                    y_max = child_y
                    item = child
        if item is not None:
            if item.inherits("QDockWidget"):
                return item
            else:
                title = item.tabText(0)
                for dockwidget in self.dockWidget.values():
                    if title.startsWith(dockwidget.windowTitle()):
                        return dockwidget
        else:
            # at init, there's no information, return None and keep self.master as is
            return None


    def refreshTabifiedDockWidgets(self):
        children = self.children()
        for child in children:
            if child.inherits("QTabBar"):
                tabCount = child.count()
                for idx in xrange(0, tabCount):
                    for v in self.dockWidget.values():
                        if v.widget() and child.tabText(idx).startsWith(v.windowTitle()) and not v.widget().windowIcon().isNull():
                            child.setTabIcon(idx, v.widget().windowIcon())


    # to and _from are volontary swapped here compared to the sent signal.
    def tabMoved(self, to, _from):
        tab = self.sender()
        self.__tabAreaInformation = (tab, to, _from)
        self.__tabMoved = True


    # gather all widgets associated to a tabbar
    # returns a tuple with first element being the
    # widget associated to currentIndex and the second
    # elements being its siblings
    def findDockWidgetsFromTabBar(self, tab):
        tabwidget = None
        tabname = ""
        if not isinstance(tab, QTabBar):
            return None
        siblings = []
        current_widget = None
        for i in xrange(0, tab.count()):
            title = tab.tabText(i)
            for dockwidget in self.dockWidget.values():
                if title == dockwidget.windowTitle():
                    if i == tab.currentIndex():
                        current_widget = dockwidget
                    else:
                        siblings.append(dockwidget)
        return (current_widget, siblings)


#############  END OF DOCKWIDGETS FUNCTIONS ###############

    def applyModule(self, modname, modtype, selected):
        appMod = ApplyModule(self)
        appMod.openApplyModule(modname, modtype, selected)

    def initCallback(self):
        self.sched.set_callback("add_qwidget", self.qwidgetResult)
        self.connect(self, SIGNAL("qwidgetResultView"), self.qwidgetResultView)
        self.connect(self, SIGNAL("strResultView"), self.strResultView)

    def qwidgetResult(self, qwidget):
        self.emit(SIGNAL("qwidgetResultView"), qwidget)
 
    def strResult(self, proc):
        self.emit(SIGNAL("strResultView"), proc)

    def qwidgetResultView(self, proc):
        proc.inst.g_display()
        self.addDockWidgets(proc.inst, proc.name)
        proc.inst.updateWidget()

    def strResultView(self, proc):
   	widget = TextEdit(proc)
	try :
	   res = ''
	   txt = proc.stream.get(0)
	   res += txt	
	   while txt:
	      txt = proc.stream.get(0)   
	      res += txt
	except Empty:
	    pass   
	if res and res != '':
	   widget.emit(SIGNAL("puttext"), res)
           self.addDockWidgets(widget, proc.name)

    def addToolBars(self, action):
        """ Init Toolbar"""
        if not action:
            #Add separator
            self.toolBar.addSeparator()
        else:
            action.setText(action.text())
            self.toolBar.addAction(action)

    def addAction(self, name, text, func = None, iconName = None, iconText = None):
        self.action[name] = QtGui.QAction(self)
        self.action[name].setObjectName("action" + name)
        self.action[name].setText(text)
        if iconName:
          self.action[name].setIcon(QIcon(iconName))
          if iconText:
            self.action[name].setIconText(iconText)
        if func:
          self.connect(self.action[name], SIGNAL("triggered()"), func)

    def setupToolBar(self):
        for action in self.toolbarList:
	   self.addToolBars(action)

    def createRootNodes(self):
        root = self.vfs.getnode('/')
        self.devicenode = deviceNode(root, str('Local devices'))
        self.logicalenode = logicalNode(root, str('Logical files'))
        self.modulesrootnode = ModulesRootNode(VFS.Get(), root)
        self.booknode = bookNode(root, str('Bookmarks'))

    def changeEvent(self, event):
        """ Search for a language change event

        This event have to call retranslateUi to change interface language on
        the fly.
        """
        if event.type() == QEvent.LanguageChange:
            self.retranslateUi(self)
            self.translation()
        else:
            QMainWindow.changeEvent(self, event)

    def translation(self):
        self.errorLoadingHelp = self.tr('Error while loading help')
        self.onlineHelp = self.tr('<br>You can check on-line help at <a href=\"http://wiki.digital-forensic.org/\">http://wiki.digital-forensic.org</a>.')
        self.notAnHelpFile = self.tr('Not an help file.') + self.onlineHelp
        self.noSuchHelpFile = self.tr('Documentation path not found.') + self.onlineHelp


class deviceNode(Node):
    def __init__(self, parent, name):
        Node.__init__(self, name, 0, parent, None)
        self.__disown__()

    def icon(self):
        return (":dev_hd.png")

class logicalNode(Node):
    def __init__(self, parent, name):
        Node.__init__(self, name, 0, parent, None)
        self.__disown__()

    def icon(self):
        return (":folder_documents_128.png")
    
class bookNode(Node):
    def __init__(self, parent, name):
        Node.__init__(self, name, 0, parent, None)
        self.__disown__()

    def icon(self):
        return (":bookmark.png")
