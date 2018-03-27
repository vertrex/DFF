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
#  Jeremy MOUNIER <jmo@arxsys.fr>
# 
import sys
import traceback
from types import *

from PyQt4.QtGui import QAbstractItemView, QApplication, QCheckBox, QDialog, QGridLayout, QLabel, QMessageBox,QSplitter, QVBoxLayout, QWidget, QDialogButtonBox, QPushButton, QLineEdit, QCompleter, QSortFilterProxyModel, QGroupBox, QFileDialog, QSpinBox, QFormLayout, QHBoxLayout, QStackedWidget, QListWidget, QListWidgetItem, QTextEdit, QPalette, QComboBox, QIntValidator, QPixmap
from PyQt4.QtCore import Qt,  QObject, QRect, QSize, SIGNAL, QModelIndex, QString, QEvent

from dff.api.loader import *
from dff.api.vfs import *
from dff.api.taskmanager.taskmanager import *
from dff.api.types.libtypes import Argument, Parameter, Variant, VMap, VList, typeId
from dff.ui.gui.widget.layoutmanager import layoutManager 

from dff.ui.gui.utils.utils import Utils
from dff.ui.gui.resources.ui_modulegeneratorwidget import Ui_moduleGeneratorWidget

class moduleShapeGenerator(QWidget, Ui_moduleGeneratorWidget):
    def __init__(self, modulename, moduletag, nodeSelected=None):
        QWidget.__init__(self)
        Ui_moduleGeneratorWidget.__init__(self)
        self.setupUi(self)
        self.labActivate.setVisible(False)
        self.labDescription.setVisible(False)
        self.loader = loader.loader()
        self.vfs = vfs.vfs()
        self.valueArgs = {}

        self.modulename = modulename
        self.moduletag = moduletag
        self.nodeSelected = nodeSelected
        self.infoContainer.setTitle(QString(self.modulename))
        self.translation()
        self.setWidget()

    def setWidget(self):
        try:
            self.module = self.loader.modules[str(self.modulename)]
        except KeyError:
            self.module = None
        if self.module and self.module.icon:
            p = QPixmap(self.module.icon)
            p.scaled(64, 64, Qt.KeepAspectRatio)
            self.modulepix.setPixmap(p)
        else:
            p = self.modulepix.pixmap().scaled(64,64, Qt.KeepAspectRatio)
            self.modulepix.setPixmap(p)

        if not self.nodeSelected:
            self.nodeSelected = []

        self.conf = self.loader.get_conf(str(self.modulename))
        try:
            self.textEdit.setText(self.conf.description)
        except TypeError:
            self.textEdit.setText(self.conf.description())
        args = self.conf.arguments()
        self.createArgShape(args)
    
    def createArgShape(self, args):
        self.listargs.connect(self.listargs, SIGNAL("currentItemChanged(QListWidgetItem*,QListWidgetItem*)"), self.argChanged)
        for arg in args:
            self.createArgument(arg)

        firstItem = self.listargs.item(0)
        if firstItem:
          firstItem.setSelected(True)
        self.argsLayout.setStretchFactor(0, 1)
        self.argsLayout.setStretchFactor(1, 3)

    def createArgument(self, arg):
        warg = QWidget()
        vlayout = QVBoxLayout()
        vlayout.setSpacing(5)
        vlayout.setMargin(0)
        winfo = QWidget()
        infolayout = QFormLayout()
        infolayout.setMargin(0)
        requirement = arg.requirementType()
        # Generate argument's widget
        warguments = self.getWidgetFromType(arg)

        if arg.requirementType() in (Argument.Optional, Argument.Empty):
            checkBox =  checkBoxWidget(self, winfo, warguments, self.labActivate.text())
            vlayout.addWidget(checkBox, 0)

        tedit = QTextEdit(str(arg.description()))
        tedit.setReadOnly(True)
        infolayout.addRow(tedit)
        winfo.setLayout(infolayout)
        vlayout.addWidget(winfo, 1)
        if warguments:
            vlayout.addWidget(warguments, 2)        
            self.valueArgs[arg.name()] = warguments
        else:
            self.valueArgs[arg.name()] = winfo
        warg.setLayout(vlayout)
        self.stackedargs.addWidget(warg)
        argitem = QListWidgetItem(str(arg.name()), self.listargs)

    def getWidgetFromType(self, arg):
        warguments = layoutManager()
        inputype = arg.inputType()
        predefs = arg.parameters()
        ptype = arg.parametersType()
        if ptype == Parameter.Editable:
            editable = True
        else:
            editable = False
        if inputype == Argument.Single:
            if arg.type() == typeId.Node:
                warguments.addSingleNode(arg.name(), predefs, self.nodeSelected, editable)
            elif arg.type() == typeId.Path:
                warguments.addSinglePath(arg.name(), predefs, editable)
            else:
                warguments.addSingleArgument(arg.name(), predefs, arg.type(), editable)
        elif inputype == Argument.List:
            if arg.type() == typeId.Node:
                warguments.addPathList(arg.name(), predefs) #, self.nodeSelected)
            elif arg.type() == typeId.Path:
                warguments.addPathList(arg.name(), predefs)
            else:
                warguments.addListArgument(arg.name(), arg.type(), predefs, editable)
        else:
            # Argument.Empty (typically, bool arguments)
            return None
        return warguments

    def argChanged(self, curitem, previtem):
        self.stackedargs.setCurrentIndex(self.listargs.row(curitem))

    def messageBox(self, coretxt, detail):
        msg = QMessageBox(self)
        msg.setWindowTitle(self.configureError)
        msg.setText(self.configureErrorMsg)
        msg.setInformativeText(coretxt)
        msg.setIcon(QMessageBox.Critical)
        msg.setDetailedText(detail)
        msg.setStandardButtons(QMessageBox.Ok)
        ret = msg.exec_()

    def translation(self):
        self.configureError = self.tr("Configuration error")
        self.configureErrorMsg = self.tr("An error was detected in the configuration")


    def validateModule(self):
        args = {}
        try :
            for argname, lmanager in self.valueArgs.iteritems():
                if lmanager.isEnabled():
                    arg = self.conf.argumentByName(argname)
                    if arg.inputType() == Argument.Empty:
                        params = True
                    else:
                        params = lmanager.get(argname)
                    args[argname] = params
            return self.conf.generate(args)
        except RuntimeError:
            err_type, err_value, err_traceback = sys.exc_info()
            err_trace =  traceback.format_tb(err_traceback)
            err_typeval = traceback.format_exception_only(err_type, err_value)
            terr = QString()
            detailerr = QString()
            for err in err_trace:
                detailerr.append(err)
            for errw in err_typeval:
                terr.append(errw)
                detailerr.append(err)
            self.messageBox(terr, detailerr)


    def launchTask(self, genargs):
	try:	
            self.taskmanager = TaskManager()
            self.taskmanager.add(str(self.modulename), genargs, ["thread", "gui"])
        except RuntimeError:
            err_type, err_value, err_traceback = sys.exc_info()
            err_trace =  traceback.format_tb(err_traceback)
            err_typeval = traceback.format_exception_only(err_type, err_value)
            terr = QString()
            detailerr = QString()
            for err in err_trace:
                detailerr.append(err)
            for errw in err_typeval:
                terr.append(errw)
                detailerr.append(err)
            self.messageBox(terr, detailerr)
        return

    def changeEvent(self, event):
        """ Search for a language change event

        This event have to call retranslateUi to change interface language on
        the fly.
        """
        if event.type() == QEvent.LanguageChange:
            self.retranslateUi(self)
            title = self.windowTitle() + ' ' + self.modulename
            self.setWindowTitle(title)
            self.translation()
        else:
            QWidget.changeEvent(self, event)


class checkBoxWidget(QCheckBox):
    def __init__(self, parent, info, widget, label):
        QCheckBox.__init__(self)
        self.__info = info
        self.__widget = widget
        self.setText(label)
        self.stateChangedWidget(Qt.Unchecked)
        self.initCallback()
    
    def initCallback(self):
        self.connect(self, SIGNAL("stateChanged(int )"), self.stateChangedWidget)
    
    def stateChangedWidget(self,  state):
        if state == Qt.Checked :
            if self.__widget:
                self.__widget.setEnabled(1)
            self.__info.setEnabled(1)
        else :
            if self.__widget:
                self.__widget.setEnabled(0)
            self.__info.setEnabled(0)
