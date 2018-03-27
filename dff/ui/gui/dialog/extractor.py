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
#  Frederic Baguelin <fba@digital-forensic.org>
import os

from PyQt4.QtCore import QSize, SIGNAL, pyqtSignature, QEvent
from PyQt4.QtGui import QDockWidget, QWidget, QVBoxLayout, QHBoxLayout, QIcon, QComboBox, QPushButton, QSortFilterProxyModel
from PyQt4.Qt import *

from dff.ui.gui.resources.ui_extractdialog import Ui_ExtractDialog

class Extractor(QDialog, Ui_ExtractDialog):
    def __init__(self, parent):
        QDialog.__init__(self, parent)
        self.setupUi(self)
        self.translation()
        self.nodes = None
        self.actions()
        self.showArgs()
        self.path = ""
        self.hide()
        self.selectedNodes = []

    def launch(self, nodes):
        self.nodes = nodes
        self.exec_()

    def getArgs(self):
        args = {}
        args["files"] = self.nodes
        args["recursive"] = self.recurseCheck.isChecked()
        args["preserve"] = self.preserveTree.isChecked()
        args["overwrite"] = self.overwriteExisting.isChecked()
        args["syspath"] = str(unicode(self.syspathLine.text()))
        return args

    def actions(self):
        self.connect(self.buttonBox, SIGNAL("accepted()"), self.verify)
        self.connect(self.buttonBox, SIGNAL("rejected()"), self.close)


    def verify(self):
        if self.syspathLine.text() != "":
            self.close()
            self.emit(SIGNAL("filled"))
        else:
            msg = QMessageBox(self)
            msg.setText(self.pathMandatoryText)
            msg.setIcon(QMessageBox.Warning)
            msg.setStandardButtons(QMessageBox.Ok)
            msg.exec_()

    def showArgs(self):
        self.connect(self.syspathBrowse, SIGNAL("clicked()"), self.getExtractFolder)

    def getExtractFolder(self):
        dialog = QFileDialog(self, self.browseTitleText,  "/home")
        dialog.setFileMode(QFileDialog.DirectoryOnly)
        dialog.setViewMode(QFileDialog.Detail)
        ret = dialog.exec_()
        if ret:
            self.path = str(dialog.selectedFiles()[0])
            self.syspathLine.setText(self.path)
        return ret


    def removeIdentical(self, toRemove):
        res = []
        for node in self.nodes:
            if node.name() not in toRemove:
                res.append(node)
        return res

    def checkIfExist(self):
        same = []
        content = os.listdir(self.path)
        for node in self.nodes:
            if node.isFile() and node.hasChildren():
                if node.name() + ".bin" in content:
                    same.append(str(node.name() + ".bin"))
            if node.name() in content:
                same.append(str(node.name()))
        if len(same) > 0:
            msg = QMessageBox()
            msg.setWindowTitle(self.warningTitleText)
            msg.setText(self.warningExistText + '\n' + str(self.path))
            msg.setInformativeText(self.warningOWText)
            msg.setIcon(QMessageBox.Warning)
            items = "".join(s.join(["", "\n"]) for s in same)
            msg.setDetailedText(items)
            msg.setStandardButtons(QMessageBox.NoToAll | QMessageBox.YesToAll)
            msg.setDefaultButton(QMessageBox.NoToAll)
            ret = msg.exec_()
            if ret == QMessageBox.NoToAll:
                self.selectedNodes = self.removeIdentical(same)
            else:
                self.selectedNodes = self.nodes
        else:
            self.selectedNodes = self.nodes

    def translation(self):
        self.pathMandatoryText = self.tr('Extraction path is mandatory')
        self.browseTitleText = self.tr('Choose the destination folder for extraction')
        self.warningTitleText = self.tr('Overwrite attempt')
        self.warningExistText = self.tr('Some selected files or folders already exist in the destination folder')
        self.warningOWText = self.tr('Overwrite with selected ones ?')
        
    def changeEvent(self, event):
        """ Search for a language change event
        
        This event have to call retranslateUi to change interface language on
        the fly.
        """
        if event.type() == QEvent.LanguageChange:
            self.retranslateUi(self)
            self.translation()
        else:
            QDialog.changeEvent(self, event)
