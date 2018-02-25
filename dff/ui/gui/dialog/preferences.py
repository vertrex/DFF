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
#  Christophe Malinge <cma@digital-forensic.org>
#
import sys, os

from os import listdir, access, makedirs, R_OK, W_OK
from os.path import normpath, dirname

from PyQt4.QtGui import QDialog, QFileDialog, QMessageBox
from PyQt4.QtCore import SIGNAL, QEvent, QString, Qt

from dff.ui.gui.resources.ui_preferences import Ui_PreferencesDialog
from dff.ui.conf import Conf
from dff.ui.gui.translator import Translator

class Preferences(QDialog, Ui_PreferencesDialog):
    def __init__(self, parent = None):
      """ Drives preferences Dialog

      TODO
       - Valide index settings are properly handle by indexer
      """
      
      super(QDialog, self).__init__()
      
      # Set up the user interface from Qt Designer
      self.setupUi(self)
      self.translation()

      # Framework singleton classes
      self.conf = Conf()
      self.translator = Translator()

      # Temporary config, to be validated once submited
      self.tNoFootPrint = self.conf.noFootPrint
      self.tNoHistoryFile = self.conf.noHistoryFile
      self.tWorkPath = self.conf.workingDir
      self.tHistoryFileFullPath = self.conf.historyFileFullPath

      if self.conf.indexEnabled:
          self.tRootIndex = self.conf.root_index
          self.tIndexName = self.conf.index_name
          self.tIndexPath = self.conf.index_path
      else:
          idx = self.tabWidget.indexOf(self.indexTab)
          self.tabWidget.removeTab(idx)
      # Activate preferences from conf values
      self.noFootPrintCheckBox.setChecked(self.conf.noFootPrint)
      self.noHistoryCheckBox.setChecked(self.conf.noHistoryFile)
      self.footprintOrNo()

      self.workingDirPath.setText(self.conf.workingDir)
      self.historyLineEdit.setText(self.conf.historyFileFullPath)
      self.docAndHelpFullPath.setText(self.conf.docPath)
      
      # Populate languages comboBox with available languages, also set to current language
      self.langPopulate()

      # Signals handling
      self.connect(self.noFootPrintCheckBox, SIGNAL("stateChanged(int)"), self.noFootPrintChanged)
      self.connect(self.workingDirBrowse, SIGNAL("clicked()"), self.workDir)
      self.connect(self.historyToolButton, SIGNAL("clicked()"), self.historyDir)
      self.connect(self.noHistoryCheckBox, SIGNAL("stateChanged(int)"), self.historyStateChanged)
      self.connect(self.langComboBox, SIGNAL("currentIndexChanged (const QString&)"), self.langChanged)

      # Help configuration
      self.connect(self.docAndHelpBrowse, SIGNAL("clicked()"), self.helpDir)

      # Show or hide label helpers
      self.globalValid()
      self.helpValid()
      
      if parent:
          self.app = parent.app
      else:
          self.app = None

      # Catch submit to create directories if needed
      self.connect(self.buttonBox, SIGNAL("accepted()"), self.validate)
      self.connect(self.buttonBox, SIGNAL("rejected()"), self.clear)
      
    def validate(self):
        if not self.tNoFootPrint and not access(self.tWorkPath, R_OK):
            if QMessageBox.question(self, self.createDirTitle, self.createDirTitle + ':<br>' + self.tWorkPath + '?', QMessageBox.Yes, QMessageBox.No) == QMessageBox.No:
                return
            else:
                try:
                    makedirs(self.tWorkPath, 0700)
                except OSError, e:
                    QMessageBox.warning(self, self.createDirFail, self.createDirFail + ':<br>' + self.tWorkPath + '<br>' + e.strerror)
                    return
        self.conf.workingDir = self.tWorkPath
        if self.tNoFootPrint != self.conf.noFootPrint:
            self.conf.noFootPrint = self.tNoFootPrint
        if not self.tNoFootPrint and self.conf.indexEnabled and not access(self.tIndexPath, R_OK):
            if QMessageBox.question(self, self.createDirTitle, self.createDirTitle + ':<br>' + self.tIndexPath + '?', QMessageBox.Yes, QMessageBox.No) == QMessageBox.No:
                return
            else:
                try:
                    makedirs(self.tIndexPath, 0700)
                except OSError, e:
                    QMessageBox.warning(self, self.createDirFail, self.createDirFail + ':<br>' + self.tIndexPath + '<br>' + e.strerror)
                    return
        if self.conf.indexEnabled:
            self.conf.root_index = self.tRootIndex
            self.conf.index_name = self.tIndexName
            self.conf.index_path = self.tIndexPath
        self.conf.noHistoryFile = self.tNoHistoryFile
        if (not self.tNoHistoryFile and not self.tNoFootPrint) and self.tHistoryFileFullPath != self.conf.historyFileFullPath and access(dirname(self.tHistoryFileFullPath), W_OK):
            self.conf.historyFileFullPath = self.tHistoryFileFullPath
        elif (not self.tNoHistoryFile and not self.tNoFootPrint) and not access(dirname(self.tHistoryFileFullPath), W_OK):
            QMessageBox.warning(self, self.histWriteFail, self.histWriteFail + ':<br>' + self.tHistoryFileFullPath)
            return
        self.conf.save()
        self.accept()
        return

    def clear(self):
        self.reject()
        return

    def footprintOrNo(self):
        """
        Enable or disable inputs which made changes on the system
        """
        # Working dir related
        self.workingDirPath.setEnabled(not self.tNoFootPrint)
        self.workingDirLabel.setEnabled(not self.tNoFootPrint)
        self.workingDirBrowse.setEnabled(not self.tNoFootPrint)
        # History related
        self.noHistoryCheckBox.setEnabled(not self.tNoFootPrint)
        self.historyLineEdit.setEnabled(not self.tNoFootPrint and not self.tNoHistoryFile)
        self.historyLabel.setEnabled(not self.tNoFootPrint and not self.tNoHistoryFile)
        self.historyToolButton.setEnabled(not self.tNoFootPrint and not self.tNoHistoryFile)
        # Indexes related
        if self.conf.indexEnabled:
            self.indexTab.setEnabled(not self.tNoFootPrint)

        # Refresh label helpers
        self.globalValid()
        if self.conf.indexEnabled:
            self.indexValid()

    def workDir(self):
        """
        Handle a new working directory
        """
        f_dialog = self.fileDialog(self.conf.workingDir)
        if f_dialog.exec_():
            self.workingDirPath.setText(f_dialog.selectedFiles()[0])
            self.tWorkPath = f_dialog.selectedFiles()[0]
            if not access(self.conf.historyFileFullPath, R_OK):
                # History file does not exists and working dir has changed, update history path
                self.conf.historyFileFullPath = normpath(str(self.tWorkPath + '/history'))
                self.historyLineEdit.setText(self.conf.historyFileFullPath)
            if self.conf.indexEnabled and not access(self.tRootIndex, R_OK):
                # Index directory does not exists and working dir has changed, update index path
                self.tRootIndex = normpath(str(self.tWorkPath) + '/indexes/')
                self.tIndexPath = normpath(self.tRootIndex + '/' + self.tIndexName)
                self.root_index_line.setText(self.tRootIndex)
            self.globalValid()
            if self.conf.indexEnabled:
                self.indexValid()

    def historyDir(self):
        """
        Handle a new history file
        """
        f_dialog = self.fileDialog(self.tHistoryFileFullPath, QFileDialog.ExistingFile)
        if f_dialog.exec_():
            self.historyLineEdit.setText(f_dialog.selectedFiles()[0])
            self.tHistoryFileFullPath = f_dialog.selectedFiles()[0]
        
    def helpDir(self):
        """
        Handle a new help.qhc file.
        Be carreful ; an help.qch file must also exists at the same directory level.
        """
        f_dialog = self.fileDialog(self.conf.docPath, QFileDialog.ExistingFile)
        if f_dialog.exec_():
            self.docAndHelpFullPath.setText(f_dialog.selectedFiles()[0])
            self.conf.docPath = f_dialog.selectedFiles()[0]
            self.helpValid()

    def globalValid(self):
        """
        Set labels 'path exists' or no in global tab.
        """
        # No footprint. hide all help labels in this tab
        if self.tNoFootPrint:
            self.workDirWillCreate.setVisible(False)
            self.workDirOK.setVisible(False)
            return
            
        # Does working dir exists ?
        if access(self.tWorkPath, R_OK):
            self.workDirWillCreate.setVisible(False)
            self.workDirOK.setVisible(True)
        else:
            self.workDirWillCreate.setVisible(True)
            self.workDirOK.setVisible(False)
        
    def helpValid(self):
        """
        Set label 'path exists' or no in help tab.
        """
        if access(self.conf.docPath, R_OK):
            self.helpNOK.setVisible(False)
            self.helpOK.setVisible(True)
        else:
            self.helpNOK.setVisible(True)
            self.helpOK.setVisible(False)

    def langPopulate(self):
        if hasattr(sys, "frozen"):
           translationPath = os.path.abspath(os.path.join(os.path.dirname(sys.executable), "resources/i18n"))
        else:
		   translationPath = normpath(sys.modules['dff.ui.gui'].__path__[0] + '/i18n/')
        i = 0
        selected = 0
        for oneFile in listdir(translationPath):
            if oneFile.startswith('Dff_') and oneFile.endswith('.qm'):
                self.langComboBox.addItem(oneFile[len('Dff_'):-len('.qm')])
                if self.conf.language == oneFile[len('Dff_'):-len('.qm')]:
                    selected = i
                i += 1
        self.langComboBox.setCurrentIndex(selected)

    def noFootPrintChanged(self, state):
        self.tNoFootPrint = (state == Qt.Checked)
        self.footprintOrNo()
        
    def historyStateChanged(self, state):
        self.tNoHistoryFile = (state == Qt.Checked)
        self.historyLabel.setEnabled((state == Qt.Unchecked))
        self.historyLineEdit.setEnabled((state == Qt.Unchecked))
        self.historyToolButton.setEnabled((state == Qt.Unchecked))

    def langChanged(self, text):
        """ Change interface language

        Sets language in configuration singleton.
        Removes previous translator.
        Updates translator with new language.
        Installs translator using new language.
        """
        self.conf.setLanguage(text)
        self.translator.loadLanguage()

    def changeEvent(self, event):
        """ Search for a language change event

        This event have to call retranslateUi to change interface language on
        the fly.
        """
        if event.type() == QEvent.LanguageChange:
            self.translation()
            self.retranslateUi(self)
        else:
            QDialog.changeEvent(self, event)

    def translation(self):
        self.createDirTitle = self.tr('Create directory')
        self.createDirFail =self.tr('Directory creation failure')
        self.histWriteFail = self.tr('History file is not writable')
