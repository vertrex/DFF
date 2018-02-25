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
from PyQt4.QtGui import  QIcon, QHBoxLayout, QPushButton, QWidget, QGridLayout, QVBoxLayout, QTextBrowser, QSplitter, QSizePolicy, QDockWidget, QMessageBox
from PyQt4.QtCore import QRect, QSize, Qt, SIGNAL, QTimer, QThread, QString, QUrl, QVariant, QStringList, QFile
# from PyQt4.QtWebKit import QWebView, QWebPage, QWebFrame
from PyQt4.QtHelp import QHelpEngine

class Help(QDockWidget):
    def __init__(self, parent=None, path=None):
        QDockWidget.__init__(self, parent)
        self.name = self.tr("Help")
        self.setFloating(False)
        self.setFeatures(QDockWidget.NoDockWidgetFeatures)

        self.__mainWidget = QSplitter(Qt.Horizontal)
        self.__uname = QWidget()

        mainWidgetLayout = QVBoxLayout(self.__uname)
        mainWidgetLayout.setContentsMargins(0, 0, 0, 0)

        # create helper + search engine
        self.__helper = QHelpEngine(path, self)

        if not self.__helper.setupData() is True:
            dialog = QMessageBox()
            
            msg = QString(self.tr("An error occurred while setting help engine up :\n"))
            msg += (self.__helper.error() + "\n")
            msg += self.tr("It might mean that the format of your help file is not correct.\n")
            msg += self.tr("You can check on-line help at http://wiki.digital-forensic.org")

            dialog.setText(msg)
            dialog.setIcon(QMessageBox.Warning)
            dialog.setWindowTitle(self.tr("Error while loading help"))
            dialog.exec_()
            return

        self.__toc = self.__helper.contentWidget()
        self.__helpBrowser = HelpBrowser(self.__helper)

        # build main widget
        self.__toolbar = QWidget()
        self.__toolbarLayout = QHBoxLayout(self.__toolbar)
        home = QPushButton(QIcon(":home.png"), "")
        previous = QPushButton(QIcon(":previous.png"), "")
        next = QPushButton(QIcon(":next.png"), "")

        # building toolbar
        self.__toolbarLayout.addWidget(home)
        self.__toolbarLayout.addWidget(previous)
        self.__toolbarLayout.addWidget(next)
        self.__toolbarLayout.setContentsMargins(0, 0, 0, 0)
        mainWidgetLayout.addWidget(self.__toolbar)
        mainWidgetLayout.addWidget(self.__helpBrowser)
        self.__mainWidget.insertWidget(0, self.__toc)
        self.__mainWidget.insertWidget(1, self.__uname)
        self.__mainWidget.setStretchFactor(1, 1)
        self.setWidget(self.__mainWidget)

        #connecting `previous`, `home` and `next` buttons
        self.connect(next, SIGNAL("clicked(bool)"), self.__helpBrowser.nextPage)
        self.connect(previous, SIGNAL("clicked(bool)"), self.__helpBrowser.prevPage)
        self.connect(home, SIGNAL("clicked(bool)"), self.__helpBrowser.goHome)
        self.connect(self.__helper.contentWidget(), SIGNAL("linkActivated(const QUrl &)"),
                     self.__helpBrowser.setSource)

class   HelpBrowser(QTextBrowser):
        def __init__(self, help_engine, parent=None):
           super(HelpBrowser, self).__init__(parent)
           self.__helpEngine = help_engine
           self.setSource(QUrl("qthelp://arxsys.fr.digital_forensics_framework.1_0/doc/main_page.html"))

        #param checked is not used
        def prevPage(self, checked):
            self.backward()

        #param checked is not used
        def nextPage(self, checked):
            self.forward()

        # param checked not used
        def goHome(self, checked):
            self.setSource(QUrl("qthelp://arxsys.fr.digital_forensics_framework.1_0/doc/main_page.html"))

        def loadResource(self, type, url):
            if url.scheme() == "qthelp":
                return self.__helpEngine.fileData(url)
            return super(HelpBrowser, self).loadResource(type, url)

