# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2011 ArxSys
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

from PyQt4.QtCore import QSize, QRect, QPoint
from PyQt4.QtGui import QIcon, QStyle, QStyleOptionDockWidgetV2, QDockWidget

from dff.api.gui.widget.dockwidget import DockWidget, DockWidgetTitleBar, DockWidgetTitleBarButton

class DockWidgetTitleBarPro(DockWidgetTitleBar):
  def __init__(self, dockWidget, hasCheckState = False, hasReport = False):
     DockWidgetTitleBar.__init__(self, dockWidget, hasCheckState)
     self.reportIcon = QIcon(":report")
     if hasReport:
       self.reportButton = DockWidgetTitleBarButton(self)
       self.reportButton.setIcon(self.reportIcon)
       self.reportButton.clicked.connect(self.toggleReport)
       self.reportButton.setVisible(True)
       self.reportButton.setToolTip(self.tr("Add content to report"))
     else:
       self.reportButton = None

  def hideSizeHint(self):
    if self.reportButton and self.checkStateButton:
       return self.reportButton.sizeHint() + self.checkStateButton.sizeHint()
    elif self.reportButton:
       return self.reportButton.sizeHint()
    else:
        return DockWidgetTitleBar.hideSizeHint(self)

  def titleOptionRect(self, fw, mw):
     if self.reportButton and self.checkStateButton:
       return QRect(QPoint(fw + mw + self.reportButton.size().width() + self.checkStateButton.size().width(), fw), QSize(self.geometry().width() - ( fw * 2 ) - mw - self.reportButton.size().width() - self.checkStateButton.size().width(), self.geometry().height() - ( fw * 2 )))
     elif self.reportButton:
       return QRect(QPoint(fw + mw + self.reportButton.size().width(), fw), QSize(self.geometry().width() - ( fw * 2 ) - mw - self.reportButton.size().width(), self.geometry().height() - ( fw * 2 )))
     else:
        return DockWidgetTitleBar.titleOptionRect(self, fw, mw)

  def resizeEvent(self, _event):
        q = self.parentWidget()
        fw = q.isFloating() and q.style().pixelMetric(QStyle.PM_DockWidgetFrameWidth, None, q) or 0
        opt = QStyleOptionDockWidgetV2()
        opt.initFrom(q)
        opt.rect = QRect(QPoint(fw, fw), QSize(self.geometry().width() - (fw * 2), self.geometry().height() - (fw * 2)))
        opt.title = q.windowTitle()
        opt.closable = self.hasFeature(q, QDockWidget.DockWidgetClosable)
        opt.floatable = self.hasFeature(q, QDockWidget.DockWidgetFloatable)
        floatRect = q.style().subElementRect(QStyle.SE_DockWidgetFloatButton, opt, q)
        if not floatRect.isNull():
            self.floatButton.setGeometry(floatRect)
        closeRect = q.style().subElementRect(QStyle.SE_DockWidgetCloseButton, opt, q)
        if not closeRect.isNull():
            self.closeButton.setGeometry(closeRect)
        top = fw
        if not floatRect.isNull():
            top = floatRect.y()
        elif not closeRect.isNull():
            top = closeRect.y()
        if self.checkStateButton:
          size = self.checkStateButton.size()
          if not closeRect.isNull():
            size = self.closeButton.size()
          elif not floatRect.isNull():
            size = self.floatButton.size()
          checkStateRect = QRect(QPoint(fw, top), size)
          self.checkStateButton.setGeometry(checkStateRect)
        if self.reportButton:
          size = self.reportButton.size()
          if not closeRect.isNull():
           size = self.closeButton.size()
          elif not floatRect.isNull():
           size = self.floatButton.size()
          reportRect = QRect(QPoint(fw, top), size)
          self.reportButton.setGeometry(reportRect)
 
  def toggleReport(self):
     parent = self.parentWidget()
     if parent:
       parent.report()

class DockWidgetPro(DockWidget):
  def __init__(self, mainWindow, widget, name):
    DockWidget.__init__(self, mainWindow, widget, name)

  def hasReport(self):
    try:
      getattr(self.childWidget, 'report')
      return True
    except AttributeError:
      return False

  def report(self):
     self.childWidget.report()

  def initTitleBar(self):
     return DockWidgetTitleBarPro(self, self.hasCheckState(), self.hasReport())
