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
#  Jeremy MOUNIER <jmo@digital-forensic.org>
#  Solal Jacob <sja@digital-forensic.org> 
#

from PyQt4.QtCore import Qt, SIGNAL, QEvent, QPoint, QSize, QRect, QTimer
from PyQt4.QtGui import QAbstractButton, QComboBox, QStyle, QPainter, QPushButton, QDockWidget, QApplication, QStylePainter, QIcon, QHBoxLayout, QStyleOptionToolButton, QWidget, QStyleOptionDockWidgetV2, QLayout, QCheckBox
 
class DockWidgetTitleBarButton(QAbstractButton):
    def __init__(self, titlebar):
        QAbstractButton.__init__(self, titlebar)
        self.setFocusPolicy(Qt.NoFocus)
  
    def sizeHint(self):
        self.ensurePolished()
        margin = self.style().pixelMetric(QStyle.PM_DockWidgetTitleBarButtonMargin, None, self)
        if self.icon().isNull():
            return QSize(margin, margin)
        iconSize = self.style().pixelMetric(QStyle.PM_SmallIconSize, None, self)
        pm = self.icon().pixmap(iconSize)
        return QSize(pm.width() + margin, pm.height() + margin)
  
    def enterEvent(self, event):
        if self.isEnabled():
            self.update()
        QAbstractButton.enterEvent(self, event)
  
    def leaveEvent(self, event):
        if self.isEnabled():
            self.update()
        QAbstractButton.leaveEvent(self, event)
  
    def paintEvent(self, _event):
        p = QPainter(self)
        opt = QStyleOptionToolButton()
        opt.init(self)
        opt.state |= QStyle.State_AutoRaise
        if self.isEnabled() and self.underMouse() and not self.isChecked() and not self.isDown():
            opt.state |= QStyle.State_Raised
        if self.isChecked():
            opt.state |= QStyle.State_On
        if self.isDown():
            opt.state |= QStyle.State_Sunken
        self.style().drawPrimitive(QStyle.PE_PanelButtonTool, opt, p, self)
        opt.icon = self.icon()
        opt.subControls = QStyle.SubControls()
        opt.activeSubControls = QStyle.SubControls()
        #opt.features = QStyleOptionToolButton.None
        opt.arrowType = Qt.NoArrow
        size = self.style().pixelMetric(QStyle.PM_SmallIconSize, None, self)
        opt.iconSize = QSize(size, size)
        self.style().drawComplexControl(QStyle.CC_ToolButton, opt, p, self)
  
  
class DockWidgetTitleBar(QWidget):
    def __init__(self, dockWidget, hasCheckState = False, hasReport = False):
        super(DockWidgetTitleBar, self).__init__(dockWidget)
        q = dockWidget
        self.floatButton = DockWidgetTitleBarButton(self)
        self.floatButton.setIcon(q.style().standardIcon(QStyle.SP_TitleBarNormalButton, None, q))
        self.floatButton.clicked.connect(self.toggleFloating)
        self.floatButton.setVisible(True)
        self.floatButton.setToolTip(self.tr("Undock"))
        self.closeButton = DockWidgetTitleBarButton(self)
        self.closeButton.setIcon(q.style().standardIcon(QStyle.SP_TitleBarCloseButton, None, q))
        self.closeButton.clicked.connect(dockWidget.close)
        self.closeButton.setVisible(True)
        self.closeButton.setToolTip(self.tr("Close"))

	if hasCheckState:
          self.checkStateButton = QCheckBox(self)
	  self.checkStateButton.setCheckState(2)
	  self.checkStateButton.setToolTip(self.tr("Disable this window"))
	  self.connect(self.checkStateButton, SIGNAL("stateChanged(int)"), self.toggleCheckState)
        else:
	  self.checkStateButton = False 
        dockWidget.featuresChanged.connect(self.featuresChanged)
        self.featuresChanged(0)
        self.reportIcon = QIcon(":report")
        if hasReport:
          self.reportButton = DockWidgetTitleBarButton(self)
          self.reportButton.setIcon(self.reportIcon)
          self.reportButton.clicked.connect(self.toggleReport)
          self.reportButton.setVisible(True)
          self.reportButton.setToolTip(self.tr("Add content to report"))
        else:
         self.reportButton = None
 
    def hasFeature(self, dockwidget, feature):
      return dockwidget.features() & feature == feature
 
    def minimumSizeHint(self):
        return self.sizeHint()
    
    def sizeHint(self):
        q = self.parentWidget()
        mw = q.style().pixelMetric(QStyle.PM_DockWidgetTitleMargin, None, q)
        fw = q.style().pixelMetric(QStyle.PM_DockWidgetFrameWidth, None, q)
        closeSize = QSize(0, 0)
        if self.closeButton:
            closeSize = self.closeButton.sizeHint()

        floatSize = QSize(0, 0)
        if self.floatButton:
            floatSize = self.floatButton.sizeHint()
        hideSize = self.hideSizeHint()

        buttonHeight = max(max(closeSize.height(), floatSize.height()), hideSize.height()) + 2
        buttonWidth = closeSize.width() + floatSize.width() + hideSize.width()
        titleFontMetrics = q.fontMetrics()
        fontHeight = titleFontMetrics.lineSpacing() + 2 * mw
        height = max(buttonHeight, fontHeight)
        return QSize(buttonWidth + height + 4 * mw + 2 * fw, height)
 
    def hideSizeHint(self):
      if self.reportButton and self.checkStateButton:
        return self.reportButton.sizeHint() + self.checkStateButton.sizeHint()
      elif self.reportButton:
        return self.reportButton.sizeHint()
      elif self.checkStateButton:
        return self.checkStateButton.sizeHint()
      else:
        return QSize(0, 0)

    def paintEvent(self, _event):
        p = QStylePainter(self)
        q = self.parentWidget()
        fw = q.isFloating() and q.style().pixelMetric(QStyle.PM_DockWidgetFrameWidth, None, q) or 0
        mw = q.style().pixelMetric( QStyle.PM_DockWidgetTitleMargin, None, q)
        titleOpt = QStyleOptionDockWidgetV2()
        titleOpt.initFrom(q)
        titleOpt.rect = self.titleOptionRect(fw, mw)
        titleOpt.title = q.windowTitle()
        titleOpt.closable = self.hasFeature(q, QDockWidget.DockWidgetClosable)
        titleOpt.floatable = self.hasFeature(q, QDockWidget.DockWidgetFloatable)
        p.drawControl(QStyle.CE_DockWidgetTitle, titleOpt)
 
    def titleOptionRect(self, fw, mw):
     if self.reportButton and self.checkStateButton:
       return QRect(QPoint(fw + mw + self.reportButton.size().width() + self.checkStateButton.size().width(), fw), QSize(self.geometry().width() - ( fw * 2 ) - mw - self.reportButton.size().width() - self.checkStateButton.size().width(), self.geometry().height() - ( fw * 2 )))
     elif self.reportButton:
       return QRect(QPoint(fw + mw + self.reportButton.size().width(), fw), QSize(self.geometry().width() - ( fw * 2 ) - mw - self.reportButton.size().width(), self.geometry().height() - ( fw * 2 )))
     elif self.checkStateButton:
       return  QRect(QPoint(fw + mw + self.checkStateButton.size().width(), fw), QSize(self.geometry().width() - ( fw * 2 ) - mw - self.checkStateButton.size().width(), self.geometry().height() - ( fw * 2 )))
     else:
       return QRect(QPoint(fw + mw, fw), QSize(self.geometry().width() - ( fw * 2 ) - mw, self.geometry().height() - ( fw * 2 )))

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
  
    def toggleFloating( self ):
        parent = self.parentWidget()
        parent.setFloating(not parent.isFloating())
 
    def toggleCheckState(self, state):
       parent = self.parentWidget()
       if parent:
         if state != 0:
           parent.updateCheckState(True)
         else:
	   parent.updateCheckState(False)

    def toggleReport(self):
      parent = self.parentWidget()
      if parent:
        parent.report()

    def featuresChanged(self, _features):
        parent = self.parentWidget()
        self.closeButton.setVisible(self.hasFeature(parent, QDockWidget.DockWidgetClosable))
        self.floatButton.setVisible(self.hasFeature(parent, QDockWidget.DockWidgetFloatable))

class DockWidget(QDockWidget):
  def __init__(self, mainWindow, childWidget, name):
    QDockWidget.__init__(self, mainWindow)
    self.mainwindow = mainWindow
    self.childWidget = childWidget
    self.init(childWidget)
    self.show()
    self.setObjectName(name)
    self.visibilityState = True
    self.setTitleBarWidget(self.initTitleBar())

  def hasCheckState(self):
    try:
      getattr(self.childWidget, 'updateCheckState')
      return True
    except AttributeError:
      return False

  def initTitleBar(self):
     return DockWidgetTitleBar(self, self.hasCheckState(), self.hasReport())

  def init(self, widget):
    self.name = widget.name
    self.setWidget(widget)
    self.connect(self, SIGNAL("topLevelChanged(bool)"), self.toplevel_changed)
    self.connect(self, SIGNAL("visibilityChanged(bool)"), self.setVisibility)
    
  def hasReport(self):
    try:
      getattr(self.childWidget, 'report')
      return True
    except AttributeError:
      return False

  def report(self):
     self.childWidget.report()

  def updateCheckState(self, state):
     self.childWidget.updateCheckState(state)
 
  def toplevel_changed(self, state):
    if not state:
      self.mainwindow.refreshTabifiedDockWidgets()

  def setVisibility(self, state):
     if state and hasattr(self.childWidget, "updateStatus"):
         self.childWidget.updateStatus()
     self.visibilityState = state

  def visibility(self):
     return self.visibilityState

  def visibility_changed(self, enable):
    if enable:
      self.raise_()
      self.setFocus()

  def changeEvent(self, event):
    """ Search for a language change event
    
    This event have to call retranslateUi to change interface language on
    the fly.
    """
    if event.type() == QEvent.LanguageChange:
      try:
        self.widget().retranslateUi(self)
      except AttributeError:
        pass
    else:
      QDockWidget.changeEvent(self, event)
