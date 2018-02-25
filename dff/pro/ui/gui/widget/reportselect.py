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
from PyQt4.QtCore import SIGNAL
from PyQt4.QtGui import QVBoxLayout, QPushButton, QIcon,QDialog, QLabel, QLineEdit, QHBoxLayout, QInputDialog, QGroupBox, QComboBox

from dff.pro.api.report.manager import ReportManager

class ReportSelectCategory(QGroupBox):
  def __init__(self, parent = None):
     QGroupBox.__init__(self, "Choose or create a new category", parent) 
     self.combo = QComboBox()
     self.connect(self.combo, SIGNAL("activated(QString)"), self.categoryChanged)
     name = QLabel("Category name :")
     layout = QHBoxLayout()
     layout.addWidget(name)
     layout.addWidget(self.combo)
     self.setLayout(layout)

  def categoryChanged(self, categoryName):
     if categoryName == "New category ...":
       categoryName, ok = QInputDialog.getText(self, self.tr("Create a new category"), self.tr("Category name : "),  QLineEdit.Normal, "")
       if ok and categoryName != "":
         categoryName = str(categoryName.toUtf8())
         category = ReportManager().category(categoryName)
         self.fill()
         self.emit(SIGNAL("categoryChanged"), category)
     else:
        category = ReportManager().category(categoryName)
        self.emit(SIGNAL("categoryChanged"), category)

  def fill(self):
     self.combo.clear()
     for category in ReportManager().categories():
        self.combo.addItem(category.name())
     if (self.combo.count()):
       self.combo.insertSeparator(self.combo.count())
     self.combo.addItem("New category ...")
     if self.combo.count() == 1:
       self.categoryChanged("New category ...")

class ReportSelectPage(QGroupBox):
  def __init__(self, parent = None):
     QGroupBox.__init__(self, "Choose or create a new page", parent)
     self.combo = QComboBox()
     name = QLabel("Page name :")
     layout = QHBoxLayout()
     layout.addWidget(name)
     layout.addWidget(self.combo)
     self.setLayout(layout) 
     self.currentCategory = None
     self.currentPage = None
     self.setDisabled(True)
     self.connect(self.combo, SIGNAL("activated(QString)"), self.pageChanged)

  def pageChanged(self, pageTitle):
     if pageTitle == "New page ...":
       pageTitle, ok = QInputDialog.getText(self, self.tr("Create a new page"), self.tr("Page title : "),  QLineEdit.Normal, "")
       if ok and pageTitle != "":
         pageTitle = str(pageTitle.toUtf8())
         page = ReportManager().createPage(self.currentCategory.name(), pageTitle)
         ReportManager().addPage(page)
         self.fill(self.currentCategory)
       else:
         return
     self.currentPage = pageTitle

  def page(self):
     if self.currentPage:
       return self.currentCategory[self.currentPage]

  def fill(self, category):
     self.setDisabled(False)
     self.combo.clear()
     self.currentCategory = category
     for page in category:
        self.combo.addItem(page.title())
     if (self.combo.count()):
       self.combo.insertSeparator(self.combo.count())
     self.combo.addItem("New page ...")
     if self.combo.count() == 1:
       self.pageChanged("New page ...")   

class ReportSelectDialog(QDialog):
  def __init__(self, parent = None):
     QDialog.__init__(self, parent)
     self.reportManager = ReportManager()
     layout = QVBoxLayout()
     labelLayout = QHBoxLayout()
     labelTitle = QLabel("Add notes to the report.")
     labelIcon = QLabel(self)
     labelIcon.setPixmap(QIcon(":report").pixmap(64))
     labelIcon.setBuddy(labelTitle)
     labelLayout.addWidget(labelIcon)
     labelLayout.addWidget(labelTitle)
     layout.addLayout(labelLayout)

     self.reportSelectCategory = ReportSelectCategory(self) 
     layout.addWidget(self.reportSelectCategory)
     self.reportSelectPage = ReportSelectPage(self)
     layout.addWidget(self.reportSelectPage)
     self.connect(self.reportSelectCategory, SIGNAL("categoryChanged"), self.reportSelectPage.fill)

     buttonLayout = QHBoxLayout()
     buttonOk = QPushButton("O&k")
     self.connect(buttonOk, SIGNAL("clicked()"), self.accept)
     buttonCancel = QPushButton("C&ancel") 
     self.connect(buttonCancel, SIGNAL("clicked()"), self.reject)
     buttonLayout.addWidget(buttonOk)
     buttonLayout.addWidget(buttonCancel)
     layout.addLayout(buttonLayout)

     self.setLayout(layout)
  
  def exec_(self):
     self.reportSelectCategory.fill()
     return QDialog.exec_(self)   

  def selection(self):
    return self.reportSelectPage.page()
