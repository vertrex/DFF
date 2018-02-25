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
#  Jeremy MOUNIER <jmo@gmail.com>
# 
from PyQt4.QtGui import QMenu, QIcon, QAction, QPixmap, QMessageBox, QDialog
from PyQt4.QtCore import SIGNAL, SLOT, QString, QObject, QEvent

from dff.api.loader import loader
from dff.api.vfs.vfs import vfs
from dff.api.vfs.libvfs import VFS, VLink, Node, TagsManager
from dff.api.types.libtypes import typeId, Variant, RCVariant
from dff.api.events.libevents import event, EventHandler

from dff.api.gui.dialog.tagmanager import TagManagerDialog

from dff.ui.gui.utils.utils import Utils
from dff.ui.gui.utils.action import Action

from dff.ui.gui.resources.ui_bookmarkdialog import Ui_AddBookmark
from dff.ui.gui.resources.ui_selection_actions import Ui_selectionActions


class tagMenu(QMenu):
  def __init__(self, parent, main, model=None):
    QMenu.__init__(self, main)
    self.model = model
    self.browser = parent
    self.parent = parent
    self.tagsmanager = TagsManager.get()
    self.setTitle(QString("Tags"))
    self.connect(self, SIGNAL("aboutToShow"), self.refreshTagMenu)
    self.manageAction = QAction(QString(self.tr("Manage tags")), self)
    self.connect(self.manageAction, SIGNAL("triggered(bool)"), self.openDialog)
    self.connect(self, SIGNAL("triggered(QAction*)"), self.tagNodes)
    self.refreshTagMenu()

  def refreshTagMenu(self):
    self.addAction(self.manageAction)
    self.addSeparator()
    tags = self.tagsmanager.tags()
    for tag in tags:
      self.addAction(QString.fromUtf8(tag.name()))

  def openDialog(self):
    selected = self.getSelectedNodes()
    tagDialog = TagManagerDialog(self, selected)
    tagDialog.exec_()

  def tagNodes(self, action):
    if action != self.manageAction:
      name = action.text()
      tagname = str(unicode(name).decode('utf-8', 'replace'))
      selected = self.getSelectedNodes()
      for node in selected:
        if node.isTagged(tagname):
          node.removeTag(tagname)
        else:
          node.setTag(tagname)                             

  def getSelectedNodes(self):
    if self.model != None:
      mod = self.model
    else:
      mod = self.browser.model()
    checked = mod.selection.get()
    if len(checked) > 0:
      selected = mod.selection.getNodes()
    else:
      selected = [mod.currentNode()]
    return selected


class selectionMenu(QMenu, Ui_selectionActions):
  def __init__(self, manager, model):
    QMenu.__init__(self, manager)
    self.setupUi(self)
    self.manager = manager
    self.model = model
    self.setTitle(QString(self.tr("Selection")))

    self.connect(self.actionSelect_all, SIGNAL("triggered()"), self.model.selectAll)
    self.connect(self.actionUnselect_all, SIGNAL("triggered()"), self.model.unselectAll)
    self.connect(self.actionClear_selection, SIGNAL("triggered()"), self.model.selection.clear)

    self.addAction(self.actionSelect_all)
    self.addAction(self.actionUnselect_all)
    self.addAction(self.actionClear_selection)

  def selectAll(self):
    self.model.selectAll()


class typeFilterMenu(QMenu):
  def __init__(self, main, model):
    QMenu.__init__(self, main)
    self.model = model
    self.filters = ["Image", "Video", "Text", "Audio", "Application"]
    self.connect(self, SIGNAL("triggered(QAction*)"), self.filterModel)
    self.createBaseTypeFilters()

  def createBaseTypeFilters(self):
    for filt in self.filters:
      self.addAction(QAction(QString(filt), self))

  def filterModel(self, action):
    name = action.text()
    pattern = "(( mime in[\"" + str(name.toLower()) + "\"]))"
    self.model.filter(str(name), pattern)

class MenuTags():
   def __init__(self, parent, mainWindow, selectItem = None):
       """ Init menus"""
       self.parent = parent
       self.mainWindow = mainWindow
       self.selectItem = selectItem	
       self.Load()
       self.parent.menuModule.connect(self.parent.menuModule, SIGNAL("aboutToShow()"), self.refreshQMenuModules)
 
   def Load(self):   
       self.listMenuAction = []
       setags = Utils.getSetTags()
       selist = list(setags)
       selist.sort()
       for tags in selist:
          if not tags == "builtins":
            self.listMenuAction.append(self.parent.menuModule.addMenu(MenuModules(self.parent, self.mainWindow, tags, self.selectItem)))
        
   def refreshQMenuModules(self):
        setags = Utils.getSetTags()
	for menu in self.listMenuAction:
	   self.parent.menuModule.removeAction(menu)
	self.Load()
  
 
class MenuModules(QMenu):
    def __init__(self, parent, mainWindow, tags, selectItem = None):
        QMenu.__init__(self, tags,  parent)
	self.tags = tags
        self.__mainWindow = mainWindow
        self.callbackSelected = selectItem
        self.loader = loader.loader()
        self.Load()
 
    def Load(self):
        modules = self.loader.modules
        actions = []
        for mod in modules :
	     m = modules[mod]
	     try :
	       if m.tags == self.tags:
                 actions.append(Action(self, self.__mainWindow, mod, self.tags, m.icon))
             except AttributeError, e:
		pass
        for i in range(0,  len(actions)) :
            if actions[i].hasOneArg :
                self.addAction(actions[i])
        self.addSeparator()
        for i in range(0,  len(actions)) :
            if not actions[i].hasOneArg :
                self.addAction(actions[i])
                
    def refresh(self):
        self.clear()
        self.Load()


class BookmarkManager(QObject):
  categories = []
  def __init__(self, model):
    self.model = model
    self.vfs = vfs()
    self.rootNode = self.vfs.getnode('/Bookmarks/')

  def getSelectedNodes(self):
    checked = self.model.selection.get()
    if len(checked) > 0:
      selected = self.model.selection.getNodes()
    else:
      selected = [self.model.currentNode()]
    return selected

  def launch(self):
    selected = self.getSelectedNodes()
    if len(selected) == 0:
      QMessageBox.warning(self, self.tr("Bookmark"), self.tr("You must specify at least one node."), QMessageBox.Ok)
      return
    bookdiag = bookmarkDialog(self)
    bookdiag.exec_()

  def createCategory(self, category):
    if category != "":
      newNodeBook = BookNode(self.rootNode, str(category.toUtf8()))
      newNodeBook.__disown__()
      BookmarkManager.categories.append(category)
      return True
    else:
      return False

  def removeCategory(self, root):
    categoryName = root.name()
    if categoryName in BookmarkManager.categories:
      BookmarkManager.categories.remove(categoryName)

class bookmarkDialog(QDialog, Ui_AddBookmark):
  def __init__(self, manager):
    super(QDialog, self).__init__()
    self.vfs = vfs()
    self.VFS = VFS.Get()
    self.setupUi(self)
    self.manager = manager
    self.initShape()

  def initShape(self):
    self.connect(self.newBox, SIGNAL("clicked()"), self.createCategoryBack)
    self.connect(self.existBox, SIGNAL("clicked()"), self.existingCategoryBack)
    self.connect(self, SIGNAL("accepted()"), self.acceptBookmark)
    
    for cat in BookmarkManager.categories:
      self.catcombo.addItem(cat)
    
    if len(BookmarkManager.categories) != 0:
      self.newBox.setChecked(True)
      self.existBox.setVisible(True)
    else:
      self.existBox.setVisible(False)

  def getSelectedCategory(self):
    if self.newBox.isChecked():
      return self.catname.text()
    else:
      return self.catcombo.currentText()

  def createCategoryBack(self):
    if self.existBox.isChecked():
      self.newBox.setChecked(True)
      self.existBox.setChecked(False)
    else:
      self.newBox.setChecked(True)

  def existingCategoryBack(self):
    if self.newBox.isChecked():
      self.existBox.setChecked(True)
      self.newBox.setChecked(False)
    else:
      self.existBox.setChecked(True)

  def changeEvent(self, event):
    """ Search for a language change event
    
    This event have to call retranslateUi to change interface language on
    the fly.
    """
    if event.type() == QEvent.LanguageChange:
      self.retranslateUi(self)
    else:
      QDialog.changeEvent(self, event)

  def acceptBookmark(self):
    selectedCategory = self.getSelectedCategory()
      # Check is is new or existing category
    try:
      i = BookmarkManager.categories.index(selectedCategory)
    except ValueError:
      if not self.manager.createCategory(selectedCategory):
        return
    selectedBookName = selectedCategory
    selectedBookmark = self.vfs.getnode('/Bookmarks/' + str(selectedBookName.toUtf8()))
    if selectedBookmark == None:
      print 'Error selected bookmark category was deleted '
      return 
    selected = self.manager.getSelectedNodes()

    for node in selected:
      if node:
        n = VLink(node, selectedBookmark)
        n.__disown__()
    e = event()
    e.thisown = False
    e.value = RCVariant(Variant(selectedBookmark))
    self.VFS.notify(e)

class BookNode(Node):
    def __init__(self, parent, name):
        Node.__init__(self, name, 0, parent, None)
        self.__disown__()
        self.setDir()

    def icon(self):
        return (":bookmark.png")

class TreeMenu(QMenu):
  """ Menu for the tree in the node browser
      Only one action : delete bookmark 
  """
  def __init__(self, treeView, node):
    QMenu.__init__(self, treeView)
    self.addAction(QIcon(":trash"), self.tr("Delete bookmark"), self.deleteBookmark)
    self.treeView = treeView
    self.node = node

  def deleteBookmark(self):
    vfs = VFS.Get()
    try :
      vfs.unregister(self.node)
    except Exception as e:
      print 'TreeMenu.deleteNode exceptions : ', str(e)
