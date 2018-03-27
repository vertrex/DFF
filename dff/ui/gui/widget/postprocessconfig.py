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
#

from PyQt4.QtGui import QLabel, QVBoxLayout, QIcon, QPixmap, QTreeWidget, QTreeWidgetItem, QWidget, QHBoxLayout, QStackedWidget, QCheckBox, QGroupBox, QScrollArea, QSplitter, QSizePolicy, QLayout, QLineEdit
from PyQt4.QtCore import Qt, SIGNAL, QVariant, QString

from dff.api.types.libtypes import Argument, Parameter, Variant, VMap, VList, typeId
from dff.api.loader.loader import loader
from dff.api.taskmanager.taskmanager import TaskManager
from dff.ui.gui.widget.generateModuleShape import moduleShapeGenerator
from dff.ui.gui.widget.layoutmanager import layoutManager 
 
class PostProcessConfigWidget(QWidget):
  def __init__(self, parent = None):
     QWidget.__init__(self, parent)
     self.tree = PostProcessModulesTreeWidget()
     self.config = PostProcessModulesConfig()   
     self.connect(self.tree, SIGNAL("moduleClicked"), self.config.update)
     self.connect(self.tree, SIGNAL("moduleStateChanged"), self.config.updateState)
     sizePolicy = QSizePolicy(QSizePolicy.Minimum, QSizePolicy.MinimumExpanding)
     sizePolicy.setVerticalStretch(1)
     self.setSizePolicy(sizePolicy)
     layout = QHBoxLayout()
     layout.setMargin(0)
     self.__splitter = QSplitter(Qt.Horizontal, self)
     layout.addWidget(self.__splitter)
     self.__splitter.addWidget(self.tree)
     self.__splitter.addWidget(self.config)
     self.__splitter.setStretchFactor(0, 0)
     self.__splitter.setStretchFactor(1, 80)
     self.setLayout(layout)

  def fillFromAnalyse(self):
     TaskManager().addAnalyseDependencies()
     self.tree.update()

class PostProcessModulesConfig(QStackedWidget):
  def __init__(self, parent = None):
     QStackedWidget.__init__(self, parent) 
     sizePolicy = QSizePolicy(QSizePolicy.MinimumExpanding, QSizePolicy.MinimumExpanding)
     sizePolicy.setVerticalStretch(1)
     self.setSizePolicy(sizePolicy)
     self.currentWidget = None    
     self.loader = loader() 
     self.moduleName = None
    
  def ppModules(self):
     return TaskManager().ppModules

  def update(self, moduleName = None):
       if self.currentWidget:	
         self.removeWidget(self.currentWidget)
         self.currentWidget.close()
         del self.currentWidget 
         self.currentWidget = None
       if moduleName:	
         self.moduleName = moduleName	
         module = self.loader.modules[self.moduleName]
         self.setCurrentWidget()
         self.addWidget(self.currentWidget)

  def configWidget(self, module, config):
     return PostProcessModuleConfigWidget(module, config)

  def setCurrentWidget(self):
     config = self.ppModules().config(self.moduleName)
     configCurrentWidget = self.configWidget(self.loader.modules[self.moduleName], config)
     scroll = QScrollArea(self) 
     scroll.setWidgetResizable(True)
     scroll.setWidget(configCurrentWidget)
     configCurrentWidget.setAutoFillBackground(False)
     self.currentWidget = scroll

  def updateState(self, state, moduleName):
     if self.moduleName == moduleName:
       self.update()
       if self.currentWidget:
         self.currentWidget.setEnabled(state)

class PostProcessModuleConfigWidget(QWidget):
  def __init__(self, module, ppConfig):
     QWidget.__init__(self)
     sizePolicy = QSizePolicy(QSizePolicy.MinimumExpanding, QSizePolicy.MinimumExpanding)
     sizePolicy.setVerticalStretch(1)
     self.setSizePolicy(sizePolicy)
     self.module = module
     self.ppConfig = ppConfig
     layout = QVBoxLayout()
     self.descriptionLayout = self.descriptionBox()
     layout.addWidget(self.descriptionLayout)
     self.optionsLayout = self.optionsBox()
     layout.addWidget(self.optionsLayout)
     scanBoxLayout = self.scanBox() 
     if scanBoxLayout :
       layout.addWidget(scanBoxLayout)	
     self.show()
     self.setLayout(layout)

  def ppModules(self):
     return TaskManager().ppModules

  def show(self):
     if self.ppModules().isSet(self.module.name):
       self.setEnabled(1)
     else:
       self.setEnabled(0)	

  def scanBox(self): #Options et options configuration donc changer :) c pas tres clair si non
     groupBox = QGroupBox(self.tr("Options"))
     groupBoxLayout = QVBoxLayout()

     flagBox = PostProcessFlagsEmptyCheckBox(self.module, 'noscan')
     groupBoxLayout.addWidget(flagBox)

     try :
       filterBox = PostProcessFilterEdit(self.module)
       groupBoxLayout.addWidget(filterBox)
     except: #Will except if module have more than one node argument or no node argument (shouldn't happen here as postprocessing is only done on one node module
       pass
 
     groupBox.setLayout(groupBoxLayout)
     return groupBox 

  def descriptionBox(self):
     groupBox = QGroupBox(self.tr("Description"))
     label = QLabel(QString(self.module.conf.description))
     label.setWordWrap(True)
     groupBoxLayout = QVBoxLayout()
     groupBoxLayout.addWidget(label)
     groupBox.setLayout(groupBoxLayout)
     return groupBox

  def optionEmptyCheckBox(self, module, argument): 
     return PostProcessOptionEmptyCheckBox(module, argument)

  def optionCheckBox(self, module, argument, optionsWidget):
     return PostProcessOptionCheckBox(module, argument, optionsWidget)

  def optionsBox(self):
     groupBox = QGroupBox(self.tr("Module configuration")) 
     groupBoxLayout = QVBoxLayout()
     arguments = self.module.conf.arguments()
     ppArgumentCounter = 0
     for argument in arguments:
	editable = True if argument.parametersType() == Parameter.Editable else False
        if argument.type() != typeId.Node:
 	   argumentWidget = layoutManager() 
	   if argument.inputType() == Argument.Single:
    	     moduleArgument = self.ppModules().argument(self.module.name, argument.name())
	     if moduleArgument:
	       moduleArgument = [Variant(moduleArgument)]
	     else:
	       moduleArgument = argument.parameters()
	     if argument.type() == typeId.Path:
	       argumentWidget.addSinglePath(argument.name(), argument.parameters(), editable, moduleArgument)
	     else:
	       argumentWidget.addSingleArgument(argument.name(), moduleArgument, argument.type(), editable)
	     checkBox = self.optionCheckBox(self.module, argument, argumentWidget)	
             groupBoxLayout.addWidget(checkBox)
	     groupBoxLayout.addWidget(argumentWidget)
	     ppArgumentCounter += 1

	   elif argument.inputType() == Argument.List:
    	     moduleArgument = self.ppModules().argument(self.module.name, argument.name())
	     if argument.type() == typeId.Path:
	       if moduleArgument == None:
		 moduleArgument = []
	       argumentWidget.addPathList(argument.name(), moduleArgument)
	     else:
	       argumentWidget.addListArgument(argument.name(), argument.type(), argument.parameters(), editable, moduleArgument)
	     checkBox = self.optionCheckBox(self.module, argument, argumentWidget)
             groupBoxLayout.addWidget(checkBox)
	     groupBoxLayout.addWidget(argumentWidget)
 	     ppArgumentCounter += 1

           if argument.requirementType() == Argument.Empty:
	     groupBoxLayout.addWidget(self.optionEmptyCheckBox(self.module, argument))
	     ppArgumentCounter += 1

     if ppArgumentCounter == 0:
        label = QLabel(self.tr("No configuration option available for this module."))
        label.setWordWrap(True)
	groupBoxLayout.addWidget(label)
     groupBox.setLayout(groupBoxLayout)
     return groupBox

class PostProcessFlagsEmptyCheckBox(QCheckBox):
  def __init__(self, module, flag):
    QCheckBox.__init__(self)
    self.flag = flag
    self.module = module
    self.setText("Scan children")
    if flag in module.flags:
       self.setCheckState(Qt.Unchecked)
    else:
       self.setCheckState(Qt.Checked)    
    self.connect(self, SIGNAL("stateChanged(int)"), self.flagStateChanged)

  def ppModules(self):
     return TaskManager().ppModules

  def flagStateChanged(self, state):
    if state == Qt.Checked:
      self.ppModules().removeFlag(self.module.name, 'noscan')
    else:
      self.ppModules().addFlag(self.module.name, 'noscan')

class PostProcessFilterEdit(QWidget):
  def __init__(self, module):
     QWidget.__init__(self)
     layout = QVBoxLayout()
     self.module = module
     nodeArgument = self.findNodeArgument(module)
     informationText = "Filter " + nodeArgument.name() + " argument with query :"
     self.label = QLabel(informationText)
     layout.addWidget(self.label)
     filterText = self.findFilterText(module)
     self.lineEdit = QLineEdit(filterText)
     self.connect(self.lineEdit, SIGNAL("editingFinished()"), self.filterEditChanged)
     layout.addWidget(self.lineEdit)
     self.setLayout(layout)

  def findNodeArgument(self, module):
    nodeArguments = module.conf.argumentsByType(typeId.Node)
    if len(nodeArguments) == 1:
      return nodeArguments[0]

  def findFilterText(self, module):
    try:
       filterText = module.scanFilter
    except AttributeError:
       filterText = ""
    return filterText

  def ppModules(self):
     return TaskManager().ppModules

  def filterEditChanged(self):
    self.module.scanFilter = self.lineEdit.text()

class PostProcessOptionEmptyCheckBox(QCheckBox):
  def __init__(self, module, argument):
    QCheckBox.__init__(self)
    self.argument = argument
    self.module = module
    self.setText(self.argument.description())
    if self.ppModules().argument(self.module.name, self.argument.name()):
      self.setCheckState(Qt.Checked)
    else:
      self.setCheckState(Qt.Unchecked)
    self.connect(self, SIGNAL("stateChanged(int)"), self.optionsStateChanged)

  def ppModules(self):
     return TaskManager().ppModules

  def optionsStateChanged(self, state):
    if state == Qt.Checked:
      self.ppModules().addArgument(self.module.name, self.argument.name(), True)
    else:
      self.ppModules().removeArgument(self.module.name, self.argument.name())

class PostProcessOptionCheckBox(QCheckBox): 
  def __init__(self, module, argument, optionsWidget):
    QCheckBox.__init__(self)
    self.module = module
    self.argument = argument 
    self.optionsWidget = optionsWidget
    self.setText(argument.description() + ": ")
    argument = self.ppModules().argument(self.module.name, self.argument.name())
    if argument:
      self.setCheckState(Qt.Checked)
      self.optionsStateChanged(Qt.Checked)
    else :
      self.setCheckState(Qt.Unchecked)
      self.optionsStateChanged(Qt.Unchecked)
    self.connect(self, SIGNAL("stateChanged(int)"), self.optionsStateChanged)
    self.connect(self.optionsWidget, SIGNAL("argumentChanged()"), self.updateArgument)

  def ppModules(self):
     return TaskManager().ppModules

  def updateArgument(self):
     value = self.optionsWidget.get(self.argument.name())
     if value:
       self.ppModules().addArgument(self.module.name, self.argument.name(), value)
     else:
       self.ppModules().removeArgument(self.module.name, self.argument.name())

  def optionsStateChanged(self, state):
    if state == Qt.Checked:
      self.optionsWidget.setEnabled(1)
      value = self.optionsWidget.get(self.argument.name())
      if value:
        self.ppModules().addArgument(self.module.name, self.argument.name(), value)	
    else:
      self.optionsWidget.setEnabled(0) 
      self.ppModules().removeArgument(self.module.name, self.argument.name())


class PostProcessModulesTreeWidget(QTreeWidget):
  def __init__(self, parent = None):
     QTreeWidget.__init__(self, parent)
     sizePolicy = QSizePolicy(QSizePolicy.Preferred, QSizePolicy.MinimumExpanding)
     self.setSizePolicy(sizePolicy)
     self.loader = loader()
     self.taskmanager = TaskManager()
     moduleMap = self.ppModuleMap()
     self.header().hide()
     self.populate(moduleMap)
     self.connect(self, SIGNAL("itemClicked(QTreeWidgetItem*, int)"), self.moduleClicked)

  def ppModules(self):
     return self.taskmanager.ppModules

  def moduleIsTyped(self, mod):
     const = mod.conf.constants()
     for c in const:
	  if c.name() in ["mime-type", "extension-type"]:
	    return True
     return False 

  def moduleNeedOneNode(self, mod):
    argsnode = mod.conf.argumentsByType(typeId.Node)
    if len(argsnode) == 1:	 
      return True 
    else:
      return False

  def moduleIsPostProcessable(self, module):
     if ("generic" in module.flags or self.moduleIsTyped(module)) and  self.moduleNeedOneNode(module):
	return True
     else:
	return False

  def ppModuleMap(self):
     tagsmap = {}
     modules = self.loader.modules
     for module in modules.itervalues():
       if self.moduleIsPostProcessable(module) and module.tags not in ["builtins", "Viewers", "Connector", "Analyse"]:	
         try :
     	    tagsmap[module.tags].append(module)
         except KeyError:
	    tagsmap[module.tags] = [module]
     return tagsmap

  def checkedModules(self):
     modules = []
     for tagsItemIndex in range(0, self.topLevelItemCount()):
	tagsItem = self.topLevelItem(tagsItemIndex)	
	for childIndex in xrange(0, tagsItem.childCount()):
	   child = tagsItem.child(childIndex)
	   if child.checkState(0):
  	     modules.append(str(child.text(0)))
     return modules	

  def checkBoxItem(self, parentWidget, parentItem = None, intType = 0):
      return CheckBoxPostProcessItem(parentWidget, parentItem, intType)

  def update(self):
     self.clear()
     self.populate(self.ppModuleMap()) 

  def populate(self, tagsmap):
     for tags in tagsmap:
       tagsItem = self.checkBoxItem(self)
       self.expandItem(tagsItem)
       tagsItem.setText(0, tags)
       tagsItem.setFlags(Qt.ItemIsUserCheckable|Qt.ItemIsSelectable|Qt.ItemIsEnabled)		
       self.addTopLevelItem(tagsItem)	
       modulesArePostProcess = 1 
       for module in tagsmap[tags]:
	   moduleItem = self.checkBoxItem(self, tagsItem)
	   moduleItem.setText(0, module.name)
	   moduleItem.setFlags(Qt.ItemIsUserCheckable|Qt.ItemIsSelectable|Qt.ItemIsEnabled)
	   if self.ppModules().isSet(module.name):
	     moduleItem.setData(0, Qt.CheckStateRole, QVariant(Qt.Checked))
           else:
	     moduleItem.setData(0, Qt.CheckStateRole, QVariant(Qt.Unchecked))
       	     modulesArePostProcess = 0
	   if module.icon:
	     icon = QIcon(QPixmap(module.icon))
	   else:
	     icon = QIcon(QPixmap(":module2.png"))
	   moduleItem.setIcon(0, icon) 

       if modulesArePostProcess: 
         tagsItem.setData(0, Qt.CheckStateRole, QVariant(Qt.Checked))
       else:
	 QTreeWidgetItem.setData(tagsItem, 0, Qt.CheckStateRole, QVariant(Qt.Unchecked))
     
  def moduleClicked(self, item, column):
     if item.childCount() == 0:
       self.emit(SIGNAL("moduleClicked"), str(item.text(0)))
     else:
	self.emit(SIGNAL("moduleClicked"))


class CheckBoxPostProcessItem(QTreeWidgetItem):
  def __init__(self, parentWidget, parentItem = None, intType = 0):
    self.loader = loader() 
    if parentItem :
      QTreeWidgetItem.__init__(self, parentItem)
    else:
      QTreeWidgetItem.__init__(self, parentWidget)
    self.parentWidget = parentWidget

  def ppModules(self):
     return TaskManager().ppModules

  def setData(self, column, role, value):
    QTreeWidgetItem.setData(self, column, role, value)
    if role == Qt.CheckStateRole:
      if self.childCount() != 0:
	for childIndex in xrange(0, self.childCount()):
	  child = self.child(childIndex)
	  child.setData(0, Qt.CheckStateRole, value)
	  self.setPostProcessState(str(child.text(0)), value)
      else:
          self.setPostProcessState(str(self.text(0)), value)

  def setPostProcessState(self, moduleName, state):   
    state = state.toInt()[0]
    self.parentWidget.emit(SIGNAL("moduleStateChanged"), state, moduleName)
    if state:
       flags = self.loader.modules[moduleName].flags
       self.ppModules().add(moduleName, exec_flags = flags)
    else:
       self.ppModules().remove(moduleName)
