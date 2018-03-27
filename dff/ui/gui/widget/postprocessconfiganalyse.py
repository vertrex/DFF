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

from PyQt4.QtGui import QLabel, QVBoxLayout, QIcon, QPixmap, QTreeWidget, QTreeWidgetItem, QWidget, QHBoxLayout, QStackedWidget, QCheckBox, QGroupBox 
from PyQt4.QtCore import Qt, SIGNAL, QVariant, QString 

from dff.api.types.libtypes import Argument, Parameter, Variant, VMap, VList, typeId
from dff.api.loader.loader import loader
from dff.api.taskmanager.taskmanager import TaskManager
from dff.ui.gui.widget.generateModuleShape import moduleShapeGenerator
from dff.ui.gui.widget.layoutmanager import layoutManager 

from dff.ui.gui.widget.postprocessconfig import PostProcessModulesConfig, PostProcessModuleConfigWidget, PostProcessModulesTreeWidget, CheckBoxPostProcessItem, PostProcessOptionEmptyCheckBox, PostProcessOptionCheckBox

class PostProcessAnalyseWidget(QWidget):
  def __init__(self, parent = None):
     QWidget.__init__(self, parent)
     self.tree = PostProcessAnalyseTreeWidget()
     self.config = PostProcessAnalysesConfig()
     self.connect(self.tree, SIGNAL("moduleClicked"), self.config.update)
     self.connect(self.tree, SIGNAL("moduleStateChanged"), self.config.updateState)
     layout = QHBoxLayout()	 
     layout.addWidget(self.tree)
     layout.addWidget(self.config)
     self.setLayout(layout)

class PostProcessAnalysesConfig(PostProcessModulesConfig):
  def __init__(self, parent = None):
     PostProcessModulesConfig.__init__(self, parent)
 
  def ppModules(self):
     return TaskManager().ppAnalyses

  def configWidget(self, module, config):
     return PostProcessAnalyseConfigWidget(module, config)

class PostProcessAnalyseConfigWidget(PostProcessModuleConfigWidget):
  def __init__(self, module, ppConfig):
    PostProcessModuleConfigWidget.__init__(self, module, ppConfig)

  def ppModules(self):
     return TaskManager().ppAnalyses

  def scanBox(self):
     return None

  def optionEmptyCheckBox(self, module, argument):
     return PostProcessAnalyseOptionEmptyCheckBox(module, argument)

  def optionCheckBox(self, module, argument, optionsWidget):
     return PostProcessAnalyseOptionCheckBox(module, argument, optionsWidget)


class PostProcessAnalyseOptionEmptyCheckBox(PostProcessOptionEmptyCheckBox):
  def __init__(self, module, argument):
    PostProcessOptionEmptyCheckBox.__init__(self, module, argument)

  def ppModules(self):
     return TaskManager().ppAnalyses

class PostProcessAnalyseOptionCheckBox(PostProcessOptionCheckBox):
  def __init__(self, module, argument, optionsWidget):
     PostProcessOptionCheckBox.__init__(self, module, argument, optionsWidget)

  def ppModules(self):
     return TaskManager().ppAnalyses

class PostProcessAnalyseTreeWidget(PostProcessModulesTreeWidget):
  def __init__(self, parent = None):
     PostProcessModulesTreeWidget.__init__(self, parent)

  def checkBoxItem(self, parentWidget, parentItem = None, intType = 0):
    return CheckBoxAnalyseItem(parentWidget, parentItem, intType)

  def ppModuleMap(self):
     tagsmap = {}
     modules = self.loader.modules
     for module in modules.itervalues():
       if module.tags.lower().find("analyse") != -1:	
         try :
     	    tagsmap[module.tags].append(module)
         except KeyError:
	    tagsmap[module.tags] = [module]
     return tagsmap

  def ppModules(self):
     return TaskManager().ppAnalyses

class CheckBoxAnalyseItem(CheckBoxPostProcessItem):
  def __init__(self, parentWidget, parentItem = None, intType = 0):
    CheckBoxPostProcessItem.__init__(self, parentWidget, parentItem, intType)

  def ppModules(self):
     return TaskManager().ppAnalyses
