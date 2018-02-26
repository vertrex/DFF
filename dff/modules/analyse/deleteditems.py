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
#  Frederic Baguelin <fba@digital-forensic.org>
# 
__dff_module__analyse_version__ = "1.0.0"

from dff.api.types.libtypes import Argument, typeId
from dff.api.module.module import Module

from dff.modules.analyse import Analyse

from dff.api.taskmanager.taskmanager import TaskManager

class DeletedItems(Analyse):
  def __init__(self):
    Analyse.__init__(self, "Deleted items")

     
  def start(self, args):
    try:
      root = args["root"].value()
    except IndexError:
      root = self.vfs.getnode('/')
    self.searches({"Deleted items": 'file == true and (deleted == true or path in ["ntfs/orphans", "ntfs/FreeSpace"])'}, root)


  def g_display(self):
    super(DeletedItems, self).g_display()
    widget = self.tabWidget.widget(0)
    if widget is not None and widget.model() is not None:
      widget.model().setSelectedAttributes(["name", "size", "type.magic"])
    
class deleteditems(Module): 
  """This analyse script search deleted nodes"""
  def __init__(self):
    Module.__init__(self, "Deleted items", DeletedItems)
    self.conf.addArgument({"name": "root",
			   "description" : "Root from where the analysis will start",
			   "input" : Argument.Required|Argument.Single|typeId.Node})
    self.tags = "Analyse"
    #self.icon = ":virus"
    self.depends = ["partition", "fatfs", "ntfs"]
    self.flags = ["gui"]
