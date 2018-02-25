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
#  Solal Jacob <sja@arxsys.fr>
#

from dff.api.gui.widget.nodewidget import NodeWidget

from dff.pro.ui.gui.utils.menumanager import MenuManagerPro

class NodeWidgetPro(NodeWidget):
  def __init__(self, selectionManager, tabmode=False, filtermode=False):
     NodeWidget.__init__(self, selectionManager, tabmode, filtermode)

  def menuManager(self, selectionManager):
     self.menumanager = MenuManagerPro(selectionManager, self.model) 
