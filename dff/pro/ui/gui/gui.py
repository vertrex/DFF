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

from dff.ui.gui.gui import GUI 

from dff.pro.ui.gui.mainwindow import MainWindowPro

class GUIPro(GUI):
  def __init__(self, arguments):
     GUI.__init__(self, arguments)
     self.translator.addTranslationPath("dff/pro/ui/gui/i18n/Dff_pro_")
     self.translator.addTranslationPath("dff/pro/modules/i18n/Dff_pro_modules_")
     self.translator.loadLanguage()

  def createMainWindow(self):
     return MainWindowPro(self, self.debug)
