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
from dff.ui.gui.widget.stdio import STDOut
from dff.ui.gui.widget.stdio import STDErr
from dff.api.report.manager import ReportManager

class STDOutPro(STDOut):
  def __init__(self, parent, debug):
     STDOut.__init__(self, parent, debug)
  
  def report(self):
      reportManager = ReportManager()
      page = reportManager.createPage("Information", "Standard output")
      data = str(self.toPlainText().toUtf8()).replace('\n', '<br>')    
      page.addText("Output", data)
      reportManager.addPage(page)

class STDErrPro(STDErr):
  def __init__(self, parent, debug):
    STDErr.__init__(self, parent, debug)

  def report(self):
     reportManager = ReportManager()
     page = reportManager.createPage("Information", "Error output")
     data = str(self.toPlainText().toUtf8()).replace('\n', '<br>')
     page.addText("Output", data)
     reportManager.addPage(page)
