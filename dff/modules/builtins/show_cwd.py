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
#  Solal Jacob <sja@digital-forensic.org>
# 

__dff_module_show_cwd_version__ = "1.0.0"

from dff.api.vfs import *
from dff.api.module.module import *
from dff.api.module import *

class SHOW_CWD(Script):
  def __init__(self):
    Script.__init__(self, "show_cwd")
    self.vfs = vfs.vfs()

  def start(self, args):
    cwd = self.vfs.getcwd()
    print cwd.absolute()

class show_cwd(Module):
  """Display current working directory"""
  def __init__(self):
    Module.__init__(self, "show_cwd", SHOW_CWD)
    self.tags = "builtins"
