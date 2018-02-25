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
# 

from dff.api.module.manager import ModuleProcessusHandler

class SqliteManager(ModuleProcessusHandler):
  def __init__(self, name):
    ModuleProcessusHandler.__init__(self, name)
    self.databases = {}

  def processus(self):
     return self.databases

  def childrenOf(self, mountpoint):
    dbs = []
    for proc, node in self.databases.iteritems():
       if node.absolute().find(mountpoint.absolute()) == 0:
         dbs.append(proc)
    return dbs

  def update(self, processus):
    self.databases[processus] = processus.node

  def executeFrom(self, src, cmd):
    for base, node in self.databases.iteritems():
      if node.uid() == src.uid():
        return base.execute(cmd)

  def execute(self, basename, cmd, root):
    responses = []
    rootAbsolute = root.absolute()
    for base, node in self.databases.iteritems():
      if node.absolute().find(rootAbsolute) == 0:
        if node.name() == basename:
          responses.append(Cursor(base.node, base.execute(cmd)))
    return responses

class Cursor:
  def __init__(self, source, cursor):
    self._cursor = cursor
    self.source =  source

  def __iter__(self):
    return iter(self._cursor)

  def fetchall(self):
    return self._cursor.fetchall()
