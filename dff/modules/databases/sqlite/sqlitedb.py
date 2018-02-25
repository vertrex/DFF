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

__dff_module_testapsw_version__ = "1.0.0"

import apsw
from struct import unpack

from dff.api.module.module import Module
from dff.api.module.script import Script
from dff.api.types.libtypes import Variant, VList, VMap, Argument, Parameter, typeId
from dff.api.apswvfs import apswvfs

from dff.api.module.manager import ModuleProcessusManager

from dff.modules.databases.sqlite.sqlitemanager import SqliteManager 

ModuleProcessusManager().register(SqliteManager('SqliteDB'))

class SqliteDB(Script):
    def __init__(self):
        Script.__init__(self, "SqliteDB")
        self.name = "SqliteDB"

    def start(self, args):     
       self.node = args["file"].value()
       avfs = apswvfs.apswVFS()
       self.db = apsw.Connection(self.node.absolute(), vfs = avfs.vfsname)

    def execute(self, cmd):
        c = self.db.cursor()
        c.execute("PRAGMA locking_mode=EXCLUSIVE;")
        try:
          c.execute(cmd)
          return c
        except:
          return c

class sqlitedb(Module):
    """Allows to query sqlite databases in the VFS"""
    def __init__(self):
        Module.__init__(self, "sqlitedb", SqliteDB) 
        self.conf.addArgument({"input": Argument.Optional|Argument.Single|typeId.Node,
                               "name": "file",
                               "description": "sqlite database file."
                               })
	self.conf.addConstant({"name": "mime-type", 
 	                   "type": typeId.String,
 	                   "description": "managed mime type",
 	                   "values": ["database/sqlite"]})
        self.tags = "Databases"
