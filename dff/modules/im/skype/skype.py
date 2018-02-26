# DFF -- An Open Source Digital Forensics Framework
#
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

from dff.api.module.module import Module, Script
from dff.api.module.manager import ModuleProcessusManager
from dff.api.types.libtypes import Argument, typeId

from sqlite import SkypeSqlite 
from skyperecord import SkypeMessage, SkypeChat, SkypeChatMember, SkypeCall, SkypeCallMember, SkypeContactGroup, SkypeAccount, SkypeTransfer, SkypeContact

from skypecontainer import SkypeContainers

class Skype(Script):
  def __init__(self):
    Script.__init__(self, "skype")
 
  def start(self, args):
    try:
      self.root = args["root"].value()
    except IndexError:
      self.root = self.vfs.getnode("/") #NOT USED ! XXX check base path for multi-dump

    try:
       self.bruteForce = args["bruteforce"].value()
    except IndexError:
       self.bruteForce = False
        
    self.containers = {}
    self.dbbManager = ModuleProcessusManager().get("DBB")
    self.sqliteManager = ModuleProcessusManager().get("SqliteDB")

    for dbbProc, node in self.dbbManager.processus().iteritems():
      directoryList = node.absolute().split('/')
      containerName = directoryList[-2]
      try:
        self.containers[containerName].add(dbbProc.dbb)
      except KeyError:
        self.containers[containerName] = SkypeContainers(node)
        try:
          self.containers[containerName].add(dbbProc.dbb)
        except:
          pass
      except:
        pass
 
    for db, node in self.sqliteManager.processus().iteritems():
      containerName = None
      directoryList = node.absolute().split('/')
      if (directoryList[-3].lower()  == 'skype' or directoryList[-3].lower() == '.skype') and directoryList[-1].lower() == 'main.db':
        containerName = directoryList[-2]
      if self.bruteForce:
        containerName = directoryList[-1] 
      if containerName:
        skypeSqlite = SkypeSqlite(db)
        for factory in SkypeSqlite.factories:
          try: 
            self.containers[containerName].add(skypeSqlite.records(factory))
          except KeyError:
            self.containers[containerName] = SkypeContainers(node)
            try:
              self.containers[containerName].add(skypeSqlite.records(factory))
            except:
              pass
          except:
            pass

    for name, container in self.containers.iteritems():
      container.correlate()
    self.report()
 
  def report(self):
    for name, container in self.containers.iteritems():
      container.report(name)

class skype(Module):
  """ This modules parse data from DBB and SQlite database to extract skype informations"""
  def __init__(self):
    Module.__init__(self, "Skype", Skype)
    self.conf.addArgument({"name" :  "root", 
                           "description" : "Root from where the analysis will start.",
                           "input" : Argument.Required | Argument.Single | typeId.Node})
    self.conf.addArgument({"name" : "bruteforce",
                           "description" : "Will try to extract info from any sqlite base even if name and schema is incorrect.",
                           "input" : Argument.Empty})
    self.tags = "Analyse" 
    self.icon = ":/chat.png"
    self.depends = ['sqlitedb', 'dbb']
