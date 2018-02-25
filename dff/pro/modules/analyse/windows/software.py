from dff.api.types.libtypes import Argument, typeId, MS64DateTime 

from dff.api.module.module import Module, Script
from dff.api.module.manager import ModuleProcessusManager

from dff.pro.api.report.manager import ReportManager
from dff.pro.api.report.fragments import TableFragment

from dff.pro.modules.analyse.analyse import Translator 

class TranslateSoftware(Translator):
  def translationMap(self):
     return {
              "Operating system" : unicode(self.tr("Operating system")),
              "DisplayName" : unicode(self.tr("Software")),
              "InstallDate" : unicode(self.tr("Install date")),
              "KeyDate" : unicode(self.tr("Install date")),
              "DisplayVersion": unicode(self.tr("Version")),
              "Publisher" : unicode(self.tr("publisher")),
              "Language" : unicode(self.tr("Language")),
              "NetworkSoftware" : unicode(self.tr("Software network connection")),
              "False" : unicode(self.tr("False")),
              "True" : unicode(self.tr("True")),
              "RunSoftware" : unicode(self.tr("Software executed at start")),
              "Name" : unicode(self.tr("Name")),
              "ExecutedCommand" : unicode(self.tr("Executed command")),
              "Once" : unicode(self.tr("Once")),
              "Software" : unicode(self.tr("Software")),
            }

class Uninstall(object):
  def __init__(self, key):
     self.__values = { 'KeyName' : key.name, 'KeyDate' : str(MS64DateTime(key.mtime)) }
     values = key.values()
     if values:
       for value in values:
          self.__values[value.name] = value.data()

  def value(self, name):
    try: 
      return self.__values[name]
    except KeyError:
      if name == 'DisplayName':
        return self.__values['KeyName'] 
      return None

class Uninstalls(object):
  def __init__(self):
     self.__uninstalls = {}

  def add(self, node, uninstall):
    try:
      self.__uninstalls[long(node.this)].append(uninstall)
    except KeyError:
      self.__uninstalls[long(node.this)] = [uninstall]

  def find(self, guid):
     for node, uninstalls in self.__uninstalls.iteritems():
        for uninstall in uninstalls:
           if uninstall.value('KeyName') == guid:
             return uninstall.value('DisplayName')
     return None

  def report(self, page):
     trSoftware = TranslateSoftware()
     header = ['DisplayName', 'KeyDate', 'DisplayVersion', 'Publisher'] 
     table = set()
     for node, uninstalls in self.__uninstalls.iteritems():
       for uninstall in uninstalls:
          line = () 
          for prop in header:
             line += (uninstall.value(prop),)
          if line != (None, None, None, None):
            table.add(line)
     table = list(table)
     if len(table):
       page.addTable('Uninstall', trSoftware.translate(header), list(table))


class MSI(object):
  def __init__(self, values):
    self.__values = {}
    for value in values:
       self.__values[value.name] = value.data()

  def value(self, name):
    try:
      return self.__values[name]
    except KeyError:
      return None

class MSIs(object):
  def __init__(self):
     self.__MSIs = {}

  def add(self, node, msi):
    try:
      self.__MSIs[long(node.this)].append(msi)
    except KeyError:
      self.__MSIs[long(node.this)] = [msi]

  def translate(self, header):
     tr = []
     for prop in header:
       try:
         tr.append(MSI.properties[prop])
       except KeyError:
         tr.append(prop)
     return tr

  def report(self, page):
     trSoftware = TranslateSoftware()
     header = ['DisplayName', 'InstallDate', 'DisplayVersion', 'Publisher'] 
     table = set()
     for node, MSIs in self.__MSIs.iteritems():
       for MSI in MSIs:
          line = () 
          for prop in header:
             line += (MSI.value(prop),)
          if line != (None, None, None, None):
            table.add(line)
     table = list(table)
     if len(table): 
       page.addTable('MSI', trSoftware.translate(header), list(table))

class ARPCache(object):
  def __init__(self, name):
     self.__softwareName = name

  def name(self):
     return self.__softwareName

class ARPCaches(object):
  def __init__(self):
     self.__arpcaches = {}

  def add(self, node, arpcache):
     try:
       self.__arpcaches[long(node.this)].append(arpcache)
     except KeyError:
       self.__arpcaches[long(node.this)] = [arpcache]

  def report(self, page):
     trSoftware = TranslateSoftware() 
     header = [trSoftware.translate('Software')] 
     table = []
     for node, arpcaches in self.__arpcaches.iteritems():
       for arpcache in arpcaches:
          table.append((arpcache.name(),))
     if len(table):
       page.addTable(trSoftware.translate('NetworkSoftware'), [trSoftware.translate('Software')], table)

class AutoRun(object):
  def __init__(self, value, once):
     self.__name = value.name
     self.__path = value.data()
     self.__once = once

  def name(self):
     return self.__name

  def path(self):
     return self.__path
  
  def once(self):
     trSoftware = TranslateSoftware()
     if self.__once:
       return trSoftware.translate('False')
     return trSoftware.translate('True')

class AutoRuns(object):
  def __init__(self):
     self.__autoruns = {}
        
  def add(self, node, run):
    try:
      self.__autoruns[long(node.this)].append(run)
    except KeyError:
      self.__autoruns[long(node.this)] = [run]

  def report(self, page):
    trSoftware = TranslateSoftware()
    table = set() 
    for node, autoruns in self.__autoruns.iteritems():
      for autorun in autoruns:
        table.add((autorun.name(), autorun.path(), autorun.once()))
    if len(table):
        
      page.addTable(trSoftware.translate("RunSoftware"), trSoftware.translate(['Name', 'ExecutedCommand', 'Once']), list(table))

class Software(Script):
  def __init__(self):
      Script.__init__(self, "Software")
     
  def start(self, args):
    try:
      self.root = args["root"].value()
    except IndexError:
      self.root = self.vfs.getnode('/')

    self.registryManager = ModuleProcessusManager().get("winreg")
    self.uninstalls = Uninstalls()
    self.MSIs = MSIs()
    self.ARPCaches = ARPCaches()
    self.autoRuns = AutoRuns()

    self.uninstalled()
    self.msi()
    self.arpcache()
    self.runs()

    self.report()

  def uninstalled(self):
     regKeys = self.registryManager.getKeys({"HKLM\Software\Microsoft\Windows\Currentversion\Uninstall\*" : ['*']} , self.root)
     regSplit = regKeys.split()
     for node, keys in regSplit.iteritems():
        for key in keys:
          self.uninstalls.add(node, Uninstall(key))

     regKeys = self.registryManager.getKeys({"HKU\Software\Microsoft\Windows\Currentversion\Uninstall\*" : ['*']} , self.root)
     regSplit = regKeys.split()
     for node, keys in regSplit.iteritems():
        for key in keys:
          self.uninstalls.add(node, Uninstall(key))

     regKeys = self.registryManager.getKeys({ "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*": ['*']} , self.root)
     regSplit = regKeys.split()
     for node, keys in regSplit.iteritems():
        for key in keys:
          self.uninstalls.add(node, Uninstall(key))

  def msi(self):
     regKeys = self.registryManager.getKeys({ "HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\UserData\*\Products\*\InstallProperties" : ['*']} , self.root)
     regSplit = regKeys.split()
     for node, keys in regSplit.iteritems():
        for key in keys:
          values = key.values()
          if values:
            self.MSIs.add(node, MSI(key.values()))  

  def arpcache(self):
     regKeys = self.registryManager.getKeys({ "HKLM\Software\Microsoft\Windows\CurrentVersion\App Management\ARPCache\*"  : ['*']} , self.root)
     regSplit = regKeys.split()
     for node, keys in regSplit.iteritems():
        for key in keys:
           applicationName = key.name
           if applicationName[0] == '{':
              applicationName =  self.uninstalls.find(applicationName)
           if applicationName:
             self.ARPCaches.add(node, ARPCache(applicationName))  

  def runs(self):
     self.runsPath("HKLM\Software\Microsoft\Windows\CurrentVersion\Run")
     self.runsPath("HKU\Software\Microsoft\Windows\CurrentVersion\Run")

     self.runsPath("HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce", True)
     self.runsPath("HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx", True)
     self.runsPath("HKU\Software\Microsoft\Windows\CurrentVersion\RunOnce", True)
     self.runsPath("HKU\Software\Microsoft\Windows\CurrentVersion\RunOnceEx", True)

  def runsPath(self, path, once = False):
     regKeys = self.registryManager.getKeys({ path : ['*']} , self.root)
     regSplit = regKeys.split()
     for node, keys in regSplit.iteritems():
        for key in keys:       
           values = key.values()
           if values: 
             for value in key.values():
                self.autoRuns.add(node, AutoRun(value, once))

  def report(self):
    self.reportManager = ReportManager()
    trSoftware = TranslateSoftware() 
    page = self.reportManager.createPage(trSoftware.translate("Operating system") + " " +  self.root.name().translate(None, "!@#$%^&'\/?"), trSoftware.translate("Software"))

    self.uninstalls.report(page)
    self.MSIs.report(page)
    self.ARPCaches.report(page)
    self.autoRuns.report(page)

    self.reportManager.addPage(page)
 
class software(Module):
  """This analysis script looks for installed software information."""
  def __init__(self):
     Module.__init__(self, "Software", Software)
     self.conf.addArgument({"name" : "root",
                           "description" : "Root from where the analysis will start.",
                           "input" : Argument.Required | Argument.Single | typeId.Node })
     self.tags = "Windows Analyse"
     self.icon = ":software"
     self.depends = ["File systems", "partition", "winreg"]
