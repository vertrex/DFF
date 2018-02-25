from struct import unpack

from dff.api.types.libtypes import Argument, typeId, DateTime, MS64DateTime
from dff.api.module.module import Module, Script
from dff.api.module.manager import ModuleProcessusManager

from dff.pro.api.report.manager import ReportManager
from dff.pro.api.report.fragments import TableFragment

from dff.pro.modules.analyse.analyse import Translator 

class SystemTranslator(Translator):
  def translationMap(self):
     return {
       "Operating system" : unicode(self.tr("Operating system")),
       "System" : unicode(self.tr("System")),
       'CSDVersion': unicode(self.tr("CSD Version")),
       'CSDBuildNumber': unicode(self.tr("CSD Build number")),
       'CurrentBuild': unicode(self.tr("Current build")),
       'CurrentBuildNumber': unicode(self.tr("Current build number")),
       'CurrentType': unicode(self.tr("Current type")),
       'CurrentVersion': unicode(self.tr("Current version")),
       'EditionID' : unicode(self.tr("Edition ID")),
       'InstallDate': unicode(self.tr("Install date")),
       'PathName': unicode(self.tr("Path name")),
       'ProductId': unicode(self.tr("Product ID")),
       'ProductName': unicode(self.tr("Product name")),
       'RegisteredOwner': unicode(self.tr("Registered owner")),
       'RegisteredOrganization': unicode(self.tr("Registered organization")),
       'SystemRoot' : unicode(self.tr("System root")),
       'Details' : unicode(self.tr("Details")),
       'Description' : unicode(self.tr("Description")),
       'Value' : unicode(self.tr("Value")),
       'Version' : unicode(self.tr("Version")),
       'Computer' : unicode(self.tr("Computer")),
       'Name' : unicode(self.tr("Name")),
       "ActiveTimeBias" : unicode(self.tr("Active time bias")),
       "Bias" :  unicode(self.tr("Bias")),
       "DaylightBias" :  unicode(self.tr("Dailight bias")),
       "StandardBias" : unicode(self.tr("Standard bias")),
       "DaylightName" : unicode(self.tr("Dailight name")),
       "StandardName" : unicode(self.tr("Standard name")),
       "TimeZoneKeyName" : unicode(self.tr("Time zone key name")),
       "DaylightStart" : unicode(self.tr("Daylight start")),
       "StandardStart" : unicode(self.tr("Standard start")),
       "TimeZone" : unicode(self.tr("Time zone")),
       "Zone" : unicode(self.tr("Zone")),
       "Shutdown" : unicode(self.tr("Shutdown")),
       "Time" : unicode(self.tr("Time")),
     }

class WindowsVersion(object):
  properties = ['CSDVersion', 'CSDBuildNumber', 'CurrentBuild', 'CurrentBuildNumber',
                'CurrentType', 'CurrentVersion,' 'EditionID', 'InstallDate', 'PathName',
                'ProductId', 'ProductName', 'RegisteredOwner', 'RegisteredOrganization', 'SystemRoot']
  def __init__(self, values): 
     self.translator = SystemTranslator()
     self.__values = {}
     for value in values: 
       if value.name in self.properties:
         self.__values[value.name] = value.data()

     try:
       installDate = self.__values['InstallDate']
       if installDate != 0:
         self.__values['InstallDate'] = str(DateTime(installDate))
     except KeyError:
       pass

  def details(self):
     values = []
     for prop in self.properties:
        try:
           value = self.__values[prop]
           if value:
             translation = self.translator.translate(prop)
             values.append((translation, value,))
        except KeyError:
           pass
     return values

  def table(self, properties):
     table = []
     for prop in properties:
       try:
          value = self.__values[prop]
          table.append(value)
       except KeyError: 
          table.append(None)
     return table

class WindowsVersions(object):
  def __init__(self):
     self.__versions = {} 
     self.translator = SystemTranslator()

  def add(self, node, version):
     try:
       self.__versions[long(node.this)].append(version)
     except KeyError:
       self.__versions[long(node.this)] = [version]

  def report(self, page):
     headerProperties = ['ProductName', 'RegisteredOwner', 'InstallDate']
     versionTable = page.addDetailTable(self.translator.translate("Version"), self.translator.translate(headerProperties))
     for node, versions in self.__versions.iteritems():
        for version in versions:
           detailTable = TableFragment(self.translator.translate("Details"), self.translator.translate(["Description", "Value"]), version.details())
           versionTable.addRow(version.table(headerProperties), detailTable)

class ComputerName(object):
  def __init__(self, value):
     self.__name = value

  def name(self):
     return self.__name

class ComputerNames(object):
  def __init__(self):
     self.translator = SystemTranslator()
     self.__computers = {}    

  def add(self, node, computer):
    try:
     self.__computers[node].append(computer)
    except KeyError:
     self.__computers[node] = [computer]

  def names(self):
     names = set()
     for node, computers in self.__computers.iteritems():
        for computer in computers:
          names.add(computer.name())
     return [list(names)]

  def report(self, page):
     names = self.names()
     if len(names):#XXX
       page.addTable(self.translator.translate("Computer"), self.translator.translate(["Name"]), names)


class TimeZone(object):
  #XXX XXX on windows 7 use @tzreds.dll notation so must have a way to get this and decode it 
  # node.find(tzres.dll) -> module ?? -> getString(-offset)
  def __init__(self, values):
     self.__values = {}
     for value in values:
        data = value.data()
        if data == None:
          data = value._value.fetch_raw_data()
        self.__values[value.name] = data 
     try:
       self.__values['TimeZoneKeyName'] = self.unicodeStrip(self.__values['TimeZoneKeyName'])
     except KeyError:
       pass
     try:
       self.__values['StandardName'] = self.searchDLLString(self.__values['StandardName'])
     except KeyError:
       pass

  def unicodeStrip(self, data):
     if data:
       for pos in range(len(data)):
         if not pos % 2:
           try:
             if data[pos] == 0x0 and data[pos+1] == 0x0:
               return data[:pos+2].decode('utf-16')
           except KeyError:
             pass
     return None

  def searchDLLString(self, data):
     if data[0] == '@':
       return None
       #print 'seeking for resource'
       #self.root.search('/....dll.mui')  
       #self.root.search('.dll')  
       #return #pefile().get_strings(number)  
     return data

  def values(self, name):
     try:
        return self.__values[name]
     except KeyError:
        return None
 
  def details(self):
     for prop in self.__values:
       print prop, self.__values[prop]   

class TimeZones(object):
  def __init__(self):
     self.translator = SystemTranslator()
     self.__timeZones = {}

  def add(self, node, timeZone):
    try:
      self.__timeZones[long(node.this)].append(timeZone)
    except KeyError:
      self.__timeZones[long(node.this)] = [timeZone]

  def report(self, page):
    table = set() 
    for node, timeZones in self.__timeZones.iteritems():
      for timeZone in timeZones:
         tz =  timeZone.values('StandardName')
         if tz == None:
           tz = timeZone.values('TimeZoneKeyName')
         if tz:
           table.add((tz,))
    page.addTable(self.translator.translate("TimeZone"), self.translator.translate(['Zone']), list(table))

class ShutdownTime(object):
  def __init__(self, data):
     data = buffer(data)
     self.__shutdownTime = MS64DateTime(unpack('Q', data)[0])

  def time(self):
     return self.__shutdownTime

class ShutdownTimes(object):
  def __init__(self):
     self.__shutdownTimes = {}
     self.translator = SystemTranslator()

  def add(self, node, shutdownTime):
     try:
       self.__shutdownTimes[long(node.this)].append(shutdownTime)
     except KeyError:
       self.__shutdownTimes[long(node.this)] = [shutdownTime]

  
  def shutdownTime(self):
     time = None
     for node, shutdownTimes in self.__shutdownTimes.iteritems():
        for shutdownTime in shutdownTimes:
           if time is None:
             time = shutdownTime.time()
           else:
             if shutdownTime.time() > time:
               time = shutdownTime.time()
     return time


  def report(self, page):
    #report only the last shutdown 
    time = self.shutdownTime()
    if time:
      page.addTable(self.translator.translate("Shutdown"), self.translator.translate(["Time"]), [(str(time),)]) 

class System(Script):
  def __init__(self):
      Script.__init__(self, "System")
     
  def start(self, args):
    self.translator = SystemTranslator()
    try:
      self.root = args["root"].value()
    except IndexError:
      self.root = self.vfs.getnode('/')
    self.process()
    self.report()


  def process(self, root=None):
    self.registryManager = ModuleProcessusManager().get("winreg")
    if root != None:
      self.root = root
    self.registryManager = ModuleProcessusManager().get("winreg")
    self.windowsVersions = WindowsVersions()
    self.computerNames = ComputerNames()
    self.timeZones = TimeZones()
    self.shutdownTimes = ShutdownTimes()

    self.version()
    self.computer()
    self.timeZone()
    self.shutdownTime()


  def version(self): 
    regKeys = self.registryManager.getKeys({ 'HKLM\Software\Microsoft\Windows NT\CurrentVersion' : ['*']  }, self.root)
    regSplit = regKeys.split()
    for node, keys in regSplit.iteritems():
       for key in keys:
          if key.values():
            self.windowsVersions.add(node, WindowsVersion(key.values()))
 
  def computer(self):
    regKeys = self.registryManager.getKeys({ 'HKLM\System\ControlSet*\Control\ComputerName\ComputerName' : ['*']  }, self.root)
    regSplit = regKeys.split()
    for node, keys in regSplit.iteritems():
       for key in keys:
          if key.values():
            for value in key.values():
               if value.name == 'ComputerName':
                 self.computerNames.add(node, ComputerName(value.data()))

  def timeZone(self):
    regKeys = self.registryManager.getKeys({ 'HKLM\System\ControlSet*\Control\TimeZoneInformation' : ['*']  }, self.root)
    regSplit = regKeys.split()
    for node, keys in regSplit.iteritems():
       for key in keys:
          if key.values():
            self.timeZones.add(node, TimeZone(key.values()))

  def shutdownTime(self):
    regKeys = self.registryManager.getKeys({ 'HKLM\System\ControlSet*\Control\Windows' : ['*']  }, self.root)
    regSplit = regKeys.split()
    for node, keys in regSplit.iteritems():
       for key in keys:
          if key.values():
            for value in key.values():
               if value.name == 'ShutdownTime':
                 self.shutdownTimes.add(node, ShutdownTime(value.data()))
         
  def report(self):
    self.reportManager = ReportManager()
    page = self.reportManager.createPage(self.translator.translate("Operating system") + " " + self.root.name().translate(None, "!@#$%^&'\/?"), self.translator.translate("System"))

    self.windowsVersions.report(page)    
    self.computerNames.report(page)
    self.timeZones.report(page)
    self.shutdownTimes.report(page)

    self.reportManager.addPage(page)
 
class system(Module):
  """This analysis script searches for system information inside the registry."""
  def __init__(self):
     Module.__init__(self, "System", System)
     self.conf.addArgument({"name" : "root",
                           "description" : "Root from where the analysis will start.",
                           "input" : Argument.Required | Argument.Single | typeId.Node })
     self.tags = "Windows Analyse"
     self.icon = ":systemsettings"
     self.depends = ["File systems", "partition", "winreg"]
