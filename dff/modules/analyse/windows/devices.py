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
from collections import OrderedDict

from dff.api.vfs.libvfs import VFS
from dff.api.types.libtypes import Argument, typeId, MS64DateTime 
from dff.api.filters.libfilters import Filter
from dff.api.module.module import Module, Script
from dff.api.module.manager import ModuleProcessusManager
from dff.api.report.manager import ReportManager

from dff.modules.analyse.analyse import Translator

class DeviceTranslator(Translator):
  def translationMap(self):
     return {
              "Operating system" : unicode(self.tr("Operating system")),   
              "Volume" : unicode(self.tr("Volume")),
              "Devices" : unicode(self.tr("Devices")),
              "Size" : unicode(self.tr("Size")),
              "Signature" : unicode(self.tr("Signature")),
              "Offset" : unicode(self.tr("Offset")),
            }

class Device(object):
  def __init__(self, enumName, uniqueID, values):
    self.__enumName = enumName
    self.__uniqueID = uniqueID
    self.__friendlyName = None
    self.__deviceDesc = None
    self.__class = None
    self.__parentIdPrefix = None
    self.__mountPoints = () 
    self.__users = ()
    if len(uniqueID) > 1 and uniqueID[1] == '&':
      end = uniqueID[2:].find('&')
      if end != -1:
        self.__parentIdPrefix = uniqueID[2:2+end]    
    for value in values:
      if value.name == 'DeviceDesc':
        self.__deviceDesc = value.data()
      elif value.name == 'Class':
        self.__class = value.data()
      elif value.name == 'FriendlyName':
        self.__friendlyName = value.data()
      elif value.name == 'ParentIdPrefix':
        self.__parentIdPrefix = value.data()

  def deviceDesc(self):
     return self.__deviceDesc

  def klass(self):
     return self.__class

  def friendlyName(self):
     return self.__friendlyName

  def enumName(self):
     return self.__enumName

  def serialNumber(self):
     if len(self.__uniqueID) < 2:
       return None
     if self.__uniqueID[1] != '&':
       pos = self.__uniqueID.rfind('&')
       if pos != -1:
         return self.__uniqueID[:pos]
     return None

  def parentIdPrefix(self):
     return self.__parentIdPrefix

  def addMountPoint(self, mountPoint):
     self.__mountPoints += (mountPoint,)

  def addUsers(self, usersTime):
     for user, time in usersTime:
       self.__users += (user, str(time),)

  def mountPoints(self):
     return self.__mountPoints

  def users(self):
     return self.__users


class DevicesReg(list):
  #We create one DevicesReg per Node
  class DevicesRegTranslator(Translator):
    def translationMap(self):
      return {  'deviceDesc' : unicode(self.tr("Description")),
                'klass' : unicode(self.tr("Class")),
                'friendlyName' : unicode(self.tr("Name")),
                'serialNumber' : unicode(self.tr("Serial number")),
                'users' : unicode(self.tr("Users last connection")),
                'mountPoints' : unicode(self.tr("Mount points")),
              } 

  def __init__(self):
     self.__currents = {}   
     self.__devices = {}     

  def addCurrent(self, node, current):
     try:
       self.__currents[long(node.this)].append(current)
     except KeyError:
       self.__currents[long(node.this)] = [current]

  def addDevice(self, node, device):
     try:
       self.__devices[long(node.this)].append(device)
     except KeyError:
       self.__devices[long(node.this)] = [device]

  def devices(self):
     return self.__devices

  def __tablesStore(self, store):
    translator = self.DevicesRegTranslator()
    properties = OrderedDict()
    properties['friendlyName'] = 0
    properties['deviceDesc'] = 0
    properties['klass'] = 0
    properties['serialNumber'] = 0
    properties['users'] = 0
    properties['mountPoints'] = 0

    for device in store:
       for prop in properties.iterkeys():
         if getattr(device, prop)():
           properties[prop] += 1
   
    finalProperty = []
    for prop in properties.iterkeys():
      if properties[prop] != 0: 
        finalProperty.append(prop)
  
    finalTable = set()
    for device in store:
      devprop = ()
      for prop in finalProperty:
        res = getattr(device, prop)()
        devprop += (res,)
      finalTable.add(devprop)        
     
    translateProperty = []
    for prop in finalProperty:
      translateProperty.append(translator.translate(prop))       
 
    return (translateProperty, finalTable)

  def tables(self):
    stores = {} 
    for devices in self.__devices.itervalues():
      for device in devices:
        try:
          stores[device.enumName()].append(device)
        except KeyError:
          stores[device.enumName()] = [device]

    tables = []
    for name, store in stores.iteritems():
      (props, table) = self.__tablesStore(store)
      tables.append((name, props, list(table)))

    return tables

class MountedDevice(object):
  def __init__(self, name, value):
     self.__name = name
     self.__value = value

  def name(self):
     return self.__name

  def value(self):
     return self.__value

  def findParentIdPrefix(self, parentIdPrefix):
     if self.__value.find(parentIdPrefix) != -1:
       return True
     return False

  def isMountPoint(self):
     return not self.isVolume()

  def isVolume(self):
     if self.__name[0:4] == '\??\\':
       return True        
     return False

  def volume(self):
     if self.isVolume:
       return self.__name[10:]

class MountedDevices(object):
   def __init__(self):
      self.__mountedDevices = {} 

   def add(self, node, mountedDevice):
     try:
       self.__mountedDevices[long(node.this)].append(mountedDevice)
     except KeyError:
       self.__mountedDevices[long(node.this)] = [mountedDevice]

   def findParentIdPrefix(self, nodeID, parentIdPrefix):
     try:
       matches = [] 
       mountedDevices = self.__mountedDevices[nodeID]
       for mountedDevice in  mountedDevices:
          if mountedDevice.findParentIdPrefix(parentIdPrefix):
            matches.append(mountedDevice)
       if len(matches):
         return matches
     except KeyError:
       pass

#no device info so it's not correlable
class Volume(object):
  def __init__(self, name, values):     
    self.__length = None
    self.__signature = None
    self.__offset = None
    signaturePos = name.find('Signature')
    if signaturePos == -1:
      return
    offsetPos = name.find('Offset')
    lengthPos = name.find('Length')
    if offsetPos ==  -1 or lengthPos == -1:
      return 
    
    self.__signature = name[signaturePos + len('Signature'):offsetPos] 
    self.__offset = name[offsetPos + len('Offset'):lengthPos] 
    self.__length = name[lengthPos + len("Length"):] 
    self.__length = str(int(self.__length, 16))    

  def offset(self):
     return self.__offset
        
  def length(self):
     return self.__length

  def signature(self):
     return self.__signature

class Volumes(object):
  def __init__(self):
     self.__volumes = {}
  
  def add(self, node, volume):
    try:       
      self.__volumes[long(node.this)].append(volume)
    except KeyError:
      self.__volumes[long(node.this)] = [volume]

  def report(self, page):
    volumeTable = set() 
    for node, volumes in self.__volumes.iteritems():
      for volume in volumes:
        result = (volume.length(), volume.signature(), volume.offset(),)
        if result != (None, None, None,):
          volumeTable.add(result)
    if len(volumeTable):
      translator= DeviceTranslator()
      headerProperties = translator.translate(['Size', 'Signature', 'Offset'])
      page.addTable(translator.translate("Volume"), headerProperties, list(volumeTable)) 
 
class Devices(Script):
  def __init__(self):
    Script.__init__(self, "Devices")


  def start(self, args):
    try:
      self.root = args["root"].value()
    except IndexError:
      self.root = self.vfs.getnode("/")
    self.process()
    self.report()



  def process(self, root=None):
    self.registryManager = ModuleProcessusManager().get("winreg")
    if root != None:
      self.root = root
    self.devices = DevicesReg()
    self.mountedDevices = MountedDevices()
    self.volumes = Volumes()
    self.currentControlSet()
    self.enums('USBSTOR')
    self.enums('USBPRINT')
    self.enums('USB')
    self.enums('IDE')
    self.storage()
    self.mounted()
    self.mountPoints()
    self.correlate()


  def currentControlSet(self):
    currents = []
    regKeys = self.registryManager.getKeys({ 'HKLM\SYSTEM\Select'   : ['current'] }, self.root) #last known good ?
    regSplit = regKeys.split()
    for node, keys in regSplit.iteritems():
      for key in keys:
         for value in key.values():
            self.devices.addCurrent(node, value.data())
    return currents
 
  def enums(self, enumName):
    regKeys = self.registryManager.getKeys({ 'HKLM\SYSTEM\ControlSet*\Enum\\' + enumName + '\*\*'   : ['Class', 'DeviceDesc', 'FriendlyName', 'ParentIdPrefix'] }, self.root)
    regSplit = regKeys.split()
    for node, keys in regSplit.iteritems():
      for key in keys:
         self.devices.addDevice(node, Device(enumName, key.name, key.values()))

  def mounted(self):
    regKeys = self.registryManager.getKeys({ 'HKLM\SYSTEM\MountedDevices' : {"values" : "*"} }, self.root)
    regSplit = regKeys.split()
    for node, keys in regSplit.iteritems():
       for key in keys:
         for value in key.values():
            self.mountedDevices.add(node, MountedDevice(value.name, value.data().decode('utf-16')))

  def storage(self):
     regKeys = self.registryManager.getKeys({'HKLM\SYSTEM\ControlSet*\Enum\STORAGE\Volume\*' : {"values" : "*"} }, self.root)
     regSplit = regKeys.split()
     for node, keys in regSplit.iteritems():
       for key in keys:
         self.volumes.add(node, Volume(key.name, key.values()))   
     #for volume in self.volumes:
        #print volume

  def correlate(self):
     for nodeID, devices in self.devices.devices().iteritems():
       for device in devices:
         parentIdPrefix = device.parentIdPrefix()
         if parentIdPrefix:
           mountedDevices = self.mountedDevices.findParentIdPrefix(nodeID, parentIdPrefix)
           if mountedDevices:
             for mountedDevice in mountedDevices:
               if mountedDevice.isMountPoint():
                 device.addMountPoint(mountedDevice.name())
               else:
                 users = self.searchUsersVolume(mountedDevice.volume())
                 device.addUsers(users)

  def mountPoints(self):
     self.__mountPointsKeys = self.registryManager.getKeys({ 'HKU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\*' : {"values" : "*"} }, self.root).split()

  def searchUsersVolume(self, volume):
    users = []
    for node, keys in self.__mountPointsKeys.iteritems():
       for key in keys:
         if volume == key.name:
           parent = key.parent().get_parent()
           for value in parent.values:
             if value.name == 'Logon User Name':
               user = value.fetch_raw_data().decode('utf-16')
               if not user in users:
                 users.append((user, MS64DateTime(key.mtime)))
    return users

  def report(self):
    translator = DeviceTranslator()
    self.reportManager = ReportManager()
    tables = self.devices.tables()
    categoryName = translator.translate("Operating system") + " " + self.root.name().translate(None, "!@#$%^&'\/?")
    page = self.reportManager.createPage(categoryName, translator.translate("Devices"))
    for (name, props, table) in tables:
       page.addTable(name, props, table)
    self.volumes.report(page)
    self.reportManager.addPage(page)    

class devices(Module):
  """Windows devices information"""
  def __init__(self):
    Module.__init__(self, "Devices", Devices)
    self.conf.addArgument({"name" : "root",
                           "description" : "Root from where the analysis will start.",
                           "input" : Argument.Required | Argument.Single | typeId.Node })
    self.tags = "Windows Analyse"
    self.icon = ":systemsettings"
    self.depends = ["File systems", "partition", "winreg"]
