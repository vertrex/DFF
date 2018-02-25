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

from dff.api.devices.libdevices import Device, DeviceList

try :
  import dbus
  import gobject
except ImportError:
  pass


class DBusHalDevice(Device):
  def __init__(self, uid, proxy_dev):
    Device.__init__(self)
    self.thisown = 0
    self.uid = uid
    self.ddev = proxy_dev
    setattr(self, "serialNumber", self.serialNumber)

  def getAllProperties(self):
    return dev_obj.GetAllProperties()

  def allProperties(self):
     buff = self.uid + "\n"
     for key, val in self.ddev.GetAllProperties().iteritems():
        buff += str(key)  + " : " + str(val) + "\n"
     return buff

  def blockDevice(self):
   try :
     return str(self.ddev.GetProperty('block.device'))
   except dbus.exceptions.DBusException:
     return Device.blockDevice(self)

  def serialNumber(self):
   try:
     return str(self.ddev.GetProperty('storage.serial'))
   except dbus.exceptions.DBusException:
      return Device.serialNumber(self) 

  def model(self):
    try:
      return str(self.ddev.GetProperty('storage.model'))
    except dbus.exceptions.DBusException:
      Device.model(self)
	
  def size(self):
   if int(self.ddev.GetProperty('storage.removable')) == 1:
    try:
     return str(self.ddev.GetProperty('storage.removable.media_size'))
    except dbus.exceptions.DBusException:
	return Device.size(self)	
   else:
     return str(self.ddev.GetProperty('storage.size'))
  
  ##def blockMajor(self):
   #return self.ddev.GetProperty('block.major') 

  #def blockMinor(self):
    #return self.ddev.GetProperty('block.minor')

  #def isVolume(self):
    #return self.ddev.GetProperty('block.is_volume')

  #def noPartitions(self):
    #return self.ddev.GetProperty('block.no_partitions')
 
  #def haveScanned(self):
    #return self.ddev.GetProperty('block.have_scanned')

  def __str__(self):
   buff = ""
   buff += "Device uid      : " + str(self.uid) + "\n"
   buff += "Block device    : " + str(self.blockDevice()) + "\n"
   #buff += "Block no partitions :" + str(self.noPartitions()) + "\n"
   #buff += "Block have scanned :" + str(self.haveScanned()) + "\n"
   return buff




class DBusHalDevices(DeviceList):
  """This class try to initialize devices list through dbus-HAL"""
  def __init__(self):
    DeviceList.__init__(self)
    self.deviceList = []
    self.thisown = 0
    system_bus = dbus.SystemBus()
    bus_name = "org.freedesktop.Hal" 
    object = "/org/freedesktop/Hal/Manager"
    miface = "org.freedesktop.Hal.Manager"
    proxy = system_bus.get_object(bus_name, object)
    iface = dbus.Interface(proxy, miface)
    devices_uid = iface.FindDeviceByCapability('block')
    for dev_uid in  devices_uid:
      dev_obj = system_bus.get_object('org.freedesktop.Hal', dev_uid)
      dev_obj = dbus.Interface(dev_obj, 'org.freedesktop.Hal.Device')
      if dev_obj.GetProperty('info.category') == "storage":	
        self.deviceList.append(DBusHalDevice(dev_uid, dev_obj))

  def __str__(self):
    buff = ""
    for dev in self.deviceList:
	buff += dev.allProperties()
	buff += "\n"
    return buff


