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

import os
from dff.api.devices.libdevices import Device, DeviceList

DevicesLib = list
LogicalLib = list
if os.name == "posix":
  try :
    from dff.api.devices.libdevices import UDevices
    DevicesLib = UDevices    
  except :
    from dff.api.devices.dbushaldev import DBusHalDevices
    import dbus
    DevicesLib = DBusHalDevices
    try:
      DevicesLib()
    except:
      DevicesLib = list
else:
  try :
    from dff.api.devices.libdevices import WMIDevices
    from dff.api.devices.libdevices import LogicalDrives
    DevicesLib = WMIDevices
    LogicalLib = LogicalDrives
  except ImportError:
    pass

class Devices():
  def __init__(self):
    if DevicesLib:
        self.__instance = DevicesLib()

  def __getattr__(self, attr):
     return getattr(self.__instance, attr)


class Logical():
  def __init__(self):
    if LogicalLib:
      self.__instance = LogicalLib()

  def __getattr__(self, attr):
        return getattr(self.__instance, attr)
