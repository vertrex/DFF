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

from struct import unpack

from dff.api.types.libtypes import Argument, typeId, MS64DateTime, MS128DateTime
from dff.api.module.module import Module, Script
from dff.api.module.manager import ModuleProcessusManager
from dff.api.report.manager import ReportManager
from dff.api.report.fragments import TableFragment

from dff.modules.analyse.analyse import Translator

class NetworkTranslator(Translator):
  def translationMap(self):
     return {
              "Operating system" : unicode(self.tr("Operating system")),   
              "Interface" : unicode(self.tr("Interface")),
              "Name" : unicode(self.tr("Name")),
              "IPAddress" : unicode(self.tr("IP Address")),
              "Mask" : unicode(self.tr("Mask")),
              "Gateway" : unicode(self.tr("Gateway")),
              "DomainName" : unicode(self.tr("Domain name")),
              "Details" : unicode(self.tr("Details")),
              "Value" : unicode(self.tr("Value")),
              "FirstConnection" : unicode(self.tr("First connection")),
              "LastConnection" : unicode(self.tr("Last connection")),
              "Network" : unicode(self.tr("Network")),
              "DefaultGatewayMAC" : unicode(self.tr("Default gateway MAC")),
              "DomainNameSuffix" : unicode(self.tr("Domain name suffix")),
            }

class NetworkInterface(object):
  class NetworkInterfaceTranslator(Translator):
    def translationMap(self):
      return {
              'guid' : unicode(self.tr('guid')),
              'dhcpIPAddress' : unicode(self.tr("Address IP (dhcp)")),
              'dhcpServer' : unicode(self.tr("Server dhcp")),
              'dhcpSubnetMask' : unicode(self.tr("Subnet mask (dhcp)")),
              'dhcpDefaultGateway' : unicode(self.tr("Default gateway (dhcp)")),
              'dhcpNameServer' : unicode(self.tr("Name server (dhcp)")),
              'dhcpDomain' : unicode(self.tr("Domain (dhcp)")),
              'domain' : unicode(self.tr("Domain")),
              'ipAddress' : unicode(self.tr("Address IP")),
              'subnetMask' : unicode(self.tr("Subnet mask")),
              'nameServer' : unicode(self.tr("Name server")),
              'defaultGateway' : unicode(self.tr("Default gateway")),
              'ipAutoconfigurationAddress': unicode(self.tr("Address ip (auto config)")),
              'ipAutoconfigurationMask': unicode(self.tr("Subnet mask (auto config)"))
             }

  properties = ['guid', 'dhcpIPAddress', 'dhcpServer', 'dhcpSubnetMask', 
               'dhcpDefaultGateway', 'dhcpNameServer', 'dhcpDomain', 'domain', 'ipAddress', 
               'subnetMask', 'nameServer', 'defaultGateway', 'ipAutoconfigurationAddress', 
               'ipAutoconfigurationMask']

  def __init__(self, guid, values):
     self.translator = self.NetworkInterfaceTranslator()
     self.__guid = guid
     self.__dhcpIPAddress = None
     self.__dhcpServer = None
     self.__dhcpSubnetMask = None
     self.__dhcpDefaultGateway= None
     self.__dhcpNameServer = None
     self.__dhcpDomain = None
     self.__domain = None
     self.__enableDHCP = None
     self.__ipAddress = None
     self.__subnetMask = None
     self.__defaultGateway = None  
     self.__nameServer = None 
     self.__ipAutoconfigurationAddress = None
     self.__ipAutoconfigurationMask = None
     self.__description = None
     for value in values:
        if value.name == 'DhcpIPAddress':
          self.__dhcpIPAddress = value.data()
        elif value.name == 'DhcpServer':
          self.__dhcpServer = value.data()
        elif value.name == 'DhcpSubnetMask':
          self.__dhcpSubnetMask = value.data()
        elif value.name == 'DhcpDefaultGateway':
           self.__dhcpDefaultGateway = value.data()
        elif value.name == 'DhcpNameServer':
           self.__dhcpNameServer = value.data()
        elif value.name == 'DhcpDomain':
           self.__dhcpDomain = value.data()
        elif value.name == 'Domain':
          self.__domain = value.data()
        elif value.name == 'EnableDHCP':
          self.__enableDHCP = value.data()
        elif value.name == 'IPAddress':
          self.__ipAddress = value.data()
        elif value.name == 'SubnetMask':
          self.__subnetMask = value.data()
        elif value.name == 'DefaultGateway':
          self.__defaultGateway = value.data()
        elif value.name == 'NameServer':
          self.__nameServer = value.data()
        elif value.name == 'IPAutoconfigurationAddress':
          self.__ipAutoconfigurationAddress = value.data()
        elif value.name == 'IPAutoconfigurationMask':
          self.__ipAutoconfigurationMask = value.data()

  def guid(self):
     return self.__guid

  def description(self, description = None):
     if description:
       self.__description = description
     return self.__description

  def toText(self, data):
     if type(data) == tuple or type(data) == list:
       if len(data) == 0:
         return None
       elif len(data) == 1:
         if data[0] ==  '0.0.0.0':
           return None
         return data[0]
       return ', '.join(data)
     if (data == '0.0.0.0'):
       return None
     return data

  def dhcpIPAddress(self):
     return self.toText(self.__dhcpIPAddress)
  
  def dhcpServer(self):
     return self.toText(self.__dhcpServer)
 
  def dhcpSubnetMask(self):
     return self.toText(self.__dhcpSubnetMask)

  def dhcpDefaultGateway(self):
     return self.toText(self.__dhcpDefaultGateway)

  def dhcpNameServer(self):
     return self.toText(self.__dhcpNameServer)

  def dhcpDomain(self):
     return self.__dhcpDomain

  def domain(self):
     return self.toText(self.__domain)

  def enableDHCP(self):
     return self.toText(self.__enableDHCP)

  def ipAddress(self):
     return self.toText(self.__ipAddress)
 
  def subnetMask(self):
     return self.toText(self.__subnetMask)
  
  def nameServer(self):
     return self.toText(self.__nameServer)

  def defaultGateway(self):
     return self.toText(self.__defaultGateway)

  def ipAutoconfigurationAddress(self):
     return self.toText(self.__ipAutoconfigurationAddress)

  def ipAutoconfigurationMask(self):
     return self.toText(self.__ipAutoconfigurationMask)

  def name(self):
     if self.__description:
       return self.description()
     return self.guid()

  def ipConfig(self):
     if self.dhcpIPAddress():
       return (self.dhcpIPAddress(), self.dhcpSubnetMask(), self.dhcpDefaultGateway(), self.dhcpNameServer())
     if self.ipAddress():
       return (self.ipAddress(), self.subnetMask(), self.defaultGateway(), self.nameServer())
     if self.ipAutoconfigurationAddress():
       return (self.ipAutoconfigurationAddress(), self.ipAutoconfigurationMask(), self.defaultGateway(), self.nameServer())
     return (None, None, None, None)   

  def __hash__(self):
     return 1

  def details(self):
     values = []
     for prop in self.properties[1:]:
        res = getattr(self, prop)()
        if res:
          values.append((self.translator.translate(prop), res,))
     return values

  def __eq__(self, other):
     flag = 0
     for prop in self.properties:
       if getattr(self, prop)() != getattr(other, prop)():
         flag = 1
         break
     if flag:
       return False
     return True
     
class NetworkInterfaces(object):
  def __init__(self):
     self.__interfaces = {}

  def add(self, node, interface):
    try:
       if not interface in self.__interfaces[long(node.this)]: #check for different control set in same base if device is the same
         self.__interfaces[long(node.this)].append(interface)
    except KeyError:
       self.__interfaces[long(node.this)] = [interface]

  def setDescription(self, values):
     for value in values:
        if value.name == 'ServiceName': 
          serviceName = value.data()
        elif value.name == 'Description':
           description = value.data()
     for node, interfaces in self.__interfaces.iteritems():
        for interface in interfaces:
          if interface.guid() == serviceName:
            interface.description(description)


  def interfaces(self):
    _interfaces = []
    for node, interfaces in self.__interfaces.iteritems():
      _interfaces += interfaces
    return _interfaces


  def report(self, page):
    translator = NetworkTranslator()
    interfaceTable = page.addDetailTable(translator.translate("Interface"), translator.translate(['Name', 'IPAddress', 'Mask', 'Gateway', 'DomainName']))
    for node, interfaces in self.__interfaces.iteritems():
      for interface in interfaces:
        detailTable = TableFragment(translator.translate("Details"), [translator.translate('Name'), translator.translate('Value')], interface.details()) 
        ipConfig = interface.ipConfig()
        name = interface.name()
        if not (name == interface.guid() and ipConfig == (None, None, None, None)):
          interfaceTable.addRow((name,) + ipConfig, detailTable)    

class Profiles(object):
  def __init__(self, guid, values):
     self.__guid = guid
     self.__dateCreated = None
     self.__dateLastConnected = None
     self.__description = None
     self.__dnsSuffix = None
     self.__defaultGatewayMAC = None
     self.__signature = None
     for value in values:
       if value.name == 'DateCreated':
         self.__dateCreated  = str(MS128DateTime(unpack('16s', buffer(value.data()))[0]))
       elif value.name == 'DateLastConnected':
         self.__dateLastConnected = str(MS128DateTime(unpack('16s', buffer(value.data()))[0]))
       elif value.name == 'Description':
         self.__description = value.data()

  def guid(self):
     return self.__guid

  def description(self):
     return self.__description

  def dateCreated(self):
     return self.__dateCreated

  def dateLastConnected(self):
     return self.__dateLastConnected 

  def setSignature(self, signature):
     self.__signature = signature

  def defaultGatewayMac(self):
     if self.__signature:
       return self.__signature.defaultGatewayMac()
 
  def dnsSuffix(self):
     if self.__signature:
       return self.__signature.dnsSuffix()

class Signature(object):
  def __init__(self, mode, values):
     self.__mode = mode
     self.__profileGuid = None
     self.__defaultGatewayMac = None
     self.__dnsSuffix = None
     self.__description = None
     self.__firstNetwork = None

     for value in values: 
       if value.name == 'DefaultGatewayMac':
         mac = ""
         macAddress = value.data()
         if macAddress:
           for x in range(0, 6):
             if (x != 0):
               mac += ':'
           mac += '%.2x' % macAddress[x]
         if mac == "00:00:00:00:00:00:":
           self.__defaultGatewayMac = None
         else:
           self.__defaultGatewayMac = mac
       elif value.name == 'DnsSuffix':
         self.__dnsSuffix = value.data()
       elif value.name == 'Description':
         self.__description = value.data()
       elif value.name == 'FirstNetwork':
         self.__firstNetwork = value.data()
       elif value.name == 'ProfileGuid':
         self.__profileGuid = value.data()

  def mode(self):
     return self.__mode

  def profileGuid(self):
     return self.__profileGuid
 
  def defaultGatewayMac(self):
     return self.__defaultGatewayMac

  def dnsSuffix(self):
     return self.__dnsSuffix

  def firstNetwork(self):
    return  self.__firstNetwork

class NetworkList(object):
  def __init__(self):
     self.__networks = {}

  def add(self, node, network):
    try:
     self.__networks[long(node.this)].append(network)
    except KeyError:
     self.__networks[long(node.this)] = [network]
  
  def addSignature(self, node, signature):
     try:
        networks = self.__networks[long(node.this)]
        for network in networks:
           if network.guid() == signature.profileGuid():
             network.setSignature(signature)
     except KeyError:
        pass
 
  def networks(self):
     return self.__networks

  def report(self, page):
     translator = NetworkTranslator()
     if len(self.__networks) == 0:
       return
     header = translator.translate(['Name', 'FirstConnection', 'LastConnection'])
     networkTable = page.addDetailTable(translator.translate("Network"), header) 
     for node, networks in self.__networks.iteritems():
        for network in networks:
           detailTable = TableFragment(translator.translate("Details"), translator.translate(['DefaultGatewayMAC', 'DomainNameSuffix']), [(network.defaultGatewayMac(), network.dnsSuffix(),)])
           networkTable.addRow((network.description(), network.dateCreated(), network.dateLastConnected(),), detailTable)

class WlanConfig(object):
  """Windows XP only for vista and 7 info are in an XML file"""
  def __init__(self, data):
     data = buffer(data)
     length, dwCtlFlags, macAddress, unknown, ssidLength, ssidRaw = unpack('II6s2sI32s', data[0:0x14+32])
     self.__ssid = ssidRaw[:ssidLength]
     mac = ""
     for x in macAddress:
        mac += '%.2x' % ord(x) + ':'
     if mac == "00:00:00:00:00:00:":
       self.__macAddress = None
     else:
       self.__macAddress = mac[:-1]

     self.__lastConnection = None
     try:
       lastConnection =  unpack('Q', data[0x2b8:0x2b8+8])[0]
       if lastConnection: 
         self.__lastConnection = str(MS64DateTime(lastConnection))
     except:
       pass

  def ssid(self):
     return self.__ssid

  def macAddress(self): #BSSID ! (address de l acces point)
     return self.__macAddress   

  def lastConnection(self): #XXX never found in examples 
     return self.__lastConnection

class WlanConfigs(object):
  def __init__(self):
     self.__configs = {}

  def add(self, node, config):
    try:
      self.__configs[long(node.this)].append(config)
    except KeyError:
      self.__configs[long(node.this)] = [config]
        
  def report(self, page):
     head = ['SSID', 'BSSID']
     table = []
     for node, configs in self.__configs.iteritems():
       for config in configs:
         ssid = config.ssid()
         mac = config.macAddress()
         if len(ssid) != 0 or mac != None:
           table.append((config.ssid(), config.macAddress(),))
     if len(table):
       page.addTable("Wifi", head, table)

class Network(Script):
  def __init__(self):
     Script.__init__(self, "Network")

  def start(self, args):
    try:
      self.root = args["root"].value()
    except IndexError:
      self.root = self.vfs.getnode("/")
    self.process()
    self.report()


  def process(self, root=None):
    if root != None:
      self.root = root
    else:
      root = self.root
    self.registryManager = ModuleProcessusManager().get("winreg")
    self.networkInterfaces = NetworkInterfaces()
    self.wlanConfigs = WlanConfigs()
    self.networkList = NetworkList()
    self.interfaces()
    self.cards()
    self.wlan()
    self.network()
    self.signatures()



  def interfaces(self):
    regKeys = self.registryManager.getKeys({ 'HKLM\SYSTEM\ControlSet*\Services\Tcpip\Parameters\Interfaces\*'   : [''] }, self.root)
    regSplit = regKeys.split()
    for node, keys in regSplit.iteritems():
      for key in keys:
         if key.values():
           self.networkInterfaces.add(node, NetworkInterface(key.name, key.values()))
  
  def cards(self):
    regKeys = self.registryManager.getKeys({ 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards\*'   : ['*'] }, self.root)
    regSplit = regKeys.split()
    for node, keys in regSplit.iteritems():
      for key in keys:
        if key.values():
          self.networkInterfaces.setDescription(key.values())

  def wlan(self):
    regKeys = self.registryManager.getKeys({ 'HKLM\SOFTWARE\Microsoft\WZCSVC\Parameters\Interfaces\*'   : ['*'] }, self.root)
    regSplit = regKeys.split()
    for node, keys in regSplit.iteritems():
      for key in keys:
        if key.values():
          for value in key.values():
             if value.name == 'ActiveSettings':
               self.wlanConfigs.add(node, WlanConfig(value.data()))

  def network(self): 
    regKeys = self.registryManager.getKeys({ 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\*': ['*'] }, self.root)
    regSplit = regKeys.split()
    for node, keys in regSplit.iteritems():
      for key in keys:
        if key.values():
          self.networkList.add(node, Profiles(key.name, key.values()))

  def signatures(self):
    for mode in ['Managed', 'Unmanaged']:
      regKeys = self.registryManager.getKeys({ 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\\'+ mode + '\*': ['*'] }, self.root)
      regSplit = regKeys.split()
      for node, keys in regSplit.iteritems():
        for key in keys:
          if key.values():
            self.networkList.addSignature(node, Signature(mode, key.values()))

  def report(self):
    self.reportManager = ReportManager()
    translator = NetworkTranslator()
    page = self.reportManager.createPage(translator.translate("Operating system") + " " + self.root.name().translate(None, "!@#$%^&'\/?").encode('UTF-8', 'replace'), translator.translate("Network"))

    self.networkInterfaces.report(page)
    self.wlanConfigs.report(page)
    self.networkList.report(page)

    self.reportManager.addPage(page)

class network(Module):
   """Windows network configuration information"""
   def __init__(self):
      Module.__init__(self, "Network", Network)
      self.conf.addArgument({"name" : "root",
                           "description" : "Root from where the analysis will start.",
                           "input" : Argument.Required | Argument.Single | typeId.Node })
      self.tags = "Windows Analyse"
      self.icon = ":network"
      self.depends = ["File systems", "partition", "winreg"]
