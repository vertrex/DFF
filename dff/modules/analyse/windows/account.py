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
from struct import unpack

from dff.api.vfs.libvfs import VFS
from dff.api.types.libtypes import Argument, typeId, MS64DateTime 
from dff.api.module.module import Module, Script
from dff.api.module.manager import ModuleProcessusManager
from dff.api.report.manager import ReportManager
from dff.api.report.fragments import TableFragment

from dff.modules.analyse.analyse import Translator 

class AccountTranslator(Translator):
  def translationMap(self):
    return {
             "Details" : unicode(self.tr("Details")),
             "Key" : unicode(self.tr("Key")),
             "Value" : unicode(self.tr("Value")),
             "Operating system" : unicode(self.tr("Operating system")),
             "Users" : unicode(self.tr("Users")),
             "Accounts" : unicode(self.tr("Accounts")),
           }

class AccountDBF(object):
  RegistryKeyPath = { "HKLM\SAM\SAM\Domains\Account" : { "values" :  "F" } } 
  def __init__(self, data):
    (unknown1, unknown2, self.__policyUpdateCount, unknown3, self.__maxPwAge, self.__minPwAge, unknown4, self.__lockoutDuration, self.__lockoutRelease, unknown5, self.__rid, self.__flags, self.__minimumPwLen, self.__pwHistoryCounts, self.__lockoutLimit) = unpack('QQIIQQQQQQIIHHH', buffer(data)[0:86])

  def policyUpdateCount(self):
     return self.__policyUpdateCount

  def maxPwAge(self):
     return self.__maxPwAge

  def minPwAge(self):
     return self.__minPwAge
 
  def lockoutDuration(self):
     return self.__lockoutDuration

  def lockoutRelease(self):
     return self.__lockoutRelease

  def RID(self):
     return self.__rid

  def flags(self):
     return self.__flags

  def minimumPwLen(self):
     return self.__minimumPwLen

  def pwHistoryCounts(self):
     return self.__pwHistoryCounts

  def lockoutLimit(self):
     return self.__lockoutLimit 

  def show(self):
     l = ["policyUpdateCount", "maxPwAge", "minPwAge", "lockoutDuration", "lockoutRelease", "RID", "flags",
          "minimumPwLen", "pwHistoryCounts", "lockoutLimit"]
     for attr in l:
        print attr, getattr(self, attr)()

class GroupC(object):
  class Translate(Translator):
     def __init__(self):
        Translator.__init__(self)
        self.trMap = {
                       "groups" : unicode(self.tr("Groups")),
                       "name" : unicode(self.tr("Name")),
                       "fullName" : unicode(self.tr("Full name")),
                       "members" : unicode(self.tr("Number of members")),
                       "ID" : unicode(self.tr("ID")),
                     }   
     
     def translate(self, k):
        try:
          return self.trMap[k]
        except KeyError:
          return k

  RegistryKeyPath = { "HKLM\SAM\SAM\Domains\Builtin\Aliases\*" : { "values" :  "*" } } 
  def __init__(self, data):
     data = buffer(data)
     self.__groupID = unpack('i', data[0:4])[0]
     self.__groupName = self.decodeDataAtOffset(data, 0x10)
     self.__fullName = self.decodeDataAtOffset(data, 0x1c)
     self.__groupMembers = unpack('i', data[0x30:0x30+4])[0]

  def decodeDataAtOffset(self, data, offset):
    (off, length) = unpack('II', data[offset:offset+8])
    return data[0x34+off:0x34+off+length]

  def ID(self):
     return self.__groupID

  def name(self):
     return self.__groupName.decode('UTF-16')

  def fullName(self):
     return self.__fullName.decode('UTF-16')

  def members(self):
     return self.__groupMembers
  
  def show(self):
     l = ['ID', 'Name', 'fullName', 'members']
     for attr in l:
        print attr, getattr(self, attr)()

class UserF(object):
  class Translate(Translator):
    def __init__(self):
      Translator.__init__(self)
 
    def unknown(self):
       return unicode(self.tr("Unknown"))
 
    def details(self):
      return { "lastLoginDate" : unicode(self.tr("Last login")),
               "passwordResetDate" : unicode(self.tr("Password reset")),
               "accountExpirationDate" : unicode(self.tr("Account expiration")),
               "RID" : unicode(self.tr("RID")),
               "failedCount" : unicode(self.tr("Login connection failed")),
               "logins" : unicode(self.tr("Login count")),
               "ACBBits" : unicode(self.tr("Properties")),
               #don't add "Unknown" here
             }

    def ACBFields(self):
       """User timestamp (mainly)"""
       return {
                0x001 : unicode(self.tr("Account disabled")),
                0x002 : unicode(self.tr("Home directory required")),
                0x004 : unicode(self.tr("Password not required")),
                0x008 : unicode(self.tr("Temporary duplicate account")),
                0x010 : unicode(self.tr("Normal user account")),
                0x020 : unicode(self.tr("MNS logon user account")),
                0x040 : unicode(self.tr("Interdomain trust account")),
                0x080 : unicode(self.tr("Workstation trust account")),
                0x100 : unicode(self.tr("Server trust account")),
                0x200 : unicode(self.tr("User password does not expire")),
                0x400 : unicode(self.tr("Account auto locked"))
              } 

  def __init__(self, data):
    self.translator = self.Translate()
    (unknown1, self.__lastLoginDate, unknown2, self.__passwordResetDate, unknown3,
     self.__accountExpirationDate, self.__rid, unknown4, self.__ACBBits, unknown5, self.__failedCount, self.__logins)\
     = unpack('QQQQQQiIH6sHH', buffer(data)[0:68])

  def lastLoginDate(self):
     if self.__lastLoginDate:
       return str(MS64DateTime(self.__lastLoginDate))
     else:
       return self.translator.unknown()

  def passwordResetDate(self):
     if (self.__passwordResetDate):
       return  str(MS64DateTime(self.__passwordResetDate))
     else:
       return self.translator.unknown()

  def accountExpirationDate(self):
     if self.__accountExpirationDate:
       return str(MS64DateTime(self.__loginTime))
     else:
       return self.translator.unknown()

  def RID(self):
     return int(self.__rid)

  def ACBBits(self):
     properties = []
     for  field, fieldName in self.translator.ACBFields().iteritems():
         if field & self.__ACBBits  == field: 
           properties.append(fieldName)
     return properties

  def failedCount(self):
     return self.__failedCount

  def logins(self):
     return self.__logins

  def details(self):
     return self.translator.details()

  def show(self):
     l = ["lastLoginDate", "passwordResetDate", "accountExpirationDate", "RID", "ACBBits", "failedCount", "logins"]
     for attr in l:
        print attr, getattr(self, attr)()

class UserV(object):
  """User info"""
  class Translate(Translator):
    def __init__(self):
      Translator.__init__(self)
  
    def details(self):
      return {"userName" : unicode(self.tr("User name")),
              "fullName" :  unicode(self.tr("Full name")),
              "comment" : unicode(self.tr("Comment")),
              "homeDirectory" : unicode(self.tr("Home directory")),
              "driveLetter" : unicode(self.tr("Drive letter")),
              "logonScreen" : unicode(self.tr("Logon screen")),
              "profilePath" : unicode(self.tr("Profile path")),
              "lmPassword" : unicode(self.tr("LM hash")),
              "ntPassword" : unicode(self.tr("NT hash"))
             }

  def __init__(self, data):
     data = buffer(data)
     self.__userName = self.decodeDataAtOffset(data, 0xc)
     self.__fullName = self.decodeDataAtOffset(data, 0x18)
     self.__comment = self.decodeDataAtOffset(data, 0x24)
     self.__homeDirectory = self.decodeDataAtOffset(data, 0x48)
     self.__driveLetter = self.decodeDataAtOffset(data, 0x54)
     self.__logonScreen = self.decodeDataAtOffset(data, 0x60)
     self.__profilePath = self.decodeDataAtOffset(data, 0x6c)
     self.__lmPassword = self.decodeDataAtOffset(data, 0x9c)
     self.__ntPassword = self.decodeDataAtOffset(data, 0xa8)

  def toHex(self, data):
    value = ''
    for i in data:
       value += '%X' % ord(i)
    return value

  def decodeDataAtOffset(self, data, offset):
    (off, length) = unpack('II', data[offset:offset+8])
    return data[0xcc+off:0xcc+off+length]

  def userName(self):
     return self.__userName.decode('UTF-16')

  def fullName(self):
     return self.__fullName.decode('UTF-16')

  def comment(self):
     return self.__comment.decode('UTF-16')

  def homeDirectory(self):      
     return self.__homeDirectory

  def driveLetter(self):
     return self.__driveLetter
 
  def logonScreen(self):
     return self.__logonScreen

  def profilePath(self):
     return self.__profilePath

  def lmPassword(self):
     return str(self.toHex(self.__lmPassword))

  def ntPassword(self):
     return str(self.toHex(self.__ntPassword))

  def details(self):
     return self.Translate().details()

  def show(self):
     l = ["userName", "fullName", "comment", "homeDirectory", "driveLetter", "logonScreen", "profilePath",
          "lmPassword", "ntPassword"]
     for attr in l:
        print attr, getattr(self, attr)()
 
class User(object):
  def __init__(self, Kdata, Vdata):
    self.decode(Kdata, Vdata)

  def decode(self, Vdata, Fdata):
     self.decodeV(Vdata)
     self.decodeF(Fdata)

  def decodeV(self, data):
    self.__v = UserV(data)

  def decodeF(self, data):
    self.__f = UserF(data)

  def show(self):
     self.__v.show()
     self.__f.show()

  def details(self):
     details = {}
     details.update(self.__v.details())
     details.update(self.__f.details())
     return details 

  def __getattr__(self, attr):
     try:
        return getattr(self.__v, attr)
     except:
        pass
     try:
       return getattr(self.__f, attr)
     except:
       pass

class Account(object):
   class Info(object):
      def __init__(self):
        self.__users = [] 
        self.__groups = [] 
        self.__accountDB = []

      def addUser(self, user):
          self.__users.append(user)
 
      def users(self):
         return self.__users
 
      def addGroup(self, group):
          self.__groups.append(group) 

      def groups(self):
         return self.__groups

      def addDB(self, accountDB):
          self.__accountDB.append(accountDB)

      def accountDB(self):
        return self.__accountDB

   def __init__(self):
     self.__accountInfo = {}

   def addUser(self, node, user):
      try:
        self.__accountInfo[node.uid()].addUser(user)
      except KeyError:          
        self.__accountInfo[node.uid()] = Account.Info()
        self.__accountInfo[node.uid()].addUser(user)

   def addGroup(self, node, group):
      try:
        self.__accountInfo[node.uid()].addGroup(group)
      except KeyError:         
        self.__accountInfo[node.uid()] = Account.Info()
        self.__accountInfo[node.uid()].addGroup(group)

   def addDB(self, node, accountDB):
      try:
        self.__accountInfo[node.uid()].addDB(accountDB)
      except KeyError:         
        self.__accountInfo[node.uid()] = Account.Info()
        self.__accountInfo[node.uid()].addDB(accountDB)

   def report(self, root):
     self.reportManager = ReportManager()
     self.translator = AccountTranslator()
     for nodeID in self.__accountInfo.iterkeys():
        node = VFS.Get().getNodeById(nodeID)
        info = self.__accountInfo[nodeID]
        categoryName = self.translator.translate("Operating system") + " " + root.name().translate(None, "!@#$%^&'\/?")
        page = self.reportManager.createPage(categoryName, self.translator.translate("Users") + " (" + node.name() + ')')
        tableHeader = ["userName", "RID", "lastLoginDate", "logins"]
        headerTranslation = []
        translationMap = {}
        translationMap.update(UserV.Translate().details())
        translationMap.update(UserF.Translate().details())
        for name in tableHeader:
          headerTranslation.append(translationMap[name]) 
                
        userTable = page.addDetailTable(self.translator.translate("Accounts"), headerTranslation)
        for user in info.users():
           tempTable = []
           for attr, description in user.details().iteritems():
             try:
               value = getattr(user, attr)()
               if value:
                 tempTable.append((description, value))
             except AttributeError:
               pass
           detailTable = TableFragment(self.translator.translate("Details"), [self.translator.translate('Key'), self.translator.translate('Value')], tempTable)
           userTable.addRow((user.userName(), user.RID(), user.lastLoginDate(), user.logins()), detailTable)
        
        groupTable = [] 
        gtr = GroupC.Translate()
        headerTranslation = []
        for m in ["name", "ID", "members"]:
          headerTranslation.append(gtr.translate(m))
        for group in info.groups():
           groupTable.append((group.name(), group.ID(), group.members()))
        page.addTable(gtr.translate("groups"), headerTranslation, groupTable)
 
        self.reportManager.addPage(page)      


class Accounts(Script):
  def __init__(self):
    Script.__init__(self, "Accounts")
    self.__accounts = None
  
  def start(self, args):
     try:
       self.root = args["root"].value()
     except IndexError:
       self.root = self.vfs.getnode("/")
     self.process()
     self.report()


  def process(self, root=None):
    if root != None:
      root = root
    else:
      root = self.root
    self.__accounts = Account()
    self.registryManager = ModuleProcessusManager().get("winreg")
    regKeys = self.registryManager.getKeys({ 'HKLM\SAM\SAM\Domains\Account\Users\*' : 
                                             { "values" : "*"} }, root)
    regSplit = regKeys.split()
    for node, keys in regSplit.iteritems():
      for key in keys:
        V = None
        F = None
        for value in key.values():
          if value.name == 'V':
            V = value.data()
          if value.name == 'F':
            F = value.data()
        if V and F:
          self.__accounts.addUser(node, User(V, F))

    groupKeys = self.registryManager.getKeys(GroupC.RegistryKeyPath, root)
    groupSplit = groupKeys.split()
    for node, keys in groupSplit.iteritems():
      for key in keys:
        for value in key.values():
          if value.name == 'C': 
            self.__accounts.addGroup(node, GroupC(value.data())) 
 
    accountDBKeys = self.registryManager.getKeys(AccountDBF.RegistryKeyPath, root)
    accountDBKeysSplit = accountDBKeys.split()
    for node, keys in accountDBKeysSplit.iteritems():
      for key in keys:
        for value in key.values():
          if value.name == 'F':
            self.__accounts.addDB(node, AccountDBF(value.data()))


  def accounts(self, root=None):
    if self.__accounts == None:
      self.process(root)
    return self.__accounts

 
  def report(self):
    try:
      self.__accounts.report(self.root)
    except Exception as e:
      print 'Module Account error when reporting ' + str(e)

class account(Module):
  """Windows users accounts information"""
  def __init__(self):
    Module.__init__(self, "Accounts", Accounts)
    self.conf.addArgument({"name" : "root",
                           "description" : "Root from where the analysis will start.",
                           "input" : Argument.Required | Argument.Single | typeId.Node })
    self.tags = "Windows Analyse"
    self.icon = ":meeting"
    self.depends = ["File systems", "partition", "winreg"]
