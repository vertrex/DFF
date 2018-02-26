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

from skyperecord import SkypeMessage, SkypeChat, SkypeChatMember, SkypeCall, SkypeCallMember, SkypeContactGroup, SkypeAccount, SkypeTransfer, SkypeContact, SkypeSMS, SkypeVoicemail

class SkypeSqliteRecord(object):
  typedSchema = None
  def __init__(self, record):
    self.__record = {}
    i = 0
    for (name, ttype) in self.typedSchema:
      self.__record[name] = record[i]
      i += 1

  def __getattr__(self, name):
    def callRecord():
       return self.record(name)
    return callRecord

  def record(self, name):
    try:
      return self.__record[name]
    except KeyError:
      return None

class SkypeAccountSqlite(SkypeAccount, SkypeSqliteRecord):
  def __init__(self, record):
    SkypeAccount.__init__(self)
    SkypeSqliteRecord.__init__(self, record)

class SkypeContactSqlite(SkypeContact, SkypeSqliteRecord):
  def __init__(self, record):
    SkypeContact.__init__(self)
    SkypeSqliteRecord.__init__(self, record)

class SkypeMessageSqlite(SkypeMessage, SkypeSqliteRecord):
  def __init__(self, record):
    SkypeMessage.__init__(self)
    SkypeSqliteRecord.__init__(self, record)

class SkypeTransferSqlite(SkypeSqliteRecord, SkypeTransfer):
  def __init__(self, record):
     SkypeSqliteRecord.__init__(self, record)
     SkypeTransfer.__init__(self)

class SkypeChatSqlite(SkypeChat, SkypeSqliteRecord):
  def __init__(self, record):
    SkypeChat.__init__(self)
    SkypeSqliteRecord.__init__(self, record)

class SkypeChatMemberSqlite(SkypeChatMember, SkypeSqliteRecord):
  def __init__(self, record):
    SkypeChatMember.__init__(self)
    SkypeSqliteRecord.__init__(self, record)

class SkypeCallSqlite(SkypeCall, SkypeSqliteRecord):
  def __init__(self, record):
    SkypeCall.__init__(self)
    SkypeSqliteRecord.__init__(self, record)
 
class SkypeCallMemberSqlite(SkypeCallMember, SkypeSqliteRecord):
  def __init__(self, record):
    SkypeCallMember.__init__(self)
    SkypeSqliteRecord.__init__(self, record)

class SkypeSMSSqlite(SkypeSMS, SkypeSqliteRecord):
  def __init__(self, record):
    SkypeSMS.__init__(self)
    SkypeSqliteRecord.__init__(self, record)

class SkypeVoicemailSqlite(SkypeVoicemail, SkypeSqliteRecord):
  def __init__(self, record):
    SkypeVoicemail.__init__(self)
    SkypeSqliteRecord.__init__(self, record)

class SkypeSqlite(object):
  factories = {
    'Messages' : SkypeMessageSqlite,
    'Accounts' : SkypeAccountSqlite,
    'Contacts' : SkypeContactSqlite,
    'Transfers' : SkypeTransferSqlite,
    'Chats' : SkypeChatSqlite,
    'ChatMembers' : SkypeChatMemberSqlite,
    'Calls' : SkypeCallSqlite,
    'CallMembers' : SkypeCallMemberSqlite,
    'SMSes' : SkypeSMSSqlite,
    'Voicemails' : SkypeVoicemailSqlite,
  }

  def __init__(self, db):
    self.db = db
    self.subclass = {}
       
  def records(self, stype):
    records = []
    try:
      cursor = self.db.execute('select * from ' + stype)
      factory = self.factories[stype]
      factory.typedSchema = cursor.getdescription() 
      for x in  cursor:
        records.append(factory(x))
      return records
    except KeyError:
      return []
