# -*- coding: utf-8 -*-
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

from dff.api.types.libtypes import DateTime 

from dff.pro.modules.analyse.analyse import Translator

class SkypeRecordTranslator(Translator):
  def translationMap(self):
    return {
             "callStart" : unicode(self.tr("'Start of call :' ")),
             "callEnd" : unicode(self.tr(" 'End of call'")),
             "Canceled" : unicode(self.tr("Canceled")),
             "Issued" : unicode(self.tr("Issued")),
             "SendFailed" : unicode(self.tr("Send failed")),
             "Failed" : unicode(self.tr("Failed")),
             "UnavailableFile" : unicode(self.tr("File unavailable")),
             "UnavailableLocalFile" : unicode(self.tr("File unavailable on this computer")),
             "Send" : unicode(self.tr("Send")),
             "Receive" : unicode(self.tr("Receive")),
             "Man" : unicode(self.tr("Man")),
             "Woman" : unicode(self.tr("Woman")),
             "Unknown" : unicode(self.tr("Unknown")),
             "Simple" : unicode(self.tr("Simple")),
             "Group" : unicode(self.tr("Group")),
             "Conference" : unicode(self.tr("Conference")),
             "Incoming" : unicode(self.tr("Incoming")),
             "Outgoing" : unicode(self.tr("Outgoing")),
             "minutes" : unicode(self.tr("minutes")),
             "seconds" : unicode(self.tr("seconds")),
           }

class SkypeMessage(object):
  SkypeType = 'Message'
  def __init__(self):
    self.translator = SkypeRecordTranslator()

  def _from(self):
     return self.record('from_dispname')

  def time(self):
    record = self.record('timestamp')
    if record:
      return str(DateTime(record))

  def message(self):
    msg = self.record('body_xml')
    if msg == None:
      msg = '' 
    t = self.type()
    if t == 30:
      if type(msg) == unicode:
        return self.translator.translate("callStart") + msg.encode('UTF-8', 'replace')
      else:
        return self.translator.translate("callStart") + msg
    elif t == 30:
      if type(msg) == unicode:
        return msg.encode('UTF-8', 'replace') + self.translator.translate("callEnd") 
      else:
        return msg + self.translator.translate("callEnd") 
    return msg 
 
class SkypeTransfer(object):
  SkypeType = 'Transfer'
  FailureReason = { 0 : "Canceled",
                    2 : "Issued",
                    5 : "SendFailed",
                    8 : "SendFailed",
                   10 : "UnavailableFile" }
  Status = { 7 : "Canceled",
             8 : "Issued",
             9 : "Canceled",
            10 : "UnavailableFile",
            11 : "UnavailableLocalFile",
            12 : "Issued" }
  Type = { 1 : "Send",
           2 : "Receive"}
  def __init__(self):
     self.translator = SkypeRecordTranslator()

  def starttime(self):
     record = self.record('starttime')
     if record == None:
       return str(DateTime(record))

  def finishtime(self):
     record = self.record('finishtime')
     if record == None:
       return str(DateTime(record))

  def transferduration(self):
     srecord = self.record('starttime')
     erecord = self.record('finishtime')
     if (srecord == None) or (erecord == None):
       return record
     return str(DateTime(erecord).toPyDateTime() - DateTime(srecord).toPyDateTime())

  def type(self):
    record = self.record('type')
    try:
      return self.translator.translate(self.Type[record])
    except KeyError:
      pass
 
  def status(self):
    record = self.record('status')
    try:
      if record == 9:
        return self.translator.translate("Failed") + " : "  + self.translator.translate(self.FailureReason[self.record('failureason')])
      else:
        return self.translator.translate(self.Status[record])
    except KeyError:
      pass

class SkypeAccount(object):
  SkypeType = 'Account'
  Gender = { 1 : 'Man',
             2 : 'Woman'}
  def __init__(self):
    self.translator = SkypeRecordTranslator() 

  def mood(self):
    return self.record('mood_text')

  def profileTimestamp(self):
    record = self.record('profile_timestamp')
    if record:
      return str(DateTime(record))

  def balance(self):
    balance = self.record('skypeout_balance')
    if balance:
      return str(balance / 100.0) + ' ' + str(self.record('skypeout_balance_currency'))
    return self.translator.translate('Unknown') 

  def gender(self):
    record = self.record('gender')
    if record == 1:
      return self.translator.translate('Man')
    elif record == 2:
      return self.translator.translate('Woman')

class SkypeContact(object):
  SkypeType = 'Contact'
  gender = { 1 : 'Man',
             2 : 'Woman'}
  def __init__(self):
    self.translator = SkypeRecordTranslator() 

  def phone(self):
    return self.record('pstnnumber')
  
  def phoneHome(self):
    return self.record('phone_home')

  def phoneOffice(self):
    return self.record('phone_office')

  def phoneMobile(self):
    return self.record('phone_mobile')

  def profile_timestamp(self):
    record = self.record('profile_timestamp')
    if record:
      return str(DateTime(record))

  def lastcalled_time(self): 
     record = self.record('lastcalled_time')
     if record:
       return str(DateTime(record))

  def last_used_network_time(self):
     record = self.record('last_used_networktime')
     if record:
       return str(DateTime(record))

  def gender(self):
    record = self.record('gender')
    if record == 1:
      return self.translator.translate('Man')
    elif record == 2:
      return self.translator.translate('Woman')

  def avatar_image(self):
    record = self.record('avatar_image')
    if record and len(record) > 1:
      return record[1:]
    return record

class SkypeChat(object):
  SkypeType = 'Chat'
  def __init__(self):
    self.translator = SkypeRecordTranslator() 

  def _type(self):
    record = self.record('type')
    if record == 1:
      return self.translator.translate('Simple')
    elif record == 2:
      return self.translator.translate('Group')
    elif record == 3:
      return self.translator.translate('Conference')
    return self.translator.translate('Unknown')

  def friendlyname(self):
    record = self.record('friendlyname')
    if record:
      return record
    record = self.record('name')
    if record:
      return record
    return self.translator.translate('Unknown')

  def timestamp(self):
    record = self.record('timestamp')
    if record:
      return str(DateTime(record))

  def activity_timestamp(self):
    record = self.record('activity_timestamp')
    if record:
      return str(DateTime(record))

  def last_change(self):
    record = self.record('last_change')
    if record:
      return str(DateTime(record))

class SkypeChatMember(object):
  SkypeType = 'ChatMember'
  def __init__(self):
     pass 

class SkypeCall(object):
  SkypeType = 'Call'
  def __init__(self):
    self.translator = SkypeRecordTranslator()

  def begin_timestamp(self):
    record = self.record('begin_timestamp')
    if record:
      return str(DateTime(record))

  def is_incoming(self):
     record = self.record('is_incoming')
     if record:
       return self.translator.translate('Incoming')
     return self.translator.translate('Outgoing')

class SkypeCallMember(object):
  SkypeType = 'CallMember'
  def __init__(self):
    self.translator = SkypeRecordTranslator()
  def call_duration(self):
    record = self.record('call_duration')
    if not record:
      return self.translator.translate("Unknown") 
    time = ""
    if record / 60:   
      time += str(record / 60) + " " + self.translator.translate("minutes") + " "
    if record % 60:
      time += str(record % 60) + " " + self.translator.translate("seconds") 
    return time 

  def start_timestamp(self):
    record = self.record('start_timestamp')
    if record:
      return str(DateTime(record))

class SkypeSMS(object):
  SkypeType = 'SMSe'
  def __init__(self):
     pass

  def timestamp(self):
    record = self.record('timestamp')
    if record:
      return str(DateTime(record))

class SkypeContactGroup(object):
  def __init__(self):
     pass

class SkypeVoicemail(object):
  SkypeType = 'Voicemail'
  def __init__(self):
    pass

  def timestamp(self):
    record = self.record('timestamp')
    if record:
      return str(DateTime(record))
